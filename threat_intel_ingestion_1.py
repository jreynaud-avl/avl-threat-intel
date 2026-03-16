"""
Threat Intelligence Feed Ingestion Module
==========================================
Fetches, deduplicates, and stores raw content from multiple source types:
  - RSS / Atom feeds
  - HTML pages (vendor blogs, advisories)
  - PDF reports (direct URL download)
  - REST API feeds (e.g. AlienVault OTX)

On first run for any feed, performs a historical backfill up to the configured
max_pages depth. Subsequent runs fetch only new content.

Feed list is read from feeds.yaml — edit that file to add/remove sources.

Dependencies:
    pip install feedparser requests beautifulsoup4 trafilatura PyMuPDF pyyaml

Usage:
    python threat_intel_ingestion.py
    python threat_intel_ingestion.py --feeds feeds.yaml --db threat_intel.db
    python threat_intel_ingestion.py --pending
"""

import argparse
import feedparser
import hashlib
import json
import logging
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
import yaml
from bs4 import BeautifulSoup

try:
    import trafilatura
    HAS_TRAFILATURA = True
except ImportError:
    HAS_TRAFILATURA = False

try:
    import fitz  # PyMuPDF
    HAS_PYMUPDF = True
except ImportError:
    HAS_PYMUPDF = False


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path("threat_intel.db")
DEFAULT_FEEDS_PATH = Path("feeds.yaml")

REQUEST_TIMEOUT = 20
RATE_LIMIT_DELAY = 1.5       # seconds between normal requests
DEFAULT_PAGE_DELAY = 2.0     # seconds between backfill page requests
MAX_CONTENT_LENGTH = 500_000 # bytes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; ThreatIntelBot/1.0; "
        "+https://example.com/threat-intel-bot)"
    )
}


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _expand_env(value: str) -> str:
    """Expand ${ENV_VAR} placeholders from environment variables."""
    return re.sub(
        r"\$\{([^}]+)\}",
        lambda m: os.environ.get(m.group(1), m.group(0)),
        value,
    )


def load_feeds(path: Path = DEFAULT_FEEDS_PATH) -> list[dict]:
    """
    Load and validate feeds from feeds.yaml.
    Skips feeds with enabled: false.
    Expands ${ENV_VAR} placeholders in header values.
    """
    with open(path) as f:
        config = yaml.safe_load(f)

    feeds = []
    for feed in config.get("feeds", []):
        if not feed.get("enabled", True):
            log.debug(f"Skipping disabled feed: {feed.get('name')}")
            continue

        # Expand env vars in headers
        if "headers" in feed:
            feed["headers"] = {
                k: _expand_env(str(v)) for k, v in feed["headers"].items()
            }

        feeds.append(feed)

    log.info(f"Loaded {len(feeds)} active feeds from {path}")
    return feeds


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db(db_path: Path) -> sqlite3.Connection:
    """Create schema tables if they don't already exist."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    # Raw report storage — one row per article/advisory/API response
    conn.execute("""
        CREATE TABLE IF NOT EXISTS raw_reports (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name   TEXT    NOT NULL,
            source_url    TEXT    NOT NULL,
            title         TEXT,
            published_at  TEXT,
            fetched_at    TEXT    NOT NULL,
            content_hash  TEXT    NOT NULL UNIQUE,
            content_type  TEXT    NOT NULL,
            raw_content   TEXT    NOT NULL,
            tags          TEXT,
            status        TEXT    DEFAULT 'pending'
        )
    """)

    # Feed registry — one row per feed URL, tracks backfill state
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feed_registry (
            url            TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            first_seen     TEXT NOT NULL,
            last_fetched   TEXT,
            backfill_done  INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    return conn


def already_seen(conn: sqlite3.Connection, content_hash: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM raw_reports WHERE content_hash = ?", (content_hash,)
    ).fetchone()
    return row is not None


def insert_report(conn: sqlite3.Connection, record: dict) -> None:
    try:
        conn.execute(
            """
            INSERT INTO raw_reports
                (source_name, source_url, title, published_at, fetched_at,
                 content_hash, content_type, raw_content, tags, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            """,
            (
                record["source_name"],
                record["source_url"],
                record.get("title"),
                record.get("published_at"),
                record["fetched_at"],
                record["content_hash"],
                record["content_type"],
                record["raw_content"],
                json.dumps(record.get("tags", [])),
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Duplicate hash — safe to ignore


# ---------------------------------------------------------------------------
# Feed registry helpers
# ---------------------------------------------------------------------------

def is_new_feed(conn: sqlite3.Connection, url: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM feed_registry WHERE url = ?", (url,)
    ).fetchone()
    return row is None


def register_feed(conn: sqlite3.Connection, feed: dict) -> None:
    conn.execute(
        """
        INSERT INTO feed_registry (url, name, first_seen, backfill_done)
        VALUES (?, ?, ?, 0)
        """,
        (feed["url"], feed["name"], _now()),
    )
    conn.commit()


def mark_backfill_done(conn: sqlite3.Connection, url: str) -> None:
    conn.execute(
        "UPDATE feed_registry SET backfill_done = 1, last_fetched = ? WHERE url = ?",
        (_now(), url),
    )
    conn.commit()


def update_last_fetched(conn: sqlite3.Connection, url: str) -> None:
    conn.execute(
        "UPDATE feed_registry SET last_fetched = ? WHERE url = ?",
        (_now(), url),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Core article fetcher (shared by all HTML/RSS fetchers)
# ---------------------------------------------------------------------------

def _fetch_article_text(url: str, extra_headers: Optional[dict] = None) -> Optional[str]:
    """
    Fetch a URL and return the main article text.
    Uses trafilatura when available, falls back to BeautifulSoup.
    """
    headers = {**HEADERS, **(extra_headers or {})}
    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        html = resp.text
    except requests.RequestException as e:
        log.warning(f"[fetch] Failed to retrieve {url}: {e}")
        return None

    if HAS_TRAFILATURA:
        text = trafilatura.extract(
            html,
            include_comments=False,
            include_tables=True,
            no_fallback=False,
        )
        if text:
            return text

    # BeautifulSoup fallback
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()
    for selector in ["article", "main", ".post-content", ".entry-content", "#content"]:
        el = soup.select_one(selector)
        if el:
            return el.get_text(separator="\n", strip=True)
    return soup.get_text(separator="\n", strip=True)


def _store_rss_entries(url: str, feed: dict, conn: sqlite3.Connection) -> int:
    """
    Parse a single RSS/Atom URL and store any new entries.
    Returns count stored. Returns 0 if the feed page is empty (signals backfill to stop).
    Shared between incremental fetch and paginated backfill.
    """
    parsed = feedparser.parse(url)
    if parsed.bozo and parsed.bozo_exception:
        log.warning(f"[RSS] Parse warning for {url}: {parsed.bozo_exception}")

    if not parsed.entries:
        return 0

    stored = 0
    for entry in parsed.entries:
        entry_url = getattr(entry, "link", None)
        if not entry_url:
            continue

        identity = f"{entry_url}|{getattr(entry, 'published', '')}"
        h = sha256(identity)
        if already_seen(conn, h):
            continue

        full_text = (
            _fetch_article_text(entry_url, feed.get("headers"))
            or getattr(entry, "summary", "")
            or ""
        )
        if not full_text.strip():
            continue

        insert_report(conn, {
            "source_name": feed["name"],
            "source_url": entry_url,
            "title": getattr(entry, "title", None),
            "published_at": getattr(entry, "published", None),
            "fetched_at": _now(),
            "content_hash": h,
            "content_type": "rss",
            "raw_content": full_text,
            "tags": feed.get("tags", []),
        })
        stored += 1
        log.info(f"[RSS] Stored: {getattr(entry, 'title', entry_url)!r}")
        time.sleep(RATE_LIMIT_DELAY)

    return stored


# ---------------------------------------------------------------------------
# Incremental fetchers — run on every scheduled pass after backfill
# ---------------------------------------------------------------------------

def fetch_rss(feed: dict, conn: sqlite3.Connection) -> int:
    log.info(f"[RSS] Incremental fetch: {feed['name']}")
    return _store_rss_entries(feed["url"], feed, conn)


def fetch_html(feed: dict, conn: sqlite3.Connection) -> int:
    log.info(f"[HTML] Incremental fetch: {feed['name']}")
    text = _fetch_article_text(feed["url"], feed.get("headers"))
    if not text:
        log.warning(f"[HTML] No content from {feed['url']}")
        return 0

    h = sha256(text)
    if already_seen(conn, h):
        return 0

    insert_report(conn, {
        "source_name": feed["name"],
        "source_url": feed["url"],
        "title": feed["name"],
        "fetched_at": _now(),
        "content_hash": h,
        "content_type": "html",
        "raw_content": text,
        "tags": feed.get("tags", []),
    })
    log.info(f"[HTML] Stored: {feed['name']}")
    return 1


def fetch_pdf(feed: dict, conn: sqlite3.Connection) -> int:
    if not HAS_PYMUPDF:
        log.error("[PDF] PyMuPDF not installed — pip install PyMuPDF")
        return 0

    log.info(f"[PDF] Fetching: {feed['name']}")
    try:
        resp = requests.get(
            feed["url"],
            headers={**HEADERS, **feed.get("headers", {})},
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        resp.raise_for_status()
        length = int(resp.headers.get("Content-Length", 0))
        if length > MAX_CONTENT_LENGTH:
            log.warning(f"[PDF] Too large ({length} bytes), skipping")
            return 0
        raw_bytes = resp.content
    except requests.RequestException as e:
        log.error(f"[PDF] Request failed: {e}")
        return 0

    h = sha256(hashlib.sha256(raw_bytes).hexdigest())
    if already_seen(conn, h):
        return 0

    try:
        doc = fitz.open(stream=raw_bytes, filetype="pdf")
        pages = [page.get_text() for page in doc]
        text = "\n\n".join(pages).strip()
    except Exception as e:
        log.error(f"[PDF] Extraction failed: {e}")
        return 0

    if not text:
        log.warning(f"[PDF] No extractable text (possibly scanned): {feed['url']}")
        return 0

    insert_report(conn, {
        "source_name": feed["name"],
        "source_url": feed["url"],
        "title": feed["name"],
        "fetched_at": _now(),
        "content_hash": h,
        "content_type": "pdf",
        "raw_content": text,
        "tags": feed.get("tags", []),
    })
    log.info(f"[PDF] Stored: {feed['name']} ({len(pages)} pages)")
    return 1


def fetch_api(feed: dict, conn: sqlite3.Connection) -> int:
    log.info(f"[API] Incremental fetch: {feed['name']}")
    try:
        resp = requests.get(
            feed["url"],
            headers={**HEADERS, **feed.get("headers", {})},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.error(f"[API] Failed: {e}")
        return 0

    raw = json.dumps(data, ensure_ascii=False)
    h = sha256(raw)
    if already_seen(conn, h):
        return 0

    insert_report(conn, {
        "source_name": feed["name"],
        "source_url": feed["url"],
        "title": f"{feed['name']} — {_now()}",
        "fetched_at": _now(),
        "content_hash": h,
        "content_type": "api",
        "raw_content": raw,
        "tags": feed.get("tags", []),
    })
    log.info(f"[API] Stored: {feed['name']}")
    return 1


FETCHERS = {
    "rss": fetch_rss,
    "html": fetch_html,
    "pdf": fetch_pdf,
    "api": fetch_api,
}


# ---------------------------------------------------------------------------
# Backfill fetchers — run once per feed on first discovery
# ---------------------------------------------------------------------------

def backfill_rss_paginated(feed: dict, conn: sqlite3.Connection) -> int:
    """
    Walk numbered RSS/Atom feed pages using the archive_url template.
    Stops early when a page returns no new entries.
    """
    bf = feed.get("backfill", {})
    archive_url = bf.get("archive_url")
    max_pages = bf.get("max_pages", 10)
    page_delay = bf.get("page_delay", DEFAULT_PAGE_DELAY)

    if not archive_url:
        log.warning(f"[BACKFILL/RSS] No archive_url for {feed['name']}, falling back to single fetch")
        return fetch_rss(feed, conn)

    total = 0
    log.info(f"[BACKFILL/RSS] {feed['name']} — up to {max_pages} pages")

    for page in range(1, max_pages + 1):
        url = archive_url.replace("{page}", str(page))
        log.info(f"[BACKFILL/RSS] Page {page}/{max_pages}: {url}")

        count = _store_rss_entries(url, feed, conn)
        total += count

        if count == 0:
            log.info(f"[BACKFILL/RSS] Page {page} empty — stopping early")
            break

        time.sleep(page_delay)

    log.info(f"[BACKFILL/RSS] {feed['name']} complete — {total} reports stored")
    return total


def backfill_html_paginated(feed: dict, conn: sqlite3.Connection) -> int:
    """
    Walk paginated HTML archive pages, storing each page's content as a report.
    Stops when a page returns less than 200 chars (indicates end of archive).
    """
    bf = feed.get("backfill", {})
    archive_url = bf.get("archive_url")
    max_pages = bf.get("max_pages", 10)
    page_delay = bf.get("page_delay", DEFAULT_PAGE_DELAY)

    if not archive_url:
        return fetch_html(feed, conn)

    total = 0
    log.info(f"[BACKFILL/HTML] {feed['name']} — up to {max_pages} pages")

    for page in range(1, max_pages + 1):
        url = archive_url.replace("{page}", str(page))
        log.info(f"[BACKFILL/HTML] Page {page}/{max_pages}: {url}")

        text = _fetch_article_text(url, feed.get("headers"))
        if not text or len(text.strip()) < 200:
            log.info(f"[BACKFILL/HTML] Page {page} appears empty — stopping early")
            break

        h = sha256(text)
        if not already_seen(conn, h):
            insert_report(conn, {
                "source_name": feed["name"],
                "source_url": url,
                "title": f"{feed['name']} — page {page}",
                "fetched_at": _now(),
                "content_hash": h,
                "content_type": "html",
                "raw_content": text,
                "tags": feed.get("tags", []),
            })
            total += 1
            log.info(f"[BACKFILL/HTML] Stored page {page}")

        time.sleep(page_delay)

    log.info(f"[BACKFILL/HTML] {feed['name']} complete — {total} pages stored")
    return total


def backfill_api_paginated(feed: dict, conn: sqlite3.Connection) -> int:
    """
    Walk a paginated REST API using limit/page query parameters.
    Stops when a page returns an empty results list.
    """
    bf = feed.get("backfill", {})
    max_pages = bf.get("max_pages", 10)
    page_delay = bf.get("page_delay", DEFAULT_PAGE_DELAY)
    page_param = bf.get("page_param", "page")
    limit_param = bf.get("limit_param", "limit")
    limit_value = bf.get("limit_value", 50)

    total = 0
    log.info(f"[BACKFILL/API] {feed['name']} — up to {max_pages} pages")

    for page in range(1, max_pages + 1):
        params = {page_param: page, limit_param: limit_value}
        log.info(f"[BACKFILL/API] Page {page}/{max_pages} params={params}")

        try:
            resp = requests.get(
                feed["url"],
                headers={**HEADERS, **feed.get("headers", {})},
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            log.error(f"[BACKFILL/API] Page {page} failed: {e}")
            break

        # Detect empty results across common API envelope shapes
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get("results", data.get("data", data.get("pulses", [])))
        else:
            items = []

        if not items:
            log.info(f"[BACKFILL/API] Page {page} empty — stopping early")
            break

        raw = json.dumps(data, ensure_ascii=False)
        h = sha256(raw)
        if not already_seen(conn, h):
            insert_report(conn, {
                "source_name": feed["name"],
                "source_url": feed["url"],
                "title": f"{feed['name']} — page {page}",
                "fetched_at": _now(),
                "content_hash": h,
                "content_type": "api",
                "raw_content": raw,
                "tags": feed.get("tags", []),
            })
            total += 1
            log.info(f"[BACKFILL/API] Stored page {page} ({len(items)} items)")

        time.sleep(page_delay)

    log.info(f"[BACKFILL/API] {feed['name']} complete — {total} pages stored")
    return total


def run_backfill(feed: dict, conn: sqlite3.Connection) -> int:
    """
    Route to the appropriate backfill strategy from feeds.yaml config.
    Only called on a feed's very first ingestion run.
    """
    feed_type = feed.get("type", "rss")
    strategy = feed.get("backfill", {}).get("strategy", "none")

    log.info(f"[BACKFILL] {feed['name']} | type={feed_type} | strategy={strategy}")

    if strategy == "none":
        return FETCHERS[feed_type](feed, conn)

    if strategy == "paginated":
        if feed_type == "rss":
            return backfill_rss_paginated(feed, conn)
        elif feed_type == "html":
            return backfill_html_paginated(feed, conn)
        else:
            log.warning(f"[BACKFILL] Paginated not supported for type '{feed_type}', using single fetch")
            return FETCHERS[feed_type](feed, conn)

    if strategy == "api":
        return backfill_api_paginated(feed, conn)

    log.warning(f"[BACKFILL] Unknown strategy '{strategy}', using single fetch")
    return FETCHERS[feed_type](feed, conn)


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_ingestion(feeds: list[dict], db_path: Path = DEFAULT_DB_PATH) -> dict:
    """
    Run a full ingestion pass over all configured feeds.

    Decision per feed:
      - Never seen before  →  register in feed_registry, run backfill, mark done
      - Seen before        →  run normal incremental fetch

    Returns a summary dict with per-feed results.
    """
    conn = init_db(db_path)
    summary = {
        "total_new": 0,
        "backfilled": 0,
        "incremental": 0,
        "errors": 0,
        "feeds": {},
    }

    for feed in feeds:
        feed_type = feed.get("type", "rss")
        if feed_type not in FETCHERS:
            log.warning(f"Unknown feed type '{feed_type}' for {feed['name']}, skipping")
            continue

        feed_result = {"new": 0, "mode": "", "error": None}

        try:
            if is_new_feed(conn, feed["url"]):
                log.info(f"New feed detected: {feed['name']} — running backfill")
                register_feed(conn, feed)
                n = run_backfill(feed, conn)
                mark_backfill_done(conn, feed["url"])
                feed_result["mode"] = "backfill"
                summary["backfilled"] += n
            else:
                n = FETCHERS[feed_type](feed, conn)
                update_last_fetched(conn, feed["url"])
                feed_result["mode"] = "incremental"
                summary["incremental"] += n

            feed_result["new"] = n
            summary["total_new"] += n

        except Exception as e:
            log.error(f"Unhandled error ingesting {feed['name']}: {e}", exc_info=True)
            summary["errors"] += 1
            feed_result["error"] = str(e)

        summary["feeds"][feed["name"]] = feed_result
        time.sleep(RATE_LIMIT_DELAY)

    conn.close()
    log.info(
        f"Ingestion complete — total_new={summary['total_new']} "
        f"backfilled={summary['backfilled']} incremental={summary['incremental']} "
        f"errors={summary['errors']}"
    )
    return summary


# ---------------------------------------------------------------------------
# Stage 2 interface
# ---------------------------------------------------------------------------

def get_pending_reports(db_path: Path = DEFAULT_DB_PATH) -> list[dict]:
    """Return all reports with status='pending', ready for Claude analysis."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM raw_reports WHERE status = 'pending' ORDER BY fetched_at ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def mark_report_analysed(report_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    """Mark a report as analysed after Stage 2 processing."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE raw_reports SET status = 'analysed' WHERE id = ?", (report_id,)
    )
    conn.commit()
    conn.close()


def mark_report_error(report_id: int, db_path: Path = DEFAULT_DB_PATH) -> None:
    """Mark a report as errored if Stage 2 processing fails."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE raw_reports SET status = 'error' WHERE id = ?", (report_id,)
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat Intelligence Feed Ingestion")
    parser.add_argument(
        "--feeds", type=Path, default=DEFAULT_FEEDS_PATH,
        help=f"Path to feeds.yaml (default: {DEFAULT_FEEDS_PATH})"
    )
    parser.add_argument(
        "--db", type=Path, default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH})"
    )
    parser.add_argument(
        "--pending", action="store_true",
        help="Print pending report count and exit (useful for monitoring)"
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.pending:
        pending = get_pending_reports(args.db)
        print(f"Reports pending analysis: {len(pending)}")
    else:
        feeds = load_feeds(args.feeds)
        result = run_ingestion(feeds, args.db)
        print(f"\nIngestion summary:\n{json.dumps(result, indent=2)}")
        pending = get_pending_reports(args.db)
        print(f"\nReports pending analysis: {len(pending)}")
