"""
Threat Intelligence Analysis Module — Stage 2
==============================================
Reads pending reports from the Stage 1 database (threat_intel.db),
sends each to Claude for structured intelligence extraction, and writes
results to a separate analysis database (threat_intel_analysed.db).

The extraction prompt is loaded from two external files:
  - prompt_system.txt   — analyst role and behaviour instructions
  - prompt_schema.json  — extraction schema, rules, and allowed values

Edit those files in GitHub to tune extraction behaviour without
touching this script.

Dependencies:
    pip install anthropic

Usage:
    python threat_intel_analysis.py
    python threat_intel_analysis.py --raw-db threat_intel.db --analysed-db threat_intel_analysed.db --limit 50
"""

import argparse
import json
import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import anthropic

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_RAW_DB        = Path("threat_intel.db")
DEFAULT_ANALYSED_DB   = Path("threat_intel_analysed.db")
DEFAULT_SYSTEM_PROMPT = Path("prompt_system.txt")
DEFAULT_SCHEMA_PATH   = Path("prompt_schema.json")
DEFAULT_LIMIT         = 50
MODEL                 = "claude-sonnet-4-6"
MAX_TOKENS            = 8000
CONTENT_PREVIEW_CHARS = 12000   # truncate very long articles before sending
RETRY_ATTEMPTS        = 3
RETRY_DELAY           = 5       # seconds between retries

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt loader
# ---------------------------------------------------------------------------

def load_prompt(
    system_path: Path = DEFAULT_SYSTEM_PROMPT,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
) -> str:
    """
    Build the full system prompt from prompt_system.txt and prompt_schema.json.
    Called once at startup — edit those files to tune extraction behaviour.
    """
    if not system_path.exists():
        raise FileNotFoundError(f"System prompt file not found: {system_path}")
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found: {schema_path}")

    system = system_path.read_text().strip()
    schema_doc = json.loads(schema_path.read_text())

    schema     = schema_doc["schema"]
    rules      = schema_doc["rules"]
    tags       = schema_doc["allowed_relevance_tags"]
    skip_reasons = schema_doc["allowed_skip_reasons"]

    rules_text = "\n".join(f"- {r}" for r in rules)
    tags_text  = ", ".join(tags)
    skip_text  = ", ".join(f'"{r}"' for r in skip_reasons)

    prompt = f"""{system}

Extract using this exact JSON schema — return nothing else:
{json.dumps(schema, indent=2)}

Rules:
{rules_text}

Allowed relevance_tags values (use only these):
{tags_text}

Allowed skip_reason values (use only these):
{skip_text}"""

    return prompt


USER_PROMPT_TEMPLATE = """Analyse the following cybersecurity report and extract structured threat intelligence.

Source: {source_name}
Title: {title}
Published: {published_at}

Report content:
{content}"""


# ---------------------------------------------------------------------------
# Analysed database schema
# ---------------------------------------------------------------------------

def init_analysed_db(db_path: Path) -> sqlite3.Connection:
    """Create the analysed intelligence database schema."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")

    # Core intelligence records — one row per processed report
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_reports (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            raw_report_id     INTEGER NOT NULL UNIQUE,
            source_name       TEXT    NOT NULL,
            source_url        TEXT,
            title             TEXT,
            published_at      TEXT,
            processed_at      TEXT    NOT NULL,
            is_threat_intel   INTEGER NOT NULL,
            skip_reason       TEXT,
            confidence        TEXT,
            report_date       TEXT,
            summary           TEXT,
            relevance_tags    TEXT,
            raw_extraction    TEXT    NOT NULL
        )
    """)

    # Threat actors
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_actors (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            name              TEXT    NOT NULL,
            aliases           TEXT,
            type              TEXT,
            attribution       TEXT
        )
    """)

    # Malware families
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malware_families (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            name              TEXT    NOT NULL,
            type              TEXT,
            capabilities      TEXT
        )
    """)

    # MITRE TTPs
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ttps (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            mitre_id          TEXT,
            name              TEXT,
            tactic            TEXT
        )
    """)

    # IOCs — flattened, one row per IOC value
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            ioc_type          TEXT    NOT NULL,
            value             TEXT    NOT NULL,
            UNIQUE(intelligence_id, ioc_type, value)
        )
    """)

    # Targets
    conn.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            target_type       TEXT    NOT NULL,
            value             TEXT    NOT NULL
        )
    """)

    # Vulnerabilities
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            intelligence_id   INTEGER NOT NULL REFERENCES intelligence_reports(id),
            cve_id            TEXT,
            product           TEXT,
            severity          TEXT
        )
    """)

    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# Raw database helpers
# ---------------------------------------------------------------------------

def get_pending_reports(db_path: Path, limit: int) -> list[dict]:
    """
    Fetch pending reports from the Stage 1 DB distributed evenly across sources.
    Round-robin selection ensures no single source dominates the batch.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    sources = conn.execute("""
        SELECT DISTINCT source_name
        FROM raw_reports
        WHERE status = 'pending'
    """).fetchall()

    if not sources:
        conn.close()
        return []

    source_names = [s["source_name"] for s in sources]
    per_source   = max(1, limit // len(source_names))
    remainder    = limit - (per_source * len(source_names))

    rows = []
    for i, source in enumerate(source_names):
        source_limit = per_source + (1 if i < remainder else 0)
        source_rows  = conn.execute("""
            SELECT id, source_name, source_url, title, published_at,
                   content_type, raw_content
            FROM raw_reports
            WHERE status = 'pending' AND source_name = ?
            ORDER BY fetched_at ASC
            LIMIT ?
        """, (source, source_limit)).fetchall()
        rows.extend(source_rows)

    conn.close()
    return [dict(r) for r in rows]


def update_raw_status(
    db_path: Path,
    report_id: int,
    status: str,
    skip_reason: str = None,
) -> None:
    """Update a report's status (and optional skip_reason) in the Stage 1 DB."""
    conn = sqlite3.connect(db_path)
    if skip_reason:
        conn.execute(
            "UPDATE raw_reports SET status = ?, skip_reason = ? WHERE id = ?",
            (status, skip_reason, report_id),
        )
    else:
        conn.execute(
            "UPDATE raw_reports SET status = ? WHERE id = ?",
            (status, report_id),
        )
    conn.commit()
    conn.close()


def ensure_skip_reason_column(db_path: Path) -> None:
    """Add skip_reason column to raw_reports if it doesn't already exist."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("ALTER TABLE raw_reports ADD COLUMN skip_reason TEXT")
        conn.commit()
        log.info("Added skip_reason column to raw_reports")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.close()


# ---------------------------------------------------------------------------
# Claude API
# ---------------------------------------------------------------------------

def call_claude(
    client: anthropic.Anthropic,
    system_prompt: str,
    report: dict,
) -> dict:
    """
    Send a report to Claude and return the parsed JSON extraction.
    Retries up to RETRY_ATTEMPTS times on transient failures.
    """
    content = report["raw_content"][:CONTENT_PREVIEW_CHARS]

    user_prompt = USER_PROMPT_TEMPLATE.format(
        source_name=report.get("source_name", "Unknown"),
        title=report.get("title", "Unknown"),
        published_at=report.get("published_at", "Unknown"),
        content=content,
    )

    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )

            raw_text = response.content[0].text.strip()

            # Detect truncated response before attempting JSON parse
            if response.stop_reason == "max_tokens":
            log.warning(f"Response truncated at max_tokens — consider increasing MAX_TOKENS")
          
            # Strip markdown fences if Claude adds them despite instructions
            if raw_text.startswith("```"):
                raw_text = raw_text.split("\n", 1)[1]
                raw_text = raw_text.rsplit("```", 1)[0].strip()

            return json.loads(raw_text)

        except json.JSONDecodeError as e:
            log.warning(f"JSON parse error on attempt {attempt}: {e}")
            if attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_DELAY)
            else:
                raise

        except anthropic.RateLimitError:
            log.warning(f"Rate limited — waiting 60s (attempt {attempt})")
            time.sleep(60)

        except anthropic.APIError as e:
            log.warning(f"API error on attempt {attempt}: {e}")
            if attempt < RETRY_ATTEMPTS:
                time.sleep(RETRY_DELAY)
            else:
                raise

    raise RuntimeError(f"All {RETRY_ATTEMPTS} attempts failed")


# ---------------------------------------------------------------------------
# Intelligence database writer
# ---------------------------------------------------------------------------

def write_intelligence(
    conn: sqlite3.Connection,
    report: dict,
    extraction: dict,
) -> int:
    """
    Write a Claude extraction into the analysed DB.
    Returns the intelligence_reports row id.
    """
    cursor = conn.execute("""
        INSERT OR IGNORE INTO intelligence_reports (
            raw_report_id, source_name, source_url, title, published_at,
            processed_at, is_threat_intel, skip_reason, confidence,
            report_date, summary, relevance_tags, raw_extraction
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        report["id"],
        report.get("source_name"),
        report.get("source_url"),
        report.get("title"),
        report.get("published_at"),
        _now(),
        1 if extraction.get("is_threat_intel") else 0,
        extraction.get("skip_reason"),
        extraction.get("confidence"),
        extraction.get("report_date"),
        extraction.get("summary"),
        json.dumps(extraction.get("relevance_tags", [])),
        json.dumps(extraction),
    ))
    intel_id = cursor.lastrowid

    # If no row was inserted (duplicate raw_report_id), signal caller to skip
    if conn.execute("SELECT changes()").fetchone()[0] == 0:
        conn.commit()
        return -1

    # If not threat intel, nothing further to write
    if not extraction.get("is_threat_intel"):
        conn.commit()
        return intel_id

    # Threat actors
    for actor in extraction.get("threat_actors", []):
        conn.execute("""
            INSERT INTO threat_actors
                (intelligence_id, name, aliases, type, attribution)
            VALUES (?, ?, ?, ?, ?)
        """, (
            intel_id,
            actor.get("name"),
            json.dumps(actor.get("aliases", [])),
            actor.get("type"),
            actor.get("attribution"),
        ))

    # Malware families
    for malware in extraction.get("malware_families", []):
        conn.execute("""
            INSERT INTO malware_families
                (intelligence_id, name, type, capabilities)
            VALUES (?, ?, ?, ?)
        """, (
            intel_id,
            malware.get("name"),
            malware.get("type"),
            json.dumps(malware.get("capabilities", [])),
        ))

    # TTPs
    for ttp in extraction.get("ttps", []):
        conn.execute("""
            INSERT INTO ttps (intelligence_id, mitre_id, name, tactic)
            VALUES (?, ?, ?, ?)
        """, (
            intel_id,
            ttp.get("mitre_id"),
            ttp.get("name"),
            ttp.get("tactic"),
        ))

    # IOCs — flattened by type
    iocs = extraction.get("iocs", {})
    ioc_type_map = {
        "ips": "ip",
        "domains": "domain",
        "hashes": "hash",
        "urls": "url",
        "emails": "email",
    }
    for field, ioc_type in ioc_type_map.items():
        for value in iocs.get(field, []):
            if value:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO iocs
                            (intelligence_id, ioc_type, value)
                        VALUES (?, ?, ?)
                    """, (intel_id, ioc_type, value))
                except sqlite3.IntegrityError:
                    pass

    # Targets
    targets = extraction.get("targets", {})
    target_type_map = {
        "industries": "industry",
        "regions": "region",
        "organisations": "organisation",
    }
    for field, target_type in target_type_map.items():
        for value in targets.get(field, []):
            if value:
                conn.execute("""
                    INSERT INTO targets (intelligence_id, target_type, value)
                    VALUES (?, ?, ?)
                """, (intel_id, target_type, value))

    # Vulnerabilities
    for vuln in extraction.get("vulnerabilities", []):
        conn.execute("""
            INSERT INTO vulnerabilities
                (intelligence_id, cve_id, product, severity)
            VALUES (?, ?, ?, ?)
        """, (
            intel_id,
            vuln.get("cve_id"),
            vuln.get("product"),
            vuln.get("severity"),
        ))

    conn.commit()
    return intel_id


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def print_summary(analysed_db: Path) -> None:
    """Print a readable summary of the analysed database after each run."""
    conn = sqlite3.connect(analysed_db)
    conn.row_factory = sqlite3.Row

    total   = conn.execute("SELECT COUNT(*) FROM intelligence_reports").fetchone()[0]
    intel   = conn.execute("SELECT COUNT(*) FROM intelligence_reports WHERE is_threat_intel = 1").fetchone()[0]
    skipped = conn.execute("SELECT COUNT(*) FROM intelligence_reports WHERE is_threat_intel = 0").fetchone()[0]
    actors  = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
    iocs    = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    ttps    = conn.execute("SELECT COUNT(*) FROM ttps").fetchone()[0]
    vulns   = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    malware = conn.execute("SELECT COUNT(*) FROM malware_families").fetchone()[0]

    print("\n" + "=" * 60)
    print("ANALYSIS DATABASE SUMMARY")
    print("=" * 60)
    print(f"Total processed:    {total}")
    print(f"Threat intel:       {intel}")
    print(f"Skipped:            {skipped}")
    print(f"\nExtracted:")
    print(f"  Threat actors:    {actors}")
    print(f"  IOCs:             {iocs}")
    print(f"  TTPs:             {ttps}")
    print(f"  Vulnerabilities:  {vulns}")
    print(f"  Malware families: {malware}")

    if skipped > 0:
        print(f"\nSkip reasons:")
        reasons = conn.execute("""
            SELECT skip_reason, COUNT(*) as count
            FROM intelligence_reports
            WHERE is_threat_intel = 0
            GROUP BY skip_reason
            ORDER BY count DESC
        """).fetchall()
        for r in reasons:
            print(f"  {r['skip_reason']}: {r['count']}")

    if actors > 0:
        print(f"\nTop threat actors:")
        top_actors = conn.execute("""
            SELECT name, attribution, COUNT(*) as mentions
            FROM threat_actors
            GROUP BY name
            ORDER BY mentions DESC
            LIMIT 10
        """).fetchall()
        for a in top_actors:
            attribution = f" ({a['attribution']})" if a['attribution'] else ""
            print(f"  {a['name']}{attribution} — {a['mentions']} report(s)")

    if iocs > 0:
        print(f"\nIOCs by type:")
        ioc_counts = conn.execute("""
            SELECT ioc_type, COUNT(*) as count
            FROM iocs
            GROUP BY ioc_type
            ORDER BY count DESC
        """).fetchall()
        for i in ioc_counts:
            print(f"  {i['ioc_type']}: {i['count']}")

    if ttps > 0:
        print(f"\nTop TTPs:")
        top_ttps = conn.execute("""
            SELECT mitre_id, name, COUNT(*) as count
            FROM ttps
            WHERE mitre_id IS NOT NULL
            GROUP BY mitre_id
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        for t in top_ttps:
            print(f"  {t['mitre_id']} {t['name']} — {t['count']} report(s)")

    conn.close()


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run_analysis(
    raw_db: Path = DEFAULT_RAW_DB,
    analysed_db: Path = DEFAULT_ANALYSED_DB,
    system_path: Path = DEFAULT_SYSTEM_PROMPT,
    schema_path: Path = DEFAULT_SCHEMA_PATH,
    limit: int = DEFAULT_LIMIT,
) -> dict:
    """
    Main Stage 2 runner.
    Loads prompt files, fetches pending reports, analyses with Claude,
    writes results to the analysed DB, updates status in Stage 1 DB.
    """
    # Load and build the prompt once at startup
    log.info(f"Loading prompt from {system_path} and {schema_path}")
    system_prompt = load_prompt(system_path, schema_path)
    log.info("Prompt loaded successfully")

    ensure_skip_reason_column(raw_db)

    client        = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
    analysed_conn = init_analysed_db(analysed_db)

    reports = get_pending_reports(raw_db, limit)
    log.info(f"Fetched {len(reports)} pending reports for analysis")

    summary = {
        "total_processed": 0,
        "threat_intel": 0,
        "skipped": 0,
        "errors": 0,
        "by_source": {},
    }

    for report in reports:
        report_id   = report["id"]
        source_name = report.get("source_name", "Unknown")
        title       = report.get("title", "Untitled")

        log.info(f"Analysing [{report_id}]: {title!r} from {source_name}")

        try:
            extraction = call_claude(client, system_prompt, report)

            intel_id = write_intelligence(analysed_conn, report, extraction)

            # Already processed in a previous run — skip status update
            if intel_id == -1:
                log.info(f"  → Already in analysed DB, skipping")
                continue

            is_intel    = extraction.get("is_threat_intel", False)
            skip_reason = extraction.get("skip_reason")

            if is_intel:
                update_raw_status(raw_db, report_id, "analysed")
                summary["threat_intel"] += 1
                log.info(f"  → Intel extracted (confidence: {extraction.get('confidence')})")
            else:
                update_raw_status(raw_db, report_id, "skipped", skip_reason)
                summary["skipped"] += 1
                log.info(f"  → Skipped: {skip_reason}")

            summary["total_processed"] += 1
            src = summary["by_source"].setdefault(
                source_name, {"intel": 0, "skipped": 0, "errors": 0}
            )
            src["intel" if is_intel else "skipped"] += 1

        except Exception as e:
            log.error(f"  → Error on report {report_id}: {e}", exc_info=True)
            update_raw_status(raw_db, report_id, "error")
            summary["errors"] += 1
            summary["by_source"].setdefault(
                source_name, {"intel": 0, "skipped": 0, "errors": 0}
            )["errors"] += 1

    analysed_conn.close()

    log.info(
        f"Analysis complete — processed={summary['total_processed']} "
        f"intel={summary['threat_intel']} skipped={summary['skipped']} "
        f"errors={summary['errors']}"
    )
    return summary


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat Intelligence Analysis — Stage 2")
    parser.add_argument("--raw-db",      type=Path, default=DEFAULT_RAW_DB)
    parser.add_argument("--analysed-db", type=Path, default=DEFAULT_ANALYSED_DB)
    parser.add_argument("--system",      type=Path, default=DEFAULT_SYSTEM_PROMPT)
    parser.add_argument("--schema",      type=Path, default=DEFAULT_SCHEMA_PATH)
    parser.add_argument("--limit",       type=int,  default=DEFAULT_LIMIT)
    return parser.parse_args()


if __name__ == "__main__":
    args   = parse_args()
    result = run_analysis(
        raw_db=args.raw_db,
        analysed_db=args.analysed_db,
        system_path=args.system,
        schema_path=args.schema,
        limit=args.limit,
    )
    print(f"\nRun summary:\n{json.dumps(result, indent=2)}")
    print_summary(args.analysed_db)
