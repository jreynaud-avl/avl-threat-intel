"""
Database inspection script — samples both Stage 1 and Stage 2 databases.
Run via the Inspect Database GitHub Actions workflow.
"""

import sqlite3
import json
from pathlib import Path

RAW_DB      = Path("threat_intel.db")
ANALYSED_DB = Path("threat_intel_analysed.db")


def inspect_raw_db():
    if not RAW_DB.exists():
        print("threat_intel.db not found — skipping Stage 1 summary")
        return

    conn = sqlite3.connect(RAW_DB)
    conn.row_factory = sqlite3.Row

    print("=" * 60)
    print("STAGE 1 DATABASE — threat_intel.db")
    print("=" * 60)

    total = conn.execute("SELECT COUNT(*) FROM raw_reports").fetchone()[0]
    print(f"Total reports: {total}\n")

    statuses = conn.execute("""
        SELECT status, COUNT(*) as count
        FROM raw_reports
        GROUP BY status
        ORDER BY count DESC
    """).fetchall()
    print("By status:")
    for s in statuses:
        print(f"  {s['status']}: {s['count']}")

    print("\nBy source:")
    sources = conn.execute("""
        SELECT source_name, COUNT(*) as count
        FROM raw_reports
        GROUP BY source_name
        ORDER BY count DESC
    """).fetchall()
    for s in sources:
        print(f"  {s['source_name']}: {s['count']}")

    conn.close()


def inspect_analysed_db():
    if not ANALYSED_DB.exists():
        print("\nthreat_intel_analysed.db not found — Stage 2 may not have run yet")
        return

    conn = sqlite3.connect(ANALYSED_DB)
    conn.row_factory = sqlite3.Row

    print("\n" + "=" * 60)
    print("STAGE 2 DATABASE — threat_intel_analysed.db")
    print("=" * 60)

    total   = conn.execute("SELECT COUNT(*) FROM intelligence_reports").fetchone()[0]
    intel   = conn.execute("SELECT COUNT(*) FROM intelligence_reports WHERE is_threat_intel = 1").fetchone()[0]
    skipped = conn.execute("SELECT COUNT(*) FROM intelligence_reports WHERE is_threat_intel = 0").fetchone()[0]
    actors  = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
    iocs    = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
    ttps    = conn.execute("SELECT COUNT(*) FROM ttps").fetchone()[0]
    vulns   = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    malware = conn.execute("SELECT COUNT(*) FROM malware_families").fetchone()[0]

    print(f"Total processed:    {total}")
    print(f"Threat intel:       {intel}")
    print(f"Skipped:            {skipped}")
    print(f"\nExtracted totals:")
    print(f"  Threat actors:    {actors}")
    print(f"  IOCs:             {iocs}")
    print(f"  TTPs:             {ttps}")
    print(f"  Vulnerabilities:  {vulns}")
    print(f"  Malware families: {malware}")

    # Skip reasons
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

    # Top threat actors
    if actors > 0:
        print(f"\nTop threat actors:")
        top_actors = conn.execute("""
            SELECT name, attribution, type, COUNT(*) as mentions
            FROM threat_actors
            GROUP BY name
            ORDER BY mentions DESC
            LIMIT 10
        """).fetchall()
        for a in top_actors:
            attribution = f" ({a['attribution']})" if a['attribution'] else ""
            print(f"  {a['name']}{attribution} [{a['type']}] — {a['mentions']} report(s)")

    # Top TTPs
    if ttps > 0:
        print(f"\nTop TTPs:")
        top_ttps = conn.execute("""
            SELECT mitre_id, name, tactic, COUNT(*) as count
            FROM ttps
            WHERE mitre_id IS NOT NULL
            GROUP BY mitre_id
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        for t in top_ttps:
            print(f"  {t['mitre_id']} — {t['name']} [{t['tactic']}] — {t['count']} report(s)")

    # IOCs by type
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

    # Top malware families
    if malware > 0:
        print(f"\nMalware families:")
        top_malware = conn.execute("""
            SELECT name, type, COUNT(*) as count
            FROM malware_families
            GROUP BY name
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        for m in top_malware:
            print(f"  {m['name']} [{m['type']}] — {m['count']} report(s)")

    # Relevance tag breakdown
    print(f"\nRelevance tags:")
    tag_rows = conn.execute("""
        SELECT relevance_tags
        FROM intelligence_reports
        WHERE is_threat_intel = 1
          AND relevance_tags IS NOT NULL
    """).fetchall()
    tag_counts = {}
    for row in tag_rows:
        tags = json.loads(row["relevance_tags"] or "[]")
        for tag in tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
    for tag, count in sorted(tag_counts.items(), key=lambda x: -x[1]):
        print(f"  {tag}: {count}")

    # Sample 3 full intel records
    print(f"\n" + "=" * 60)
    print("SAMPLE THREAT INTEL RECORDS (3 random)")
    print("=" * 60)

    samples = conn.execute("""
        SELECT ir.id, ir.raw_report_id, ir.source_name, ir.source_url,
               ir.title, ir.published_at, ir.confidence, ir.report_date,
               ir.summary, ir.relevance_tags
        FROM intelligence_reports ir
        WHERE ir.is_threat_intel = 1
        ORDER BY RANDOM()
        LIMIT 3
    """).fetchall()

    for i, rec in enumerate(samples, 1):
        intel_id = rec["id"]
        print(f"\n--- Record {i} ---")
        print(f"Intelligence ID:  {intel_id}")
        print(f"Raw report ID:    {rec['raw_report_id']}")
        print(f"Source:           {rec['source_name']}")
        print(f"URL:              {rec['source_url']}")
        print(f"Title:            {rec['title']}")
        print(f"Published:        {rec['published_at']}")
        print(f"Report date:      {rec['report_date']}")
        print(f"Confidence:       {rec['confidence']}")
        print(f"Relevance tags:   {rec['relevance_tags']}")
        print(f"Summary:          {rec['summary']}")

        # Threat actors for this record
        actors_rows = conn.execute("""
            SELECT name, aliases, type, attribution
            FROM threat_actors WHERE intelligence_id = ?
        """, (intel_id,)).fetchall()
        if actors_rows:
            print(f"\nThreat actors:")
            for a in actors_rows:
                aliases = json.loads(a['aliases'] or '[]')
                alias_str = f" aka {', '.join(aliases)}" if aliases else ""
                print(f"  {a['name']}{alias_str} [{a['type']}]"
                      f"{' — ' + a['attribution'] if a['attribution'] else ''}")

        # TTPs
        ttp_rows = conn.execute("""
            SELECT mitre_id, name, tactic
            FROM ttps WHERE intelligence_id = ?
        """, (intel_id,)).fetchall()
        if ttp_rows:
            print(f"\nTTPs:")
            for t in ttp_rows:
                print(f"  {t['mitre_id']} — {t['name']} [{t['tactic']}]")

        # IOCs
        ioc_rows = conn.execute("""
            SELECT ioc_type, value
            FROM iocs WHERE intelligence_id = ?
            ORDER BY ioc_type
        """, (intel_id,)).fetchall()
        if ioc_rows:
            print(f"\nIOCs:")
            current_type = None
            for ioc in ioc_rows:
                if ioc['ioc_type'] != current_type:
                    current_type = ioc['ioc_type']
                    print(f"  [{current_type}]")
                print(f"    {ioc['value']}")

        # Vulnerabilities
        vuln_rows = conn.execute("""
            SELECT cve_id, product, severity
            FROM vulnerabilities WHERE intelligence_id = ?
        """, (intel_id,)).fetchall()
        if vuln_rows:
            print(f"\nVulnerabilities:")
            for v in vuln_rows:
                cve = v['cve_id'] or 'No CVE'
                print(f"  {cve} — {v['product']} [{v['severity']}]")

        # Malware
        malware_rows = conn.execute("""
            SELECT name, type, capabilities
            FROM malware_families WHERE intelligence_id = ?
        """, (intel_id,)).fetchall()
        if malware_rows:
            print(f"\nMalware families:")
            for m in malware_rows:
                caps = json.loads(m['capabilities'] or '[]')
                caps_str = f": {', '.join(caps)}" if caps else ""
                print(f"  {m['name']} [{m['type']}]{caps_str}")

        # Targets
        target_rows = conn.execute("""
            SELECT target_type, value
            FROM targets WHERE intelligence_id = ?
            ORDER BY target_type
        """, (intel_id,)).fetchall()
        if target_rows:
            print(f"\nTargets:")
            current_type = None
            for t in target_rows:
                if t['target_type'] != current_type:
                    current_type = t['target_type']
                    print(f"  [{current_type}]")
                print(f"    {t['value']}")

    conn.close()


if __name__ == "__main__":
    inspect_raw_db()
    inspect_analysed_db()
