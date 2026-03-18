"""
Rebuild Script
==============
Drops the analysed database and resets all raw reports to 'pending'
so Stage 2 re-processes everything from scratch with the new schema.

Run this via the rebuild_db GitHub Actions workflow whenever the
Stage 2 schema changes significantly.

Usage:
    python rebuild_db.py
"""

import sqlite3
import os
from pathlib import Path

RAW_DB      = Path("threat_intel.db")
ANALYSED_DB = Path("threat_intel_analysed.db")


def rebuild():
    # Step 1 — delete the analysed DB entirely
    if ANALYSED_DB.exists():
        os.remove(ANALYSED_DB)
        print(f"Deleted {ANALYSED_DB}")
    else:
        print(f"{ANALYSED_DB} not found — nothing to delete")

    # Step 2 — reset all reports in the raw DB back to pending
    if not RAW_DB.exists():
        print(f"ERROR: {RAW_DB} not found — cannot reset statuses")
        return

    conn = sqlite3.connect(RAW_DB)

    # Count current statuses before reset
    statuses = conn.execute("""
        SELECT status, COUNT(*) as count
        FROM raw_reports
        GROUP BY status
    """).fetchall()
    print(f"\nCurrent raw DB statuses before reset:")
    for s in statuses:
        print(f"  {s[0]}: {s[1]}")

    # Reset everything back to pending
    conn.execute("""
        UPDATE raw_reports
        SET status = 'pending', skip_reason = NULL
        WHERE status IN ('analysed', 'skipped', 'error')
    """)
    conn.commit()

    total = conn.execute(
        "SELECT COUNT(*) FROM raw_reports WHERE status = 'pending'"
    ).fetchone()[0]

    conn.close()
    print(f"\nReset complete — {total} reports set to 'pending'")
    print("Stage 2 will re-process all reports on the next run.")


if __name__ == "__main__":
    rebuild()
