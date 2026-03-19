"""
Migration: Add detection mapping columns to ttps table
=======================================================
Adds mapped_detection_id and detection_status to the existing ttps table
without dropping or modifying any existing data.

Safe to run multiple times — uses ALTER TABLE ADD COLUMN which is a no-op
if the column already exists (handled via try/except).

Usage:
    python migrate_add_detection_columns.py
"""

import sqlite3
from pathlib import Path

ANALYSED_DB = Path("threat_intel_analysed.db")


def migrate():
    if not ANALYSED_DB.exists():
        print(f"ERROR: {ANALYSED_DB} not found")
        return

    conn = sqlite3.connect(ANALYSED_DB)

    # Show current ttps table structure
    cols = conn.execute("PRAGMA table_info(ttps)").fetchall()
    print("Current ttps columns:")
    for c in cols:
        print(f"  {c[1]} ({c[2]})")

    # Count existing rows so we can confirm nothing was lost
    ttp_count = conn.execute("SELECT COUNT(*) FROM ttps").fetchone()[0]
    print(f"\nExisting TTP rows: {ttp_count}")

    # Add mapped_detection_id column
    try:
        conn.execute("ALTER TABLE ttps ADD COLUMN mapped_detection_id TEXT")
        print("\nAdded column: mapped_detection_id")
    except sqlite3.OperationalError as e:
        print(f"\nSkipped mapped_detection_id: {e}")

    # Add detection_status column with default 'unreviewed'
    try:
        conn.execute(
            "ALTER TABLE ttps ADD COLUMN detection_status TEXT DEFAULT 'unreviewed'"
        )
        # Set all existing rows to 'unreviewed'
        conn.execute(
            "UPDATE ttps SET detection_status = 'unreviewed' WHERE detection_status IS NULL"
        )
        print("Added column: detection_status (all existing rows set to 'unreviewed')")
    except sqlite3.OperationalError as e:
        print(f"Skipped detection_status: {e}")

    conn.commit()

    # Confirm final structure
    cols_after = conn.execute("PRAGMA table_info(ttps)").fetchall()
    print("\nUpdated ttps columns:")
    for c in cols_after:
        print(f"  {c[1]} ({c[2]}) default={c[4]}")

    # Confirm row count unchanged
    ttp_count_after = conn.execute("SELECT COUNT(*) FROM ttps").fetchone()[0]
    print(f"\nTTP rows after migration: {ttp_count_after}")
    print("\nMigration complete — no data was modified or deleted.")

    conn.close()


if __name__ == "__main__":
    migrate()
