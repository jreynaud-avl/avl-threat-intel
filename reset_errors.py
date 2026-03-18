"""
Resets reports with status='error' back to 'pending' so Stage 2 retries them.
Run manually via the GitHub Actions workflow when needed.
"""
import sqlite3
from pathlib import Path

DB = Path("threat_intel.db")
conn = sqlite3.connect(DB)

errors = conn.execute("SELECT id, title FROM raw_reports WHERE status = 'error'").fetchall()
print(f"Found {len(errors)} errored reports:")
for row in errors:
    print(f"  [{row[0]}] {row[1]}")

conn.execute("UPDATE raw_reports SET status = 'pending' WHERE status = 'error'")
conn.commit()
print(f"\nReset {len(errors)} reports back to pending")
conn.close()
