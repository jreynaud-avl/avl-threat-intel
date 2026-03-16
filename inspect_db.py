"""
Quick inspection of raw_reports content.
Prints a sample of records showing what's actually in the raw_content field.
"""

import sqlite3
import json

DB_PATH = "threat_intel.db"

conn = sqlite3.connect(DB_PATH)
conn.row_factory = sqlite3.Row

# Overall stats
print("=" * 60)
print("DATABASE SUMMARY")
print("=" * 60)
total = conn.execute("SELECT COUNT(*) FROM raw_reports").fetchone()[0]
print(f"Total reports: {total}")

by_source = conn.execute("""
    SELECT source_name, COUNT(*) as count
    FROM raw_reports
    GROUP BY source_name
""").fetchall()
for row in by_source:
    print(f"  {row['source_name']}: {row['count']} reports")

# Sample 3 records and show full detail
print("\n" + "=" * 60)
print("SAMPLE RECORDS (3)")
print("=" * 60)

rows = conn.execute("""
    SELECT id, source_name, title, published_at, content_type,
           length(raw_content) as content_length, raw_content
    FROM raw_reports
    ORDER BY RANDOM()
    LIMIT 3
""").fetchall()

for i, row in enumerate(rows, 1):
    print(f"\n--- Record {i} ---")
    print(f"ID:           {row['id']}")
    print(f"Source:       {row['source_name']}")
    print(f"Title:        {row['title']}")
    print(f"Published:    {row['published_at']}")
    print(f"Type:         {row['content_type']}")
    print(f"Content size: {row['content_length']} chars")
    print(f"\nRAW CONTENT (first 2000 chars):")
    print("-" * 40)
    print(row['raw_content'][:2000])
    print("-" * 40)

conn.close()
