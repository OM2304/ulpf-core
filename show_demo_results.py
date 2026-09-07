import json
import os
import sqlite3
from pathlib import Path

PARSERS_DIR = Path("ulpf/parsers/generated")
DB_PATH = "live_demo_storage.db"

def show_generated_parsers():
    print("=" * 60)
    print("1. AI-GENERATED PARSERS ON DISK (ulpf/parsers/generated/)")
    print("=" * 60)

    if not PARSERS_DIR.exists():
        print(f"Directory '{PARSERS_DIR}' does not exist.\n")
        return

    json_files = list(PARSERS_DIR.glob("*.json"))
    if not json_files:
        print("No generated parser definitions found on disk.\n")
        return

    for p in json_files:
        size = p.stat().st_size
        print(f"\n[FILE] {p.name} ({size} bytes)")
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                print(f"  • Parser ID : {data.get('parser_id')}")
                print(f"  • Pattern   : {data.get('regex_pattern')}")
                print(f"  • Mappings  : {data.get('field_mappings')}")
        except Exception as err:
            print(f"  • Error reading {p.name}: {err}")
    print()

def show_normalized_events(limit: int = 5):
    print("=" * 60)
    print(f"2. NORMALIZED OCSF EVENTS (Database: {DB_PATH})")
    print("=" * 60)

    if not os.path.exists(DB_PATH):
        print(f"Database file '{DB_PATH}' not found.\n")
        return

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        rows = cursor.execute(
            """
            SELECT event_id, parser_id, src_ip, src_port, dst_ip, dst_port, protocol, action, disposition
            FROM normalized_events
            ORDER BY rowid DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        if not rows:
            print("No normalized records found in 'normalized_events'.\n")
            return

        for idx, row in enumerate(rows, start=1):
            r = dict(row)
            print(f"\n[Event #{idx}] ID: {r['event_id']}")
            print(f"  • Parser Used : {r['parser_id']}")
            print(f"  • Source      : {r['src_ip']}:{r['src_port']}")
            print(f"  • Destination : {r['dst_ip']}:{r['dst_port']}")
            print(f"  • Protocol    : {r['protocol']}")
            print(f"  • Action      : {r['action']} -> Disposition: {r['disposition']}")
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
    finally:
        conn.close()
    print()

if __name__ == "__main__":
    show_generated_parsers()
    show_normalized_events()