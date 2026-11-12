#!/usr/bin/env python3
"""
Checks that HomeGuard can reach the Oracle database with your .env settings.

    python3 test_connection.py
"""

import sys

import oracledb

import db

EXPECTED = ["DEVICES", "FLAGGED", "NETWORK", "USERS"]


def main() -> int:
    print("[*] Connecting with the settings in database/.env ...")
    try:
        pool = db.get_pool()
        with pool.acquire() as conn, conn.cursor() as cur:
            cur.execute("SELECT USER FROM dual")
            print(f"[OK] Connected as {cur.fetchone()[0]}")

            cur.execute("SELECT table_name FROM user_tables WHERE table_name IN ('USERS','DEVICES','NETWORK','FLAGGED')")
            found = sorted(r[0] for r in cur.fetchall())
            missing = [t for t in EXPECTED if t not in found]
            if missing:
                print(f"[!] Missing tables: {', '.join(missing)}. Run backend/setup.sql first.")
                return 1
            print(f"[OK] Tables found: {', '.join(found)}")
    except RuntimeError as err:                       # missing .env value or wallet folder
        print(f"[!] {err}")
        return 1
    except oracledb.Error as err:
        print(f"[!] Database error: {err}")
        print("    Common causes: wrong DB_USER / DB_PASSWORD, DB_DSN not listed in tnsnames.ora,")
        print("    wrong WALLET_PASSWORD, or WALLET_DIR pointing at the wrong folder.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())