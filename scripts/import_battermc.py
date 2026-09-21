from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.config import settings  # noqa: E402
from app.store import Store  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Import legacy Better MC accounts into Muxi Account")
    parser.add_argument("legacy_db", type=Path)
    parser.add_argument("--target", type=Path, default=settings.database_path)
    args = parser.parse_args()

    if not args.legacy_db.is_file():
        print(f"legacy database not found: {args.legacy_db}", file=sys.stderr)
        return 2

    target = Store(args.target)
    imported = skipped = 0
    with sqlite3.connect(args.legacy_db) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT email,username,password_hash,role,verified,created_at,last_login_at FROM accounts ORDER BY id"
        ).fetchall()
    for row in rows:
        _, created = target.import_account(
            email=str(row["email"]),
            username=str(row["username"]),
            password_hash=str(row["password_hash"]),
            role=str(row["role"]),
            verified=bool(row["verified"]),
            created_at=str(row["created_at"]),
            last_login_at=row["last_login_at"],
        )
        imported += int(created)
        skipped += int(not created)
    print(f"legacy accounts: {len(rows)}, imported: {imported}, skipped existing: {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
