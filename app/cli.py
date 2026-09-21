from __future__ import annotations

import argparse

from .config import settings
from .store import Store


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    promote = sub.add_parser("promote-admin", help="Promote an account to admin")
    promote.add_argument("identity", help="email or username")
    args = parser.parse_args()

    store = Store(settings.database_path)
    if args.command == "promote-admin":
        account = store.promote_admin(args.identity)
        if account is None:
            print("account not found")
            return 2
        print(f"promoted {account.username} ({account.email})")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

