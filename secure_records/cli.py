"""Create the first admin from the command line (the API itself needs an admin to add users).

    SECRET_KEY=... python -m secure_records.cli create-user --email you@example.com --role admin
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import select

from .config import Settings
from .main import create_app, init_schema
from .models import User
from .security import ROLES, hash_password


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="secure_records")
    sub = parser.add_subparsers(dest="command", required=True)
    cu = sub.add_parser("create-user")
    cu.add_argument("--email", required=True)
    cu.add_argument("--role", choices=ROLES, default="analyst")
    args = parser.parse_args(argv)

    app = create_app(Settings.from_env())
    init_schema(app)
    password = getpass.getpass("Password (min 10 characters): ")
    try:
        password_hash = hash_password(password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    with app.state.sessionmaker() as db:
        if db.scalar(select(User.id).where(User.email == args.email.lower())):
            print("Error: that email already exists.", file=sys.stderr)
            return 2
        db.add(User(email=args.email.lower(), password_hash=password_hash, role=args.role))
        db.commit()
    print(f"Created {args.role} {args.email.lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
