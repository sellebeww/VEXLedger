# Copyright (c) 2026 Vassel Goleyu. MIT License.
"""Command line: `vexledger create-admin USERNAME` bootstraps the first admin (no public signup)."""

import argparse
import asyncio
import getpass
import os
import sys

from sqlalchemy.exc import IntegrityError

from vexledger.api.schemas import USERNAME
from vexledger.auth.provider import make_hasher
from vexledger.config import get_settings
from vexledger.db.repos.users import UserRepository
from vexledger.db.session import make_engine, make_session_factory

PASSWORD_ENV = "VEXLEDGER_ADMIN_PASSWORD"  # noqa: S105 - the variable name, not a secret


class CliError(Exception):
    pass


def _password() -> str:
    """From the environment (automation) or an interactive prompt; never from argv."""
    if (value := os.environ.get(PASSWORD_ENV)) is not None:
        return value
    if not sys.stdin.isatty():
        raise CliError(f"no terminal: set {PASSWORD_ENV} or run interactively")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat password: "):
        raise CliError("passwords do not match")
    return first


async def create_admin(username: str, password: str) -> None:
    settings = get_settings()
    if not USERNAME.fullmatch(username):
        raise CliError("username must be 3-64 characters of letters, digits, . _ -")
    if len(password) < settings.password_min_length:
        raise CliError(f"password needs at least {settings.password_min_length} characters")
    hashed = make_hasher(settings).hash(password)
    engine = make_engine(settings.database_url)
    try:
        async with make_session_factory(engine)() as session, session.begin():
            await UserRepository(session).create(
                username=username, password_hash=hashed, role="admin"
            )
    except IntegrityError as exc:
        raise CliError(f"user {username!r} already exists") from exc
    finally:
        await engine.dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vexledger")
    sub = parser.add_subparsers(dest="command", required=True)
    admin = sub.add_parser("create-admin", help="create an admin user")
    admin.add_argument("username")
    args = parser.parse_args(argv)
    try:
        asyncio.run(create_admin(args.username, _password()))
    except CliError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1
    sys.stdout.write(f"admin {args.username!r} created\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
