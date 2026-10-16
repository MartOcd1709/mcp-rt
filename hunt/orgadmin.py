"""`mcp-rt org` — platform tenant admin from the CLI (create orgs, mint role-scoped tokens).

For VPS/ops bootstrapping without the dashboard. Uses the same DATABASE_URL store as `mcp-rt serve`.

    mcp-rt org create --name "Acme Corp"              # -> prints an owner token (store it safely)
    mcp-rt org token  --org-id 2 --role member        # -> prints a member token for that org
"""
from __future__ import annotations

import argparse
import sys

from hunt.platform_db import ROLES, Store


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mcp-rt org", description="platform org / API-token admin")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--db", default=None,
                        help="DB url (default: $DATABASE_URL or sqlite:///mcprt_platform.db)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create", parents=[common], help="create an org, print its owner token")
    c.add_argument("--name", required=True)
    t = sub.add_parser("token", parents=[common], help="mint an additional token for an org")
    t.add_argument("--org-id", type=int, required=True)
    t.add_argument("--role", default="member", choices=ROLES)
    args = p.parse_args(argv)

    store = Store(args.db)
    if args.cmd == "create":
        tok = store.create_org(args.name)
        print(f"org '{args.name}' created. OWNER token (shown once — store it safely):\n    {tok}")
    elif args.cmd == "token":
        tok = store.create_token(args.org_id, args.role)
        print(f"{args.role} token for org {args.org_id} (shown once):\n    {tok}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
