"""`python -m rugguard_mcp` entrypoint with subcommand dispatch.

Subcommands:
  (none) | run   Start the MCP server (stdio transport — the default
                 mode used by Claude Desktop, Cursor, etc.).
  init           Generate a fresh dedicated wallet at `~/.rugguard/wallet.json`.
  status         Print wallet address + current spend caps + 24 h usage.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    sub = args[0] if args else "run"

    if sub in ("run", ""):
        # Lazy import: `init` should work even on a fresh install before
        # `mcp` (FastMCP) is exercised, in case of a broken transport dep.
        from rugguard_mcp.server import run

        run()
        return 0

    if sub == "init":
        from rugguard_mcp.wallet_helper import init_wallet

        force = "--force" in args[1:]
        return init_wallet(force=force)

    if sub == "status":
        from rugguard_mcp.wallet_helper import status

        return status()

    print(
        f"Unknown subcommand: {sub!r}\n"
        "Usage: python -m rugguard_mcp [run|init|status]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
