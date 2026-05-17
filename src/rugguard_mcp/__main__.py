"""`python -m rugguard_mcp` entrypoint with subcommand dispatch.

Subcommands:
  (none) | run   Start the MCP server (stdio transport — the default
                 mode used by Claude Desktop, Cursor, etc.).
  init           Generate a fresh dedicated wallet at `~/.rugguard/wallet.json`.
  status         Print wallet address + current spend caps + 24 h usage.

Flags (apply to `run` only):
  --demo         Start the server in demo mode: canned scenarios, no
                 wallet required, no payment. Equivalent to setting
                 RUGGUARD_MCP_DEMO=1 in the environment. Use this to
                 verify that Claude Desktop / Cursor sees the tools
                 before funding a real wallet.
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv

    # Parse the --demo flag. We accept it before OR after a subcommand
    # so `python -m rugguard_mcp --demo` and `python -m rugguard_mcp run
    # --demo` both work. Setting the env var BEFORE the server import is
    # not strictly required (the flag is read at call time), but doing
    # it here keeps the contract identical whether the user used the
    # flag or the env var.
    if "--demo" in args:
        os.environ["RUGGUARD_MCP_DEMO"] = "1"
        args = [a for a in args if a != "--demo"]

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
        "Usage: python -m rugguard_mcp [run|init|status] [--demo]",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
