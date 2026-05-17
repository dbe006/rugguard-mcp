"""Wallet onboarding helper for the RugGuard MCP server.

`python -m rugguard_mcp init` creates a fresh, dedicated EOA wallet for the
MCP server and prints onboarding instructions. The wallet is stored under
`~/.rugguard/wallet.json` with mode 600 (POSIX best-effort).

Why a dedicated wallet:
  - Limits blast radius if the private key leaks.
  - Lets the user fund a small bounded balance ($5 to $20) and treat it as a
    spending cap, on top of the in-process caps in spend_cap.py.
  - Makes accidental private-key commits less catastrophic (the wallet only
    holds what was deposited for RugGuard calls).

The init command refuses to overwrite an existing wallet file — the user has
to delete it manually. This is intentional: regenerating silently would lose
any USDC already deposited on the old address.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from eth_account import Account

DEFAULT_WALLET_PATH = Path.home() / ".rugguard" / "wallet.json"


def wallet_path() -> Path:
    """Resolve the wallet storage path — env override + default."""
    override = os.environ.get("RUGGUARD_MCP_WALLET_PATH")
    if override:
        return Path(override).expanduser()
    return DEFAULT_WALLET_PATH


def load_wallet() -> dict[str, Any] | None:
    """Return the saved wallet record, or None if not initialized."""
    path = wallet_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save_wallet(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write so a crash mid-init can't leave a partial wallet file
    # with a private key that wasn't reported to the user.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX FS — best-effort.


def init_wallet(*, force: bool = False, output_stream: Any = None) -> int:
    """Generate a fresh wallet and write it to disk. Returns a CLI exit code.

    `force=True` overwrites an existing wallet file. Default is to refuse.
    """
    out = output_stream or sys.stdout
    path = wallet_path()

    if path.exists() and not force:
        print(
            f"Wallet already exists at {path}. Refusing to overwrite.\n"
            f"  - To inspect: cat '{path}' (contains the private key, treat as a secret).\n"
            f"  - To regenerate (and LOSE any USDC on the current address): delete the file first.",
            file=out,
        )
        return 1

    account = Account.create()
    # `account.key` is bytes; we store the hex form. eth_account uses the
    # canonical no-0x form internally, but adding the 0x prefix makes the
    # file usable by typical Web3 tooling (Foundry, Hardhat, MetaMask import).
    private_key_hex = "0x" + account.key.hex().removeprefix("0x")

    _save_wallet(
        path,
        {
            "version": 1,
            "address": account.address,
            "private_key": private_key_hex,
            "chain": "base",
            "purpose": "rugguard-mcp dedicated payer wallet",
        },
    )

    print(
        "\n  RugGuard MCP wallet generated.\n"
        "  --------------------------------\n"
        f"  Address       : {account.address}\n"
        f"  Stored at     : {path}\n"
        f"  Permissions   : 0600 (POSIX best-effort)\n"
        "\n"
        "  Next steps:\n"
        "    1. Send 5 to 20 USDC on Base mainnet to the address above.\n"
        "       (Coinbase: withdraw → Asset USDC → Network Base → paste address.\n"
        "        Binance: same, ensure 'BASE' network, not 'BSC' or 'BEP20'.)\n"
        "    2. Wait for confirmation on basescan: https://basescan.org/address/"
        + account.address
        + "\n"
        "    3. Configure your MCP client to launch `python -m rugguard_mcp`.\n"
        "       The wallet is auto-discovered from this file.\n"
        "\n"
        "  Safety notes:\n"
        "    - This wallet is dedicated. Do NOT reuse it for anything else.\n"
        "    - The spending caps default to $5/session and $10/24h — restrict\n"
        "      further with RUGGUARD_MCP_SESSION_SPEND_CAP_USD and\n"
        "      RUGGUARD_MCP_DAILY_SPEND_CAP_USD.\n"
        "    - Treat the file above like an SSH key. Don't commit it.\n",
        file=out,
    )
    return 0


def status() -> int:
    """Print the current wallet + cap state. Returns a CLI exit code."""
    # Import inside to avoid a circular import at module-load time (spend_cap
    # is imported from x402_client which the server imports — keeping this
    # branch lazy means `rugguard-mcp init` doesn't pull in spend_cap state).
    from rugguard_mcp.spend_cap import summary_for_human

    wallet = load_wallet()
    path = wallet_path()

    if wallet is None:
        print(
            f"No wallet found at {path}.\n"
            "  Run `python -m rugguard_mcp init` to generate one.",
            file=sys.stdout,
        )
        return 1

    address = wallet.get("address", "<unknown>")
    print(
        f"Wallet         : {address}\n"
        f"File           : {path}\n"
        f"Spend          : {summary_for_human()}\n"
        f"basescan       : https://basescan.org/address/{address}",
        file=sys.stdout,
    )
    return 0
