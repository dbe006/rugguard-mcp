# rugguard-mcp

MCP server for [RugGuard](https://rugguard.redfleet.fr) — pre-trade rug-check API for AI agents. Wraps the x402 payment flow so [Claude Desktop](https://claude.ai/download), [Cursor](https://cursor.sh), and other MCP-aware agents can call RugGuard without speaking x402 themselves.

## What it does

Two paid MCP tools:

- **`scan_token(chain, address)`** — runs 14 heuristics on Base + 5 on Solana SPL, returns a weighted risk score 0–100, a verdict (`safe | low_risk | medium_risk | high_risk | critical | uncertain`), and structured red flags (owner renounced, LP locked, honeypot signatures, top10 concentration, mint authority, bytecode similarity to known rugs via MinHash, deployer rug history, etc.). Pays $0.01 USDC on Base behind the scenes.
- **`explain_scan(scan_id)`** — replays a previously-cached scan's full per-heuristic audit trail. Pays $0.005 USDC.

One free MCP resource:

- **`rugguard://metrics`** — live empirical recall + per-chain sample counts, sourced from `/v1/metrics`. Free, no payment, no signature. Lets an agent (or a human reviewing the integration) audit per-heuristic recall **before** pointing a funded wallet at the paid tools. No competitor publishes their own miss rate — this is the differentiator made machine-discoverable.

The server holds a dedicated Base-mainnet wallet and signs each EIP-3009 USDC `transferWithAuthorization` transparently. The agent never sees the payment friction.

## Install

```bash
pip install rugguard-mcp
```

## First-time setup

Generate a dedicated wallet (never reuse your main one):

```bash
python -m rugguard_mcp init
```

This creates `~/.rugguard/wallet.json` (mode 600 on POSIX) and prints the address to fund. Send **5–20 USDC on Base mainnet** to that address — both Coinbase and Binance support "Network: Base" withdrawals.

Check status:

```bash
python -m rugguard_mcp status
```

## Configure your MCP client

### Claude Desktop

Edit `claude_desktop_config.json` (`%APPDATA%\Claude\claude_desktop_config.json` on Windows, `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "rugguard": {
      "command": "python",
      "args": ["-m", "rugguard_mcp"]
    }
  }
}
```

Restart Claude Desktop. The `scan_token` and `explain_scan` tools appear in the tool drawer.

### Cursor / other MCP clients

Same `mcpServers` shape, point to `python -m rugguard_mcp` or the `rugguard-mcp` console script.

## Safety

**Spending caps** (defense in depth against a runaway agent or a compromised remote server):

| Cap | Default | Override |
|---|---|---|
| Per-session (resets on restart) | $5 | `RUGGUARD_MCP_SESSION_SPEND_CAP_USD` |
| Rolling 24 h | $10 | `RUGGUARD_MCP_DAILY_SPEND_CAP_USD` |

The caps are enforced **client-side, before** the EIP-3009 signature — even a compromised 402 response can't trick the wallet into overspending.

**Asset whitelist**: the client refuses to sign for anything other than canonical USDC on Base (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) or Base Sepolia. A malicious 402 trying to redirect to a different EIP-3009-compatible token in your wallet is rejected before signing.

**Replay window**: EIP-3009 authorizations are bound to a 10-second `validBefore` window — short enough that a captured payment header can't be replayed against the USDC contract after the legitimate settlement.

**Wallet at rest**: `~/.rugguard/wallet.json` is mode 600 on POSIX (best-effort on Windows — set ACLs manually for production-grade isolation). Treat the file like an SSH key: don't commit it, don't share it.

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `RUGGUARD_API_URL` | `https://rugguard.redfleet.fr` | Override for staging / self-hosted |
| `RUGGUARD_X402_PRIVATE_KEY` | unset | Legacy fallback for users who don't want `init` |
| `RUGGUARD_MCP_WALLET_PATH` | `~/.rugguard/wallet.json` | Move the wallet file elsewhere |
| `RUGGUARD_MCP_SPEND_LOG_PATH` | `~/.rugguard/spend_log.json` | Where the 24 h spend ledger lives |
| `RUGGUARD_MCP_SESSION_SPEND_CAP_USD` | `5.0` | Tighter cap for cautious operators |
| `RUGGUARD_MCP_DAILY_SPEND_CAP_USD` | `10.0` | Tighter cap for cautious operators |

## Source

This package is the public, slim distribution of the MCP server. The underlying RugGuard API + heuristic engine remain in a private repo. Code in this repo is MIT-licensed and auditable end-to-end — review it before pointing your funded wallet at it.

- API: https://rugguard.redfleet.fr
- OpenAPI: https://rugguard.redfleet.fr/openapi.json
- Methodology + empirical recall: https://rugguard.redfleet.fr/validation.html
- x402scan: https://www.x402scan.com/server/88f6ecef-5668-4def-90a3-6984865f0e06

## License

MIT — see [LICENSE](LICENSE).
