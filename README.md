# rugguard-mcp

MCP server for [RugGuard](https://rugguard.redfleet.fr) — pre-trade rug-check API for AI agents. Wraps the x402 payment flow so [Claude Desktop](https://claude.ai/download), [Cursor](https://cursor.sh), and other MCP-aware agents can call RugGuard without speaking x402 themselves.

## What it does

Three paid MCP tools:

- **`scan_token(chain, address)`** — runs 14 heuristics on Base + 5 on Solana SPL, returns a weighted risk score 0–100, a verdict (`safe | low_risk | medium_risk | high_risk | critical | uncertain`), and structured red flags (owner renounced, LP locked, honeypot signatures, top10 concentration, mint authority, bytecode similarity to known rugs via MinHash, deployer rug history, etc.). Pays $0.01 USDC on Base behind the scenes.
- **`pretrade_check(chain, address, intended_trade_usd, policy)`** *(new in v0.2.0)* — the pre-trade firewall. Wraps the same engine as `scan_token` and overlays a prescriptive `block | caution | allow` decision plus a clamped `max_suggested_exposure_usd`, given the agent's risk policy (`conservative | balanced | aggressive`). Returns a signed JSON report (Ed25519) when the deployment has signing configured — verifiable offline via the [`rugguard-verify`](https://pypi.org/project/rugguard-verify/) CLI. Same $0.01 USDC price as `scan_token`.
- **`explain_scan(scan_id)`** — replays a previously-cached scan's full per-heuristic audit trail. Pays $0.005 USDC.

One free MCP resource:

- **`rugguard://metrics`** — live empirical recall + per-chain sample counts, sourced from `/v1/metrics`. Free, no payment, no signature. Lets an agent (or a human reviewing the integration) audit per-heuristic recall **before** pointing a funded wallet at the paid tools. No competitor publishes their own miss rate — this is the differentiator made machine-discoverable.

The server holds a dedicated Base-mainnet wallet and signs each EIP-3009 USDC `transferWithAuthorization` transparently. The agent never sees the payment friction.

## Install

```bash
pip install rugguard-mcp
```

## Try it without paying (recommended first step)

Before funding a wallet, verify the MCP integration works end-to-end in
Claude Desktop / Cursor / your runtime. Launch the server in demo mode:

```bash
python -m rugguard_mcp --demo
```

Or configure your MCP client to launch it that way directly:

```json
{
  "mcpServers": {
    "rugguard": {
      "command": "python",
      "args": ["-m", "rugguard_mcp", "--demo"]
    }
  }
}
```

(equivalent: set `RUGGUARD_MCP_DEMO=1` in the `env` block of the MCP
client config).

In demo mode the three paid tools return canned scenarios deterministically
(safe / caution / critical, picked by the last hex char of the address)
flagged with `"_demo": true` so the agent never mistakes them for real
data. No wallet, no payment, no network call to `/v1/scan` or
`/v1/pretrade/check`. The free `rugguard://metrics` resource still serves
the real live recall numbers.

Use this to:

- Verify the tool drawer shows `scan_token`, `pretrade_check`,
  `explain_scan` in Claude Desktop / Cursor.
- Walk through a full scan → decision flow in your agent before
  committing on-chain funds.
- Build and test conditional edges / state branches against realistic
  response shapes.

When you're ready for real scans, drop the `--demo` flag and follow the
First-time setup below.

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

Restart Claude Desktop. The `scan_token`, `pretrade_check`, and `explain_scan` tools appear in the tool drawer.

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

<!-- mcp-name: io.github.dbe006/rugguard-mcp -->

