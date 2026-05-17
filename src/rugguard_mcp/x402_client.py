"""Minimal x402 v1 client for RugGuard's MCP server.

Handles the standard 402-then-pay-then-retry flow against an x402-protected
GET endpoint. The signing path uses EIP-3009 `transferWithAuthorization` on
USDC v2 (Base mainnet today), with the holder's private key held only in
process memory — we never touch disk.

Caller must provide a `private_key_hex` for an EOA funded with USDC on Base.
The amount per call is set by the server's 402 response, not by us, so a
mis-priced endpoint can drain the wallet faster than expected.

**Spend caps** (defense in depth against a runaway agent or a misbehaving
remote server): every paid call is gated through `rugguard_mcp.spend_cap`.
A session cap (default $5) and a 24 h cap (default $10) are enforced before
we sign, and the actual settled amount is recorded after a successful
on-chain settle. If either cap is breached we raise `SpendCapExceededError`
without signing — no payment leaves the wallet.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data

from rugguard_mcp.spend_cap import (
    SpendCapExceededError,
    authorize_and_charge as _authorize_and_charge,
    confirm as _confirm_spend,
    rollback as _rollback_spend,
)

BASE_CHAIN_ID = 8453

# How long the EIP-3009 transferWithAuthorization stays valid for replay
# on the USDC contract. Was 60 s; tightened to 10 s after the security
# audit H2 (client): the signature is portable — anyone who captures the
# X-Payment header inside the validBefore window can replay it directly
# against the USDC.transferWithAuthorization function. 10 s is enough for
# DNS + TLS + facilitator verify + on-chain settle (~3-5 s in practice on
# Base), with a couple of seconds of clock-skew tolerance. Tighter than
# spec but spec's 60 s ceiling, not a floor.
SIG_VALID_WINDOW_SECONDS = 10

# USDC decimals on Base — used to convert the server's atomic-unit amount
# back to a USD float for the spend-cap check. Hardcoded because the MCP
# only ever sees USDC (the x402 ecosystem standard on Base today). If a
# future facilitator advertises a different asset, this needs updating.
USDC_DECIMALS = 6

# Asset whitelist (security audit #5): a malicious 402 response — from
# DNS hijack, MITM, or the user setting RUGGUARD_API_URL to an attacker
# host — could ask us to sign a transferWithAuthorization for a DIFFERENT
# EIP-3009-compatible token the user happens to hold (USDT, DAI, etc.).
# The USD-denominated spend cap wouldn't catch it because our atomic→USD
# conversion assumes USDC's 6 decimals; a token with 18 decimals would
# show as a microscopic charge against the cap while transferring the
# full balance.
#
# This map pins (network → expected_asset_address) for every network we'll
# sign payments on. Anything else is rejected before the EIP-3009 signature
# is computed. The asset addresses are checksummed; the comparison is
# case-insensitive so a non-canonical-case 402 doesn't false-negative.
ALLOWED_NETWORK_ASSETS: dict[str, str] = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}

# Canonical EIP-712 domain bindings for USDC v2. The signature is bound to
# (name, version, chainId, verifyingContract) — a malicious server that
# changes name or version would get a signature valid for a token with
# THAT name/version, not USDC. We reject upfront for a clear error rather
# than producing a signature the facilitator silently can't verify.
EXPECTED_EIP712_NAME = "USD Coin"
EXPECTED_EIP712_VERSION = "2"


# X402PaymentError was defined here in v0.1.x and v0.2.0. Moved to
# `rugguard_mcp.errors` in v0.2.1 so SpendCapExceededError can subclass
# it without a circular import. The re-import below keeps every existing
# `from rugguard_mcp.x402_client import X402PaymentError` call site
# working unchanged.
from rugguard_mcp.errors import X402PaymentError  # noqa: E402, F401


def _build_typed_data(
    *,
    payer: str,
    receiver: str,
    value: int,
    asset_addr: str,
    name: str,
    version: str,
    chain_id: int = BASE_CHAIN_ID,
) -> dict[str, Any]:
    now = int(time.time())
    return {
        "domain": {
            "name": name,
            "version": version,
            "chainId": chain_id,
            "verifyingContract": asset_addr,
        },
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "message": {
            "from": payer,
            "to": receiver,
            "value": value,
            # v0.2.2: tightened from 0 to (now - 5). The 5s backward
            # clock-skew tolerance is enough for a facilitator with a
            # mildly fast clock to still accept us, while reducing the
            # signature's TOTAL liveness window to ~15s (SIG_VALID_WINDOW_S
            # forward + 5s back) — well under the EIP-3009 60s ceiling.
            # Mirrors the integration kits' inline x402_pay.py which has
            # used `now - 5` since v0.1.0.
            "validAfter": now - 5,
            "validBefore": now + SIG_VALID_WINDOW_SECONDS,
            "nonce": "0x" + secrets.token_hex(32),
        },
    }


def _encode_payment_header(typed: dict[str, Any], signature_hex: str, network: str) -> str:
    msg = typed["message"]
    payload = {
        "x402Version": 1,
        "scheme": "exact",
        "network": network,
        "payload": {
            "signature": signature_hex,
            "authorization": {
                "from": msg["from"],
                "to": msg["to"],
                "value": str(msg["value"]),
                "validAfter": str(msg["validAfter"]),
                "validBefore": str(msg["validBefore"]),
                "nonce": msg["nonce"],
            },
        },
    }
    return base64.b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()


def _validate_payment_requirements(req: dict[str, Any]) -> None:
    """Reject 402 responses that would make us sign for an untrusted asset.

    Hard-pins (network, asset, EIP-712 domain name+version) to canonical
    USDC-on-Base bindings. Raises X402PaymentError BEFORE the EIP-3009
    signature is computed so no malicious payment ever leaves the wallet.

    Threat model: the server is NOT trusted to choose what token we pay in.
    Without this check, the trust path is:
      DNS → server → 402.accepts[0].asset → eth_account.sign_typed_data → wallet
    All it takes is one compromised link (TLS pin missing, DNS hijack,
    user-set RUGGUARD_API_URL pointing somewhere else) to land in
    sign_typed_data with attacker-chosen field values. The spend cap is
    USD-denominated and assumes USDC 6-decimals — so an 18-decimal token
    sneaks past as a "microscopic" charge while moving full balance.
    """
    network = req.get("network")
    if not isinstance(network, str):
        raise X402PaymentError(f"untrusted_payment_requirement:network={network!r}")
    expected_asset = ALLOWED_NETWORK_ASSETS.get(network)
    if expected_asset is None:
        raise X402PaymentError(
            f"untrusted_payment_requirement:unsupported_network={network!r}"
        )
    asset = req.get("asset")
    if not isinstance(asset, str) or asset.lower() != expected_asset.lower():
        raise X402PaymentError(
            "untrusted_payment_requirement:"
            f"asset={asset!r} on {network!r} "
            f"(this MCP only signs payments to USDC {expected_asset})"
        )
    extra = req.get("extra") if isinstance(req.get("extra"), dict) else {}
    if extra.get("name") != EXPECTED_EIP712_NAME:
        raise X402PaymentError(
            "untrusted_payment_requirement:"
            f"extra.name={extra.get('name')!r} (expected {EXPECTED_EIP712_NAME!r})"
        )
    if extra.get("version") != EXPECTED_EIP712_VERSION:
        raise X402PaymentError(
            "untrusted_payment_requirement:"
            f"extra.version={extra.get('version')!r} (expected {EXPECTED_EIP712_VERSION!r})"
        )


def _extract_tx_hash_from_payment_response(header_value: str | None) -> str | None:
    """Best-effort decode of the X-Payment-Response header to surface the
    on-chain tx hash for the spend log. Returns None silently on any decode
    error — the log entry just goes without a tx hash, which is a recoverable
    audit gap (not a security issue)."""
    if not header_value:
        return None
    try:
        decoded = base64.b64decode(header_value, validate=True).decode("utf-8")
        payload = json.loads(decoded)
    except ValueError:
        # Covers binascii.Error (bad base64), UnicodeDecodeError, and
        # JSONDecodeError — all ValueError subclasses since Python 3.10.
        return None
    tx = payload.get("transaction") if isinstance(payload, dict) else None
    return tx if isinstance(tx, str) else None


async def _x402_round_trip(
    *,
    client: httpx.AsyncClient,
    method: str,
    url: str,
    private_key_hex: str,
    json_body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    """Shared 402-then-pay-then-retry core for paid_get and paid_post.

    `method` is "GET" or "POST". For POST, `json_body` is sent on both the
    first probe and the signed retry — FastAPI's Depends() runs BEFORE
    request-body parsing, so the body is unconsumed on the initial 402.

    Spend caps are reserved BEFORE the EIP-3009 signature is computed.
    On any non-200 outcome, the reservation is released so the cap budget
    isn't burned by a failed call.
    """
    account = Account.from_key(private_key_hex.removeprefix("0x"))

    first = await client.request(method, url, json=json_body)
    if first.status_code != 402:
        return first.status_code, first.json()

    body = first.json()
    try:
        req = body["accepts"][0]
    except (KeyError, IndexError, TypeError) as exc:
        raise X402PaymentError("invalid_402_body") from exc

    # Asset / network / EIP-712 domain whitelist — refuse to sign for
    # anything other than canonical USDC on Base. This MUST run BEFORE
    # the cap reservation so we don't burn a charge_id on a rejected
    # 402; and BEFORE the EIP-3009 signature so a malicious server
    # can't drain a non-USDC token the user happens to also hold.
    _validate_payment_requirements(req)

    # Defense in depth: refuse to sign if the amount the server is asking
    # for would push us over a configured spend cap. Enforced client-side,
    # BEFORE the EIP-3009 signature is computed — even a compromised
    # server can't trick us into draining the wallet, because the cap
    # budget lives entirely on the user's machine.
    #
    # Concurrency: authorize_and_charge() atomically reserves the slot
    # by appending a pending entry under a file lock. Two concurrent
    # paid calls can't both pass the same cap baseline — the second
    # sees the first's pending and rejects. We MUST confirm() on settle
    # success or rollback() on any failure path, otherwise the slot leaks
    # for up to 24 h (until the entry rolls out of the daily window).
    atomic_amount = int(req["maxAmountRequired"])
    amount_usd = atomic_amount / (10**USDC_DECIMALS)
    charge_id = _authorize_and_charge(amount_usd)  # raises if over cap

    try:
        typed = _build_typed_data(
            payer=account.address,
            receiver=req["payTo"],
            value=atomic_amount,
            asset_addr=req["asset"],
            name=req["extra"]["name"],
            version=req["extra"]["version"],
        )
        signable = encode_typed_data(full_message=typed)
        signed = Account.sign_message(signable, private_key=account.key)
        sig = signed.signature.hex()
        if not sig.startswith("0x"):
            sig = "0x" + sig
        header = _encode_payment_header(typed, sig, req["network"])

        second = await client.request(
            method, url, json=json_body, headers={"X-Payment": header}
        )
        if second.status_code == 402:
            # Server rejected the payment — release the cap reservation
            # so the user can retry without burning a slot.
            _safely_rollback(charge_id)
            err = second.json().get("error", "unknown")
            raise X402PaymentError(f"payment_rejected:{err}")
        if second.status_code == 200:
            tx_hash = _extract_tx_hash_from_payment_response(
                second.headers.get("X-Payment-Response")
                or second.headers.get("Payment-Response")
            )
            # Promote pending → settled (best-effort: FS error mustn't
            # fail a request the user already paid for; the pending entry
            # will roll off the 24 h window automatically if confirm
            # itself fails).
            _safely_confirm(charge_id, tx_hash)
        else:
            # Non-200, non-402 — settle never happened, free the slot.
            _safely_rollback(charge_id)
        return second.status_code, second.json()
    except BaseException:
        # Any exit through this except path means we either never sent the
        # signed request or never got a successful response. Free the cap
        # reservation. Includes asyncio.CancelledError + KeyboardInterrupt.
        _safely_rollback(charge_id)
        raise


async def paid_get(
    *,
    url: str,
    private_key_hex: str,
    timeout_seconds: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    """GET an x402-protected URL, paying automatically if 402 is returned.

    Returns (status_code, body). On the happy path: status=200 and body is the
    resource's JSON. On payment failure: re-raises X402PaymentError with the
    server-reported reason so the caller can surface it to the agent.

    Spend caps are enforced before signing: if the requested amount would push
    either the session or the 24 h total over the configured cap, raises
    SpendCapExceededError WITHOUT signing, so no payment leaves the wallet.
    """
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        return await _x402_round_trip(
            client=client, method="GET", url=url, private_key_hex=private_key_hex
        )


async def paid_post(
    *,
    url: str,
    json_body: dict[str, Any],
    private_key_hex: str,
    timeout_seconds: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    """POST an x402-protected URL with a JSON body, paying automatically on 402.

    Same semantics as `paid_get`: returns (status_code, body), raises
    `SpendCapExceededError` before signing if the requested amount would
    breach a cap, raises `X402PaymentError` on payment-side rejection.

    The JSON body is sent on BOTH the initial probe and the signed retry
    because FastAPI's payment dependency runs before body parsing — the
    initial 402 short-circuits before the server has consumed the body.

    Use for `/v1/pretrade/check` and any future POST-based paid endpoint.
    """
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        return await _x402_round_trip(
            client=client,
            method="POST",
            url=url,
            private_key_hex=private_key_hex,
            json_body=json_body,
        )


def _safely_confirm(charge_id: str, tx_hash: str | None) -> None:
    """Wrap confirm() to swallow transient OSErrors — we never want the audit
    write to fail a request the user has already paid for on-chain."""
    try:
        _confirm_spend(charge_id, tx_hash)
    except OSError:
        pass


def _safely_rollback(charge_id: str) -> None:
    """Wrap rollback() to swallow transient OSErrors. Worst case the pending
    entry rots out of the 24 h window naturally."""
    try:
        _rollback_spend(charge_id)
    except OSError:
        pass


# Re-export for convenience — callers (server.py) handle this distinctly
# from network errors when surfacing to the agent.
__all__ = ["X402PaymentError", "SpendCapExceededError", "paid_get", "paid_post"]
