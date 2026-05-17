"""Error classes for rugguard-mcp.

Extracted into its own module to break the circular dependency:
  - `x402_client.py` raises `X402PaymentError` AND imports
    `SpendCapExceededError` from `spend_cap.py`.
  - `spend_cap.py` raises `SpendCapExceededError`. As of v0.2.1, this
    error subclasses `X402PaymentError` so downstream integration kits
    that do `except X402PaymentError` automatically also catch a
    spend-cap breach. Without the subclass relationship the upgrade
    path documented in the kits' READMEs (drop-in replacement of the
    inline `paid_post` with `from rugguard_mcp.x402_client import
    paid_post`) would surface spend-cap breaches as **uncaught**
    exceptions in the agent's event loop — which was the v0.2.0
    behavior and the reason for this v0.2.1 bump.

Re-exported from `rugguard_mcp.x402_client` for backwards compatibility
so existing `from rugguard_mcp.x402_client import X402PaymentError,
SpendCapExceededError` keeps working unchanged.
"""

from __future__ import annotations


class X402PaymentError(RuntimeError):
    """Raised when the x402 round-trip fails (invalid 402 body, payment
    rejected by the facilitator, etc.).

    Catch this in user code if you want to handle ANY payment-side
    failure uniformly — including spend-cap breaches, since
    `SpendCapExceededError` is a subclass."""


class SpendCapExceededError(X402PaymentError):
    """Raised when a payment would push the total over a configured cap.

    Subclasses `X402PaymentError` (since v0.2.1) so callers using
    `except X402PaymentError:` automatically also catch this — the
    documented "drop-in upgrade" path from the inline kit `paid_post`
    to the MCP version requires this subclass relationship.
    """

    def __init__(self, cap_kind: str, cap_usd: float, would_be_total_usd: float) -> None:
        super().__init__(
            f"{cap_kind} cap of ${cap_usd:.4f} would be exceeded "
            f"(post-charge total: ${would_be_total_usd:.4f}). "
            "Restart the server to reset the session cap, or top up the daily "
            "cap with RUGGUARD_MCP_DAILY_SPEND_CAP_USD."
        )
        self.cap_kind = cap_kind
        self.cap_usd = cap_usd
        self.would_be_total_usd = would_be_total_usd
