"""Spending caps for the RugGuard MCP server.

Protects the user's funded wallet from runaway agents:

  - **Session cap** (default $5) — total spent since process start. Resets
    when the MCP server is restarted. Catches a buggy agent that loops on
    `scan_token`.
  - **Daily cap** (default $10) — total spent in the last rolling 24 h.
    Persists across restarts via `~/.rugguard/spend_log.json`. Catches an
    agent that drains the wallet slowly over multiple sessions.

Both caps default conservative. Override via env vars:

  RUGGUARD_MCP_SESSION_SPEND_CAP_USD
  RUGGUARD_MCP_DAILY_SPEND_CAP_USD

A user can disable a cap by setting it to a very large number (we don't
support a literal "unlimited" sentinel because that risks accidental
disablement). Setting either to 0 means "deny every paid call" — useful
for dry-run testing.

## Concurrency model (security audit Path-2 #4)

The earlier API exposed `authorize()` + `record()` with the record landing
only AFTER the on-chain settle. Between the two, two concurrent
`scan_token` calls could both pass `authorize()` against the same
baseline, both sign + settle on chain, and only THEN both record —
blowing the cap by 2x. Two changes neutralize this:

  1. **Pre-reservation** — `authorize_and_charge(amount)` atomically reads
     the log, computes the would-be total INCLUDING pending entries from
     prior in-flight calls, raises if over the cap, and appends a
     `status="pending"` entry. Subsequent `authorize_and_charge` sees the
     pending and respects it.

  2. **File lock** — the read-classify-write triple in
     `authorize_and_charge` happens inside an OS-level exclusive lock
     (sentinel `.lock` file with `O_EXCL`, cross-platform, no external
     dep). The locked section contains NO `await`, so under Python's GIL
     the lock is atomic for both intra-process asyncio concurrency AND
     multiple MCP server instances running against the same log path.

After the call, the caller invokes `confirm(charge_id, tx_hash)` on
success (pending → settled) or `rollback(charge_id)` on payment failure
(pending entry removed). A pending entry that never gets confirmed/
rolled back rots out of the 24 h window after a day, so a crashed process
mid-call leaks at most one cap slot for 24 h, not forever.

Persistence: JSON log under `~/.rugguard/spend_log.json` (atomic write
via tmp + os.replace, mode 600 on POSIX). If multiple MCP servers are run
on the same machine against DIFFERENT wallets, set
`RUGGUARD_MCP_SPEND_LOG_PATH` per server so they don't share caps.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_SESSION_CAP_USD = 5.0
DEFAULT_DAILY_CAP_USD = 10.0

# Anchored when the module is imported (= process start), used to scope the
# session cap. A fresh restart resets the session counter to zero.
_PROCESS_STARTED_AT = time.time()

# How long to wait for the file lock before giving up. The locked section
# only touches a tiny JSON file (no network, no DB) so contention should
# clear in milliseconds even on slow disks. 5 s is generous; if we hit it,
# something is wrong (stale .lock, FS hang).
_LOCK_TIMEOUT_S = 5.0

# A .lock file older than this is assumed to be from a crashed process and
# silently reaped. Conservative because a lock held for >30 s by a healthy
# process would already have busted the _LOCK_TIMEOUT_S deadline.
_STALE_LOCK_AGE_S = 30.0


# SpendCapExceededError was defined here in v0.1.x and v0.2.0. Moved to
# `rugguard_mcp.errors` in v0.2.1 to break the circular dependency that
# prevented it from subclassing X402PaymentError. The re-export below
# keeps the import path `from rugguard_mcp.spend_cap import
# SpendCapExceededError` working unchanged.
from rugguard_mcp.errors import SpendCapExceededError  # noqa: E402, F401


@dataclass(frozen=True)
class SpendState:
    session_spent_usd: float
    daily_spent_usd: float
    session_cap_usd: float
    daily_cap_usd: float


def _log_path() -> Path:
    override = os.environ.get("RUGGUARD_MCP_SPEND_LOG_PATH")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".rugguard" / "spend_log.json"


def _session_cap() -> float:
    return float(
        os.environ.get("RUGGUARD_MCP_SESSION_SPEND_CAP_USD", DEFAULT_SESSION_CAP_USD)
    )


def _daily_cap() -> float:
    return float(os.environ.get("RUGGUARD_MCP_DAILY_SPEND_CAP_USD", DEFAULT_DAILY_CAP_USD))


def _load_entries(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Corrupt log file shouldn't lock the user out of paying. Log will be
        # overwritten on the next successful write.
        return []
    entries = raw.get("entries") if isinstance(raw, dict) else None
    return entries if isinstance(entries, list) else []


def _trim_to_24h(entries: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    cutoff = now - 86400
    return [
        e
        for e in entries
        if isinstance(e.get("ts_epoch"), (int, float)) and e["ts_epoch"] >= cutoff
    ]


def _persist(path: Path, entries: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: tmp then rename. Survives crashes mid-write.
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps({"version": 1, "entries": entries}, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    # Tighten perms — the log doesn't contain the key but it does reveal
    # spending patterns and tx hashes that we'd rather not leak.
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows / non-POSIX FS — best-effort.


def _reap_if_stale(lock_path: Path) -> bool:
    """Remove `lock_path` if it's older than _STALE_LOCK_AGE_S. Returns
    True if reaped (or vanished spontaneously), False if it's a healthy
    lock that the caller should keep waiting on."""
    try:
        age = time.time() - lock_path.stat().st_mtime
    except OSError as exc:
        # ENOENT = vanished between our FileExistsError and stat() — fine,
        # the next loop iteration will re-attempt the create.
        return exc.errno == errno.ENOENT
    if age <= _STALE_LOCK_AGE_S:
        return False
    with contextlib.suppress(OSError):
        os.unlink(lock_path)
    return True


@contextlib.contextmanager
def _file_lock(path: Path, timeout: float = _LOCK_TIMEOUT_S) -> Iterator[None]:
    """Cross-platform exclusive lock via O_EXCL sentinel file.

    Works on Windows AND POSIX without an external dep. The mechanism is
    `os.open(... O_CREAT | O_EXCL)` which is atomic at the syscall level —
    only one caller wins; the rest get FileExistsError. We poll with a
    short sleep until acquired or the deadline hits.

    Stale-lock recovery: if a .lock file is older than _STALE_LOCK_AGE_S
    we assume the holder crashed and reap it. The healthy fast path
    (acquire under contention <100 ms) never enters this branch.

    Critical: the body of the `with` block must NOT contain `await` —
    if asyncio gives up the loop while holding the sentinel, another
    coroutine in the same process could acquire it via the same lock
    function (file locks are not asyncio-aware on the same FD).
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + timeout
    fd: int | None = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            break
        except FileExistsError:
            if _reap_if_stale(lock_path):
                continue
            if time.time() > deadline:
                raise TimeoutError(
                    f"Could not acquire spend-cap lock on {lock_path} within {timeout}s"
                ) from None
            time.sleep(0.01)
    try:
        yield
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            os.unlink(lock_path)


def _sum_amounts(entries: list[dict[str, Any]], *, only_pending_or_settled: bool = True) -> float:
    """Sum amount_usd. Default counts BOTH pending and settled entries so
    pre-reservation works."""
    total = 0.0
    for e in entries:
        status = e.get("status", "settled")  # legacy entries (pre-fix) have no status
        if only_pending_or_settled and status not in ("pending", "settled"):
            continue
        try:
            total += float(e.get("amount_usd", 0))
        except (TypeError, ValueError):
            continue
    return total


def current_state() -> SpendState:
    """Snapshot of session + daily spend totals INCLUDING pending entries.

    Counts pending so a coroutine that's mid-flight (signed but not yet
    settled) still occupies its cap slot — otherwise a second concurrent
    call would see the pre-call baseline and double-spend.
    """
    now = time.time()
    entries = _trim_to_24h(_load_entries(_log_path()), now)
    daily = _sum_amounts(entries)
    session = _sum_amounts(
        [e for e in entries if float(e.get("ts_epoch", 0)) >= _PROCESS_STARTED_AT]
    )
    return SpendState(
        session_spent_usd=session,
        daily_spent_usd=daily,
        session_cap_usd=_session_cap(),
        daily_cap_usd=_daily_cap(),
    )


def authorize_and_charge(amount_usd: float) -> str:
    """Atomically check caps and reserve the budget by appending a `pending`
    entry. Returns a `charge_id` the caller MUST pass to either
    `confirm(charge_id, tx_hash)` on settle success, or `rollback(charge_id)`
    if the payment failed.

    Concurrency-safe: the read-classify-append happens inside an
    exclusive file lock. Two `authorize_and_charge` calls fired at the
    same time can't both pass against the same baseline — the second one
    sees the first's pending entry.

    Raises SpendCapExceededError if the would-be total (including pending
    in-flight reservations) breaches a configured cap.
    """
    now = time.time()
    path = _log_path()
    charge_id = uuid.uuid4().hex
    with _file_lock(path):
        entries = _trim_to_24h(_load_entries(path), now)
        daily_pending = _sum_amounts(entries)
        session_pending = _sum_amounts(
            [e for e in entries if float(e.get("ts_epoch", 0)) >= _PROCESS_STARTED_AT]
        )
        if session_pending + amount_usd > _session_cap():
            raise SpendCapExceededError(
                "session", _session_cap(), session_pending + amount_usd
            )
        if daily_pending + amount_usd > _daily_cap():
            raise SpendCapExceededError(
                "daily", _daily_cap(), daily_pending + amount_usd
            )
        entries.append(
            {
                "charge_id": charge_id,
                "ts_iso": datetime.now(UTC).isoformat(timespec="seconds"),
                "ts_epoch": now,
                "amount_usd": float(amount_usd),
                "status": "pending",
                "tx": "",
            }
        )
        _persist(path, entries)
    return charge_id


def confirm(charge_id: str, tx_hash: str | None = None) -> None:
    """Promote a pending charge to settled, attaching the on-chain tx hash.

    No-op if the charge_id isn't found — defensive, the caller may double-
    confirm in a retry path.
    """
    path = _log_path()
    with _file_lock(path):
        entries = _load_entries(path)
        for e in entries:
            if e.get("charge_id") == charge_id:
                e["status"] = "settled"
                if tx_hash:
                    e["tx"] = tx_hash
                break
        _persist(path, entries)


def rollback(charge_id: str) -> None:
    """Drop a pending charge — the on-chain settle never happened, so the
    cap slot is freed. No-op if the charge_id isn't found.
    """
    path = _log_path()
    with _file_lock(path):
        entries = _load_entries(path)
        entries = [e for e in entries if e.get("charge_id") != charge_id]
        _persist(path, entries)


# --- Back-compat shims for callers that haven't migrated yet ---
# These keep the old API working but route through the new atomic primitives.
# Internal callers (rugguard_mcp.x402_client) should use authorize_and_charge
# + confirm/rollback directly.


def authorize(amount_usd: float) -> None:
    """Deprecated read-only cap check — leaves a TOCTOU window between
    authorize() and record(). Kept for callers that haven't migrated.

    The check still counts pending entries, so it's defensive against an
    in-flight `authorize_and_charge` from another coroutine. But it does
    NOT reserve a slot, so two simultaneous `authorize()` calls against
    a near-cap budget can both pass. Use `authorize_and_charge` instead.
    """
    state = current_state()
    if state.session_spent_usd + amount_usd > state.session_cap_usd:
        raise SpendCapExceededError(
            "session", state.session_cap_usd, state.session_spent_usd + amount_usd
        )
    if state.daily_spent_usd + amount_usd > state.daily_cap_usd:
        raise SpendCapExceededError(
            "daily", state.daily_cap_usd, state.daily_spent_usd + amount_usd
        )


def record(amount_usd: float, tx_hash: str | None = None) -> None:
    """Deprecated — appends a settled entry directly without a prior reserve.

    Useful for tests and for synchronous flows where TOCTOU isn't a concern,
    but production callers should use authorize_and_charge + confirm so the
    cap is reserved atomically against concurrent callers.
    """
    now = time.time()
    path = _log_path()
    with _file_lock(path):
        entries = _trim_to_24h(_load_entries(path), now)
        entries.append(
            {
                "ts_iso": datetime.now(UTC).isoformat(timespec="seconds"),
                "ts_epoch": now,
                "amount_usd": float(amount_usd),
                "status": "settled",
                "tx": tx_hash or "",
            }
        )
        _persist(path, entries)


def reset_24h_window() -> int:
    """Drop all entries (mostly for tests / manual reset). Returns the count."""
    path = _log_path()
    with _file_lock(path):
        entries = _load_entries(path)
        _persist(path, [])
    return len(entries)


def summary_for_human() -> str:
    """Pretty one-line spend status — used by `python -m rugguard_mcp status`."""
    s = current_state()
    return (
        f"Session: ${s.session_spent_usd:.4f} / ${s.session_cap_usd:.2f} cap   "
        f"24 h: ${s.daily_spent_usd:.4f} / ${s.daily_cap_usd:.2f} cap   "
        f"(started {datetime.fromtimestamp(_PROCESS_STARTED_AT, UTC).isoformat(timespec='seconds')})"
    )
