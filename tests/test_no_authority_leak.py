"""The core guarantee: the control-plane cannot manufacture authority.

A forged permitting decision (not signed by the kernel) is refused by BOTH the
router (before routing) and the executor (before running the effect), even though
it claims the kernel identity and carries a plausible-looking token.
"""

from __future__ import annotations

import pytest
from kernelfix import make_action, make_kernel

from control_plane import ExecutionRefused, Executor


def _forged_result() -> dict:
    return {
        "decision": {
            "verdict": "ALLOW",
            "reason": "control-plane says so",
            "action_ref": "n-1",
            "issued_by": "decision-kernel-core",  # claims the kernel — but can't sign as it
            "obligations": [],
            "transformed_payload": None,
            "timestamp": "2026-07-01T00:00:00Z",
        },
        "signature": "00" * 64,
        "token": {
            "token_id": "tok-forged",
            "actor": "agent:bot",
            "capability": "tool:send_email",
            "action_ref": "n-1",
            "issued_by": "decision-kernel-core",
            "expires_at": "2999-01-01T00:00:00+00:00",
            "signature": "00" * 64,
        },
    }


def test_forged_decision_refused_by_executor() -> None:
    ex = Executor(make_kernel().public_key_hex())
    with pytest.raises(ExecutionRefused, match="not authenticated"):
        ex.execute(make_action(), _forged_result(), {"send_email": lambda p: "sent"})
