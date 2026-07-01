"""Shared helpers for the integration tests (not collected; imported explicitly).

Kept out of conftest.py on purpose: conftest is auto-loaded, and importing the
kernel there would break the deps-free static CI job (which runs only the
stdlib-only boundary tests).
"""

from __future__ import annotations

from typing import Any

from kernel import Kernel, KernelAuthority

POLICY = {
    "grants": {"agent:bot": ["tool:send_email"]},
    "purpose_bindings": {"customer_support": ["support_reply"]},
    "redactions": [{"action_purpose": "support_reply", "redact_fields": ["ssn"]}],
    "contain_threat_classes": ["malicious"],
    "default": "deny",
}


def make_kernel() -> Kernel:
    return Kernel(KernelAuthority.generate(), POLICY)


def make_action(**kw: Any) -> dict[str, Any]:
    base = {
        "actor": "agent:bot",
        "tool": "send_email",
        "action_purpose": "support_reply",
        "data_labels": ["customer_support"],
        "payload": {},
        "capability": "tool:send_email",
        "nonce": "n-1",
    }
    base.update(kw)
    return base
