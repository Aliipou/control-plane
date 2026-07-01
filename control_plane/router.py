"""The dumb, deterministic orchestrator. It DECIDES NOTHING.

Pipeline (cp_01):  identity -> call the pinned kernel -> validate the kernel's
signature at runtime -> write audit -> return the verified result.

The control-plane holds no authority: it never constructs a Decision, never picks
a verdict. It routes an action to the kernel and REFUSES to forward anything it
cannot cryptographically verify came from the kernel. Any decision logic added
here would be an authority leak.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kernel import verify_authority

from .compat import check_contracts


class AuthorityError(RuntimeError):
    """Raised when a decision cannot be authenticated as the kernel's."""


class Router:
    def __init__(
        self,
        kernel: Any,
        *,
        audit: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
        identity_ok: Callable[[dict[str, Any]], bool] | None = None,
        kernel_public_key: str | None = None,
    ) -> None:
        # Assume an untrusted dependency environment: fail fast if the installed
        # contracts are a version we do not understand.
        self.contracts_version = check_contracts()
        self._kernel = kernel
        self._pub = kernel_public_key or kernel.public_key_hex()
        self._audit = audit or (lambda action, decision: None)
        self._identity_ok = identity_ok or (lambda action: bool(action.get("actor")))

    def route(self, action: dict[str, Any], threat_class: str | None = None) -> dict[str, Any]:
        """Route one action through the kernel and return its verified, signed
        result: {decision, signature, token}. Raises AuthorityError if identity
        fails or the kernel signature does not verify."""
        if not self._identity_ok(action):
            raise AuthorityError("identity check failed")

        result = self._kernel.decide(action, threat_class)  # the kernel is the sole authority
        decision, signature = result["decision"], result["signature"]

        # Runtime authority validation — trust nothing that isn't a verified,
        # kernel-signed decision. In production the kernel is a separate service;
        # this is the check that stops a compromised transport from injecting a
        # forged verdict.
        if not verify_authority(decision, signature, self._pub):
            raise AuthorityError(
                "kernel signature invalid — refusing to route an unauthenticated decision"
            )

        self._audit(action, decision)  # write-only audit sink (injected)
        return result
