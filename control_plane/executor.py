"""The Policy Enforcement Point (PEP).

Runs an effect ONLY against a kernel-signed decision AND a valid, unspent
capability token. No token -> no execution. A caller that bypassed the kernel
cannot execute, because it cannot present a token the kernel signed.

Enforces the verdict semantics: DENY/DEFER do not run; LIMIT runs the minimized
payload; CONTAIN runs only tools inside the decision's containment allowlist
(empty by default -> the effect is refused = contained).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from kernel import TokenStore, verify_authority


class ExecutionRefused(RuntimeError):
    pass


class Executor:
    def __init__(self, kernel_public_key: str) -> None:
        self._pub = kernel_public_key
        self._tokens = TokenStore()

    def execute(
        self,
        action: dict[str, Any],
        result: dict[str, Any],
        tools: dict[str, Callable[[dict[str, Any]], Any]],
    ) -> Any:
        decision = result["decision"]
        signature = result["signature"]
        token = result.get("token")

        if not verify_authority(decision, signature, self._pub):
            raise ExecutionRefused("decision not authenticated by the kernel")

        verdict = decision["verdict"]
        if verdict in ("DENY", "DEFER") or token is None:
            raise ExecutionRefused(f"verdict {verdict}: no execution")

        capability = token["capability"]
        ok, why = self._tokens.verify_and_spend(
            token,
            kernel_public_key_hex=self._pub,
            expected_action_ref=decision["action_ref"],
            expected_capability=capability,
        )
        if not ok:
            raise ExecutionRefused(f"token rejected: {why}")

        tool_name = capability.split("tool:")[-1]

        if verdict == "CONTAIN":
            allowed = (decision.get("containment") or {}).get("allowed_tools", [])
            if tool_name not in allowed:
                raise ExecutionRefused(
                    f"contained: tool '{tool_name}' not in containment allowlist {allowed}"
                )

        fn = tools.get(tool_name)
        if fn is None:
            raise ExecutionRefused(f"no executor registered for tool '{tool_name}'")

        # LIMIT executes the kernel-minimized payload; otherwise the original.
        if verdict == "LIMIT":
            payload = decision.get("transformed_payload")
        else:
            payload = action.get("payload", {})
        return fn(payload or {})
