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

from kernel import SpentStore, TokenStore, action_fingerprint, verify_authority


class ExecutionRefused(RuntimeError):
    pass


class Executor:
    def __init__(
        self,
        kernel_public_key: str,
        *,
        spent_store: SpentStore | None = None,
    ) -> None:
        self._pub = kernel_public_key
        # HB-1: the TokenStore is durable and cross-process by default (see
        # kernel.TokenStore). Pass ``spent_store=`` to share one across executors
        # (multi-replica) or to opt in to InMemorySpentStore for single-process.
        self._tokens = TokenStore(spent_store=spent_store)

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

        # Mandatory mediation: the signed decision authorizes a SPECIFIC action's
        # content. Recompute the fingerprint from the action we were handed and
        # refuse if it differs from what the kernel signed — otherwise a caller
        # could re-attach a valid decision/token to a different (denied) action.
        binding = action_fingerprint(action)
        if decision.get("action_binding") != binding:
            raise ExecutionRefused(
                "action does not match the authorized decision (binding mismatch)"
            )

        # W-1: the LIVE action's reference must equal the one the kernel signed.
        # action_binding now folds action_ref/nonce in, but check it explicitly at
        # the PEP so a decision minted for one action reference cannot authorize a
        # different action object with the same security content.
        live_ref = action.get("nonce") or action.get("action_ref") or ""
        if live_ref != decision.get("action_ref", ""):
            raise ExecutionRefused(
                "action nonce/action_ref does not match the authorized decision"
            )

        verdict = decision["verdict"]
        if verdict in ("DENY", "DEFER") or token is None:
            raise ExecutionRefused(f"verdict {verdict}: no execution")

        capability = token["capability"]
        ok, why = self._tokens.verify_and_spend(
            token,
            kernel_public_key_hex=self._pub,
            expected_action_ref=decision["action_ref"],
            expected_capability=capability,
            expected_action_binding=binding,
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
