from __future__ import annotations

import pytest
from kernelfix import make_action, make_kernel

from control_plane import ExecutionRefused, Executor, Router


def _wire():
    k = make_kernel()
    return k, Router(k), Executor(k.public_key_hex())


def test_allow_executes_tool() -> None:
    k, r, ex = _wire()
    action = make_action()
    res = r.route(action)
    out = ex.execute(action, res, {"send_email": lambda p: "sent"})
    assert out == "sent"


def test_deny_refuses_execution() -> None:
    k, r, ex = _wire()
    action = make_action(actor="agent:evil")  # no capability -> DENY, token None
    res = r.route(action)
    with pytest.raises(ExecutionRefused):
        ex.execute(action, res, {"send_email": lambda p: "sent"})


def test_limit_executes_minimized_payload() -> None:
    k, r, ex = _wire()
    action = make_action(payload={"ssn": "123-45-6789", "body": "hi"})
    res = r.route(action)
    assert res["decision"]["verdict"] == "LIMIT"
    seen: dict = {}
    ex.execute(action, res, {"send_email": lambda p: seen.update(p)})
    assert seen["ssn"] == "[REDACTED]"  # tool never sees the raw secret


def test_spent_token_refused_on_second_execute() -> None:
    k, r, ex = _wire()
    action = make_action()
    res = r.route(action)
    ex.execute(action, res, {"send_email": lambda p: "sent"})
    with pytest.raises(ExecutionRefused, match="spent"):
        ex.execute(action, res, {"send_email": lambda p: "sent"})


def test_contain_refuses_sensitive_tool() -> None:
    k, r, ex = _wire()
    action = make_action()
    res = r.route(action, threat_class="malicious")  # CONTAIN, allowed_tools=[]
    assert res["decision"]["verdict"] == "CONTAIN"
    with pytest.raises(ExecutionRefused, match="contained"):
        ex.execute(action, res, {"send_email": lambda p: "sent"})
