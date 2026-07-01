from __future__ import annotations

import pytest
from kernel import KernelAuthority
from kernelfix import make_action, make_kernel

from control_plane import AuthorityError, Router


def test_route_returns_verified_decision_and_audits() -> None:
    k = make_kernel()
    audited: list[dict] = []
    r = Router(k, audit=lambda action, decision: audited.append(decision))
    res = r.route(make_action())
    assert res["decision"]["verdict"] == "ALLOW"
    assert res["token"] is not None
    assert len(audited) == 1  # write-only audit sink was called


def test_route_refuses_when_signature_does_not_verify() -> None:
    # The router receives a decision signed by k, but verifies against a DIFFERENT
    # public key -> it must refuse to forward an unauthenticated decision.
    k = make_kernel()
    wrong_pub = KernelAuthority.generate().public_key_hex()
    r = Router(k, kernel_public_key=wrong_pub)
    with pytest.raises(AuthorityError, match="signature invalid"):
        r.route(make_action())


def test_route_refuses_bad_identity() -> None:
    r = Router(make_kernel(), identity_ok=lambda action: False)
    with pytest.raises(AuthorityError, match="identity"):
        r.route(make_action())
