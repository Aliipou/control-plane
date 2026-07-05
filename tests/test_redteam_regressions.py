"""Regression tests adapted from poc9 (control-plane shares HB-1 replay and the
W-1 nonce-unbinding weakness). Requires the kernel package (integration test)."""

from __future__ import annotations

import pytest
from kernelfix import make_action, make_kernel

from control_plane import ExecutionRefused, Executor, Router

# The kernel packages ship the durable spent-store fix; skip cleanly if the env
# has no kernel installed (mirrors the other kernel-dependent tests).
kernel = pytest.importorskip("kernel")
FileSpentStore = kernel.FileSpentStore
InMemorySpentStore = kernel.InMemorySpentStore


# --- HB-1: cross-instance token double-spend (poc9 A) -----------------------
def test_hb1_cross_instance_replay_rejected(tmp_path):
    store = FileSpentStore(tmp_path / "spent")
    k = make_kernel()
    r = Router(k)
    action = make_action()
    res = r.route(action)

    ex1 = Executor(k.public_key_hex(), spent_store=store)
    ex2 = Executor(k.public_key_hex(), spent_store=store)  # second replica/process
    assert ex1.execute(action, res, {"send_email": lambda p: "sent"}) == "sent"
    with pytest.raises(ExecutionRefused, match="spent"):
        ex2.execute(action, res, {"send_email": lambda p: "sent"})


def test_hb1_inmemory_optin_still_works(tmp_path):
    k = make_kernel()
    r = Router(k)
    action = make_action()
    res = r.route(action)
    ex = Executor(k.public_key_hex(), spent_store=InMemorySpentStore())
    assert ex.execute(action, res, {"send_email": lambda p: "sent"}) == "sent"


# --- W-1: nonce/action_ref bound (poc9 B) -----------------------------------
def test_w1_different_action_rejected(tmp_path):
    """A decision minted for one action cannot execute a DIFFERENT action object
    with the same security content but a different nonce/action_ref."""
    k = make_kernel()
    r = Router(k)
    authorized = make_action(nonce="n1")
    attacker = make_action(nonce="DIFFERENT", action_ref="REQ-X")
    res = r.route(authorized)
    ex = Executor(k.public_key_hex(), spent_store=InMemorySpentStore())
    with pytest.raises(ExecutionRefused, match="binding mismatch|action_ref|nonce"):
        ex.execute(attacker, res, {"send_email": lambda p: "sent"})
