from __future__ import annotations

import pytest

from control_plane import IncompatibleContracts, check_contracts


def test_accepts_current_contracts() -> None:
    version = check_contracts(min_major=0, min_minor=2)
    assert version  # returns the installed contracts version


def test_rejects_too_old_contracts() -> None:
    # Demand a version newer than what's installed -> fail fast.
    with pytest.raises(IncompatibleContracts):
        check_contracts(min_major=99, min_minor=0)
