"""Dependency-trust: verify the contract version at startup.

The control-plane assumes an UNTRUSTED dependency environment. Before it routes
anything it confirms the installed contracts package is a version it understands
— an incompatible contract is a fail-fast condition, not a silent mismatch.
"""

from __future__ import annotations

import decision_os_contracts


class IncompatibleContracts(RuntimeError):
    pass


def check_contracts(min_major: int = 0, min_minor: int = 2) -> str:
    """Return the installed contracts version, or raise if it is too old."""
    version = decision_os_contracts.__version__
    major, minor, *_ = (int(x) for x in version.split("."))
    if (major, minor) < (min_major, min_minor):
        raise IncompatibleContracts(
            f"control-plane needs decision-os-contracts >= {min_major}.{min_minor}, "
            f"found {version}"
        )
    return version
