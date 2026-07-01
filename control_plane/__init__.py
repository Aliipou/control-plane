"""control-plane — the dumb, security-first orchestrator of the Decision OS.

Routes actions to the kernel, verifies the kernel's signature at runtime, and
enforces token-bound execution. Holds NO authority: it never decides, never
constructs a Decision. Depends on the kernel (verification + tokens) and the
contracts package; the audit sink is injected.
"""

from .compat import IncompatibleContracts, check_contracts
from .executor import ExecutionRefused, Executor
from .router import AuthorityError, Router

__all__ = [
    "Router",
    "AuthorityError",
    "Executor",
    "ExecutionRefused",
    "check_contracts",
    "IncompatibleContracts",
]
