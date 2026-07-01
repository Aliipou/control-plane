# control-plane — the dumb, security-first orchestrator

Routes actions through the Decision OS. It **decides nothing** — it holds no
authority. Any decision logic here would be an authority leak.

## Pipeline (cp_01)

```
Request
  → identity check
  → call the pinned kernel (the sole authority)
  → validate the kernel's signature at RUNTIME   ← refuses anything it can't verify
  → write to the audit ledger (injected sink)
  → return the verified {decision, signature, token}
        → Executor (PEP): verify signature + spend the one-time token → run the effect
```

- **Assumes an untrusted dependency environment** — checks the installed
  `decision-os-contracts` version at startup (`compat.py`) and verifies every
  decision's kernel signature at runtime (`router.py`). It trusts nothing it
  cannot cryptographically verify.
- **Mandatory mediation** — the `Executor` runs an effect only against a valid,
  unspent, kernel-signed capability token. `DENY`/`DEFER` don't run; `LIMIT` runs
  the minimized payload; `CONTAIN` runs only tools in the containment allowlist
  (empty by default → the effect is refused = contained).
- **No authority leak** — a forged permitting decision (not kernel-signed) is
  refused by both the router and the executor, even if it claims the kernel
  identity (`tests/test_no_authority_leak.py`).

## Dependencies & CI

Consumes the pinned core packages (`decision-os-contracts@v0.2.0`,
`decision-kernel-core@v0.1.0`) — the standard Python-package consumption pattern
(see contracts-spec `INTEGRATION.md`). These are **private** repos, so full
integration CI needs a read credential (`DEPLOY_TOKEN` secret). Until it's set,
the `static` CI job (lint + dependency-free rule A/B boundary checks) keeps the
repo green; the `integration` job activates automatically once the secret exists.

## Shape

```
control_plane/
  router.py    # dumb orchestrator: identity -> kernel -> verify signature -> audit
  executor.py  # PEP: verify signature + spend token -> run effect (verdict-aware)
  compat.py    # fail-fast contract-version check (untrusted-dependency posture)
tests/         # router, executor, no-authority-leak, compat, rule A/B boundaries
```
