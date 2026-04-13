# AGENTS.md (pyhaystack_async scope)

This file applies to work inside `pyhaystack_async/` only.

## Scope

- This package is the modern async implementation.
- Treat `pyhaystack_async/` as the source of truth for new development.
- Do not modify files outside this folder unless explicitly requested.

## Hard Constraints

1. Python minimum version is 3.10.
2. Use `asyncio` + `httpx` only for transport/concurrency.
3. Never add:
   - `threading`
   - `fysom`
   - `signalslot`
4. Keep authentication semantics equivalent to legacy behavior.
5. API compatibility with legacy package is not required.

## Package Structure Contract

- `src/pyhaystack_async/client/http/`: HTTP transport and HTTP error/auth wrappers.
- `src/pyhaystack_async/client/ops/`: vendor auth protocol flows.
- `src/pyhaystack_async/client/`: sessions, loader/factory, high-level client APIs.
- `src/pyhaystack_async/client/mixins/`: vendor convenience APIs.
- `src/pyhaystack_async/util/`: shared protocol/crypto helpers.
- `tests/`: async tests using pytest + pytest-asyncio.

Do not collapse boundaries between transport/auth/session layers.

## Auth Parity Checklist (must preserve)

- NiagaraAX:
  - two-step login
  - cookie handling (`niagara_session` variants)
  - basic-auth persistence after login
- Niagara4:
  - SCRAM challenge flow
  - server signature verification
  - cookie extraction (`JSESSIONID`, user cookie)
- SkySpark legacy:
  - HMAC-SHA1 challenge flow
  - cookie parsing from login response
- SkySpark SCRAM:
  - handshake token flow
  - nonce validation
  - bearer token extraction from response headers
- WideSky:
  - OAuth2 token flow
  - token expiry semantics
  - clear auth on 401 so re-auth can occur

## Coding Rules

- Use type hints for all public functions/methods.
- Keep methods small; prefer explicit helper methods over deeply nested logic.
- Raise package-specific exceptions where meaningful.
- Avoid broad refactors unrelated to the task.
- Preserve existing naming and module conventions unless change is required.

## Testing Requirements

For any behavior change or new feature:

1. Add/update tests in `pyhaystack_async/tests/`.
2. Cover success path and at least one failure path.
3. Mock network I/O in unit tests (e.g., `respx`) unless explicitly doing integration tests.

## Required Validation Before Hand-off

Run from `pyhaystack_async/`:

```bash
uv sync --all-extras
uv run ruff check src/ tests/
uv run pytest tests/ -v
grep -rn "import threading\|import fysom\|import signalslot\|from threading\|from fysom\|from signalslot" src/
```

If any command fails, fix before hand-off.

## Change Delivery Format

When handing off work, include:

1. What changed (files + behavior).
2. Why the change was needed.
3. Auth/protocol implications (if any).
4. Exact validation commands run and pass/fail status.
5. Any known limitations or follow-up work.

## Cutover Note

Do not remove legacy package from repo during normal tasks. Legacy removal is a separate explicit migration step after parity confirmation.
