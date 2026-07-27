# pyhaystack-async

Modern async Python client for [Project Haystack](https://www.project-haystack.org/doc/docHaystack/Intro) servers.

## Requirements

- Python ≥ 3.10
- [astral-uv](https://docs.astral.sh/uv/) for dependency management

## Quick Start

```python
import asyncio
from pyhaystack_async.client.loader import connect

async def main():
    async with connect("skyspark", uri="https://...", username="admin", password="...", project="demo") as session:
        about = await session.about()
        print(about)

        grid = await session.read(filter_expr="site")
        print(grid)

asyncio.run(main())
```

## HTTP and TLS Configuration

HTTP options are passed through `http_args` to `connect()` and the session
constructors. Modern TLS with certificate verification is the default.

```python
async with connect(
    "ax",
    uri="https://legacy-niagara.example",
    username="admin",
    password="...",
    http_args={"legacy_tls": True},
) as session:
    about = await session.about()
```

`legacy_tls=True` explicitly enables a compatibility TLS context for older
servers. It permits TLS 1.0 and later and legacy cipher suites while retaining
certificate verification. Use `tls_verify=False` only when the server cannot
provide a trusted certificate:

```python
http_args={"legacy_tls": True, "tls_verify": False}
```

For a custom trust policy, pass a configured `ssl.SSLContext` as
`tls_verify`; it is passed to HTTPX unchanged. A CA-file path may also be
provided as `tls_verify`. Legacy TLS and disabled verification are intended
only for isolated, trusted networks. They can expose connections to
protocol- and cipher-level attacks and must not become a default setting.

## Supported Platforms

| Alias       | Class                           | Auth Method        |
|-------------|---------------------------------|--------------------|
| `ax`        | `NiagaraHaystackSession`        | Cookie-digest      |
| `n4`        | `Niagara4HaystackSession`       | SCRAM-SHA256       |
| `skyspark2` | `SkysparkHaystackSession`       | HMAC-SHA1          |
| `skyspark`  | `SkysparkScramHaystackSession`  | SCRAM bearer token |
| `widesky`   | `WideskyHaystackSession`        | OAuth2 M2M         |

## Development

```bash
cd pyhaystack_async
uv sync --all-extras
uv run pytest
uv run ruff check src/ tests/
```

## Architecture

- **No threading, no fysom, no signalslot** — pure asyncio with `async`/`await`
- **httpx** for all HTTP transport (replaces `requests`)
- **Python 3.10+** syntax: `X | Y` unions, dataclasses, match statements where useful
- All vendor auth flows ported as standalone async coroutines
- Session classes composable via mixins (BQL, Eval, CRUD, MultiHis, Password)
