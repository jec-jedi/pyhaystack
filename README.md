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
