"""Niagara BQL (Browse Query Language) mixin."""

from __future__ import annotations

import io
from typing import Any

try:
    import pandas as pd
    HAVE_PANDAS = True
except ImportError:
    HAVE_PANDAS = False


class BQLMixin:
    """Mixin providing BQL query support for Niagara sessions."""

    async def get_bql(self, statement: str) -> Any:
        """Execute a BQL query and return parsed result.

        Returns a pandas DataFrame if pandas is available, otherwise raw text.
        """
        resp = await self._get(  # type: ignore[attr-defined]
            "bql",
            api=False,
            params={"bql": statement},
        )

        if HAVE_PANDAS:
            return pd.read_csv(io.StringIO(resp.text))
        return resp.text
