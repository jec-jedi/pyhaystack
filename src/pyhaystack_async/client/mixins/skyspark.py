"""SkySpark Axon eval expression mixin."""

from __future__ import annotations

import hszinc


class EvalMixin:
    """Mixin providing SkySpark Axon expression evaluation."""

    async def get_eval(self, expr: str) -> hszinc.Grid:
        """Evaluate an Axon expression on the SkySpark server.

        :param expr: Axon expression string.
        """
        return await self._get_grid("eval", args={"expr": expr})  # type: ignore[attr-defined]
