"""Fin session support."""

from __future__ import annotations

from typing import Any

import hszinc

from .skyspark import SkysparkScramHaystackSession


class FinSession(SkysparkScramHaystackSession):
    """Async session for Fin's SkySpark-compatible Haystack API."""

    async def point_write(
        self,
        point: str | hszinc.Ref,
        *,
        level: int | None = None,
        val: Any = None,
        who: str | None = None,
        duration: Any = None,
    ) -> hszinc.Grid:
        """Write a point using Fin's Zinc POST pointWrite endpoint."""
        grid = hszinc.Grid()
        grid.column["id"] = {}
        row: dict[str, Any] = {"id": self._obj_to_ref(point)}

        if level is not None:
            grid.column["level"] = {}
            grid.column["val"] = {}
            grid.column["who"] = {}
            row.update({"level": level, "val": val, "who": who or self._username})
            if duration is not None:
                grid.column["duration"] = {}
                row["duration"] = duration

        grid.append(row)
        return await self._post_grid(
            "pointWrite",
            grid,
            post_format=hszinc.MODE_ZINC,
        )
