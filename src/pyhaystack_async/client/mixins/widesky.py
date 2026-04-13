"""WideSky CRUD, multi-history, and password mixins."""

from __future__ import annotations

from typing import Any

import hszinc


class CRUDMixin:
    """Mixin providing WideSky entity CRUD operations."""

    async def create_entity(self, entities: list[dict[str, Any]]) -> hszinc.Grid:
        """Create one or more entities.

        :param entities: List of dicts, each containing tag key/value pairs.
                         An ``id`` key is optional.
        """
        grid = hszinc.Grid()

        # Collect all columns across all entities
        columns: set[str] = set()
        for e in entities:
            columns.update(e.keys())
        for col in sorted(columns):
            grid.column[col] = {}

        for e in entities:
            row = {}
            for col in columns:
                row[col] = e.get(col)
            grid.append(row)

        return await self._post_grid("createRec", grid)  # type: ignore[attr-defined]

    async def update_entity(self, entities: list[dict[str, Any]]) -> hszinc.Grid:
        """Update one or more entities.

        :param entities: List of dicts, each must contain an ``id`` key.
        """
        grid = hszinc.Grid()
        columns: set[str] = set()
        for e in entities:
            columns.update(e.keys())
        for col in sorted(columns):
            grid.column[col] = {}
        for e in entities:
            row = {}
            for col in columns:
                row[col] = e.get(col)
            grid.append(row)

        return await self._post_grid("updateRec", grid)  # type: ignore[attr-defined]

    async def delete_entity(
        self,
        ids: list[str | hszinc.Ref] | None = None,
        filter_expr: str | None = None,
    ) -> hszinc.Grid:
        """Delete entities by ID(s) or filter expression."""
        if ids is not None:
            grid = hszinc.Grid()
            grid.column["id"] = {}
            grid.extend([{"id": self._obj_to_ref(i)} for i in ids])  # type: ignore[attr-defined]
            return await self._post_grid("deleteRec", grid)  # type: ignore[attr-defined]
        elif filter_expr is not None:
            return await self._get_grid("deleteRec", args={"filter": filter_expr})  # type: ignore[attr-defined]
        else:
            raise ValueError("Specify ids or filter_expr")


class MultiHisMixin:
    """Mixin providing multi-point history read/write for WideSky."""

    async def multi_his_read(
        self,
        points: list[str | hszinc.Ref],
        rng: Any,
    ) -> hszinc.Grid:
        """Read history for multiple points in one request."""
        grid = hszinc.Grid()
        if isinstance(rng, slice):
            str_rng = ",".join(hszinc.dump_scalar(p) for p in (rng.start, rng.stop))
        elif not isinstance(rng, str):
            str_rng = hszinc.dump_scalar(rng)
        else:
            str_rng = rng
        grid.metadata["range"] = str_rng
        grid.column["id"] = {}
        grid.extend([{"id": self._obj_to_ref(p)} for p in points])  # type: ignore[attr-defined]
        return await self._post_grid("hisRead", grid)  # type: ignore[attr-defined]

    async def multi_his_write(
        self,
        records: list[dict[str, Any]],
    ) -> hszinc.Grid:
        """Write history for multiple points."""
        if not records:
            raise ValueError("No records to write")

        grid = hszinc.Grid()
        columns: set[str] = set()
        for rec in records:
            columns.update(rec.keys())
        for col in sorted(columns):
            grid.column[col] = {}
        for rec in records:
            row = {col: rec.get(col) for col in columns}
            grid.append(row)
        return await self._post_grid("hisWrite", grid)  # type: ignore[attr-defined]


class PasswordMixin:
    """Mixin providing password change for WideSky."""

    async def update_password(
        self,
        new_password: str,
    ) -> hszinc.Grid:
        """Change the logged-in user's password."""
        grid = hszinc.Grid()
        grid.column["newPassword"] = {}
        grid.append({"newPassword": new_password})
        return await self._post_grid("password", grid)  # type: ignore[attr-defined]
