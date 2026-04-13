"""High-level Entity model for Project Haystack."""

from __future__ import annotations

from typing import Any

from hszinc import Ref


class Entity:
    """Represents a Project Haystack entity with its tags."""

    def __init__(self, session: Any, entity_id: str, tags: dict[str, Any] | None = None):
        self._session = session
        self._entity_id = entity_id
        self._tags: dict[str, Any] = dict(tags or {})

    @property
    def id(self) -> Ref:
        return Ref(self._entity_id)

    @property
    def dis(self) -> str:
        return self._tags.get("dis", "")

    @property
    def tags(self) -> dict[str, Any]:
        return self._tags

    def has_tag(self, name: str) -> bool:
        return name in self._tags

    def __repr__(self) -> str:
        return f"<Entity {self._entity_id}: {self._tags}>"

    def _update_tags(self, tags: dict[str, Any]) -> None:
        self._tags.update(tags)
