"""Small application-facing object-storage boundary."""

from __future__ import annotations

from django.core.files.storage import Storage, storages


class ObjectStorage:
    """Delegate object operations to Django's configured S3-compatible storage."""

    def __init__(self, backend: Storage | None = None) -> None:
        self.backend = backend if backend is not None else storages["default"]

    def save(self, name: str, content) -> str:
        return self.backend.save(name, content)

    def open(self, name: str, mode: str = "rb"):
        return self.backend.open(name, mode)

    def exists(self, name: str) -> bool:
        return self.backend.exists(name)

    def delete(self, name: str) -> None:
        self.backend.delete(name)

    def url(self, name: str) -> str:
        return self.backend.url(name)
