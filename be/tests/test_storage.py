from io import BytesIO
from unittest.mock import MagicMock

from compass.integrations.storage import ObjectStorage


def test_object_storage_delegates_to_configured_backend():
    backend = MagicMock()
    backend.save.return_value = "media/example.txt"
    storage = ObjectStorage(backend)

    assert storage.save("example.txt", BytesIO(b"hello")) == "media/example.txt"
    storage.exists("example.txt")
    storage.open("example.txt")
    storage.url("example.txt")
    storage.delete("example.txt")

    backend.save.assert_called_once()
    backend.exists.assert_called_once_with("example.txt")
    backend.open.assert_called_once_with("example.txt", "rb")
    backend.url.assert_called_once_with("example.txt")
    backend.delete.assert_called_once_with("example.txt")
