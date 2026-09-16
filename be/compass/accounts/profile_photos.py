"""Safe normalization and private storage for optional account profile photos."""

from __future__ import annotations

import logging
import uuid
import warnings
from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

from django.conf import settings
from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone
from PIL import Image, ImageOps, UnidentifiedImageError

from compass.integrations.storage import ObjectStorage

from .models import User

logger = logging.getLogger("compass.accounts.profile_photos")

SUPPORTED_IMAGE_FORMATS = frozenset({"JPEG", "PNG", "WEBP"})
_READ_CHUNK_SIZE = 64 * 1024


class ProfilePhotoValidationError(ValueError):
    """Raised when an upload is not a safe, supported profile photo."""


@dataclass(frozen=True, slots=True)
class NormalizedProfilePhoto:
    content: bytes
    content_type: str = "image/webp"
    extension: str = ".webp"


def _setting(name: str, default: int) -> int:
    return int(getattr(settings, name, default))


def _read_bounded(upload: BinaryIO) -> bytes:
    maximum = _setting("PROFILE_PHOTO_MAX_UPLOAD_BYTES", 5 * 1024 * 1024)
    declared_size = getattr(upload, "size", None)
    if isinstance(declared_size, int) and declared_size > maximum:
        raise ProfilePhotoValidationError("profile photo exceeds the upload size limit")

    seek = getattr(upload, "seek", None)
    if callable(seek):
        seek(0)

    chunks_method = getattr(upload, "chunks", None)
    if callable(chunks_method):
        chunks = chunks_method(chunk_size=_READ_CHUNK_SIZE)
    else:
        read = getattr(upload, "read", None)
        if not callable(read):
            raise ProfilePhotoValidationError("profile photo upload is not readable")

        def read_chunks():
            while True:
                chunk = read(_READ_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

        chunks = read_chunks()

    data = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise ProfilePhotoValidationError("profile photo upload must contain bytes")
        if len(data) + len(chunk) > maximum:
            raise ProfilePhotoValidationError("profile photo exceeds the upload size limit")
        data.extend(chunk)
    if not data:
        raise ProfilePhotoValidationError("profile photo upload is empty")
    return bytes(data)


def _raise_invalid_image(exc: Exception) -> ProfilePhotoValidationError:
    return ProfilePhotoValidationError("profile photo is not a valid supported raster image")


def normalize_profile_photo(upload: BinaryIO) -> NormalizedProfilePhoto:
    """Validate image contents and return metadata-free, bounded WebP bytes."""

    raw = _read_bounded(upload)
    maximum_pixels = _setting("PROFILE_PHOTO_MAX_PIXELS", 25_000_000)
    maximum_dimension = _setting("PROFILE_PHOTO_MAX_DIMENSION", 1024)
    maximum_output = _setting("PROFILE_PHOTO_MAX_OUTPUT_BYTES", 2 * 1024 * 1024)
    quality = _setting("PROFILE_PHOTO_WEBP_QUALITY", 85)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(BytesIO(raw)) as opened:
                if opened.format not in SUPPORTED_IMAGE_FORMATS:
                    raise ProfilePhotoValidationError(
                        "profile photo format must be JPEG, PNG, or WebP"
                    )
                opened.verify()

            with Image.open(BytesIO(raw)) as image:
                if image.format not in SUPPORTED_IMAGE_FORMATS:
                    raise ProfilePhotoValidationError(
                        "profile photo format must be JPEG, PNG, or WebP"
                    )
                width, height = image.size
                if width < 1 or height < 1 or width * height > maximum_pixels:
                    raise ProfilePhotoValidationError("profile photo dimensions are not allowed")
                if getattr(image, "is_animated", False) or getattr(image, "n_frames", 1) > 1:
                    raise ProfilePhotoValidationError("animated profile photos are not supported")
                image.load()
                oriented = ImageOps.exif_transpose(image)
                prepared = oriented.convert(
                    "RGBA"
                    if "A" in oriented.getbands() or "transparency" in oriented.info
                    else "RGB"
                )
                try:
                    prepared.thumbnail(
                        (maximum_dimension, maximum_dimension),
                        Image.Resampling.LANCZOS,
                    )
                    # Do not carry EXIF, ICC, XMP, or other source metadata into the output.
                    prepared.info.clear()
                    output = BytesIO()
                    prepared.save(output, format="WEBP", quality=quality, method=6)
                finally:
                    prepared.close()
                    if oriented is not image:
                        oriented.close()

        content = output.getvalue()
    except ProfilePhotoValidationError:
        raise
    except (
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
        OSError,
        SyntaxError,
        UnidentifiedImageError,
        ValueError,
    ) as exc:
        raise _raise_invalid_image(exc) from exc

    if len(content) > maximum_output:
        raise ProfilePhotoValidationError("normalized profile photo exceeds the output size limit")
    return NormalizedProfilePhoto(content=content)


def _delete_safely(storage: ObjectStorage, object_key: str) -> None:
    try:
        storage.delete(object_key)
    except Exception:
        # Cleanup failure must not make a successfully committed account reference unusable.
        logger.exception("profile photo object cleanup failed")


def _storage_or_default(storage: ObjectStorage | None) -> ObjectStorage:
    return storage if storage is not None else ObjectStorage()


def set_profile_photo(
    user: User,
    upload: BinaryIO,
    *,
    storage: ObjectStorage | None = None,
) -> str:
    """Store a normalized photo, point the account at it, then clean up the old object."""

    if not getattr(user, "pk", None):
        raise ValueError("user must be saved before setting a profile photo")

    normalized = normalize_profile_photo(upload)
    storage = _storage_or_default(storage)
    old_key = user.profile_photo_object_key
    requested_key = f"profile-photos/users/{user.pk}/{uuid.uuid4().hex}.webp"
    new_key = storage.save(
        requested_key,
        ContentFile(normalized.content, name=requested_key.rsplit("/", 1)[-1]),
    )
    if not new_key:
        raise ProfilePhotoValidationError("object storage did not return a profile photo key")

    previous_key = user.profile_photo_object_key
    previous_updated_at = user.profile_photo_updated_at
    user.profile_photo_object_key = new_key
    user.profile_photo_updated_at = timezone.now()
    try:
        user.save(
            update_fields=[
                "profile_photo_object_key",
                "profile_photo_updated_at",
                "updated_at",
            ]
        )
    except Exception:
        user.profile_photo_object_key = previous_key
        user.profile_photo_updated_at = previous_updated_at
        _delete_safely(storage, new_key)
        raise

    if old_key and old_key != new_key:
        transaction.on_commit(lambda: _delete_safely(storage, old_key))
    return new_key


def remove_profile_photo(user: User, *, storage: ObjectStorage | None = None) -> bool:
    """Clear the account reference first and clean up the private object after commit."""

    old_key = user.profile_photo_object_key
    if not old_key:
        return False

    storage = _storage_or_default(storage)
    previous_updated_at = user.profile_photo_updated_at
    user.profile_photo_object_key = None
    user.profile_photo_updated_at = timezone.now()
    try:
        user.save(
            update_fields=[
                "profile_photo_object_key",
                "profile_photo_updated_at",
                "updated_at",
            ]
        )
    except Exception:
        user.profile_photo_object_key = old_key
        user.profile_photo_updated_at = previous_updated_at
        raise

    transaction.on_commit(lambda: _delete_safely(storage, old_key))
    return True


def profile_photo_url(user: User, *, storage: ObjectStorage | None = None) -> str | None:
    """Return a short-lived URL from the configured private storage backend when available."""

    if not user.profile_photo_object_key:
        return None
    return _storage_or_default(storage).url(user.profile_photo_object_key)
