from io import BytesIO
from unittest.mock import Mock

import pytest
from django.test import TestCase, override_settings
from PIL import Image

from compass.accounts.models import Role, User
from compass.accounts.profile_photos import (
    ProfilePhotoValidationError,
    normalize_profile_photo,
    profile_photo_url,
    remove_profile_photo,
    set_profile_photo,
)
from compass.integrations.storage import ObjectStorage


class MemoryBackend:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.deleted: list[str] = []
        self.fail_save = False

    def save(self, name, content):
        if self.fail_save:
            raise RuntimeError("storage unavailable")
        content.seek(0)
        self.objects[name] = content.read()
        return name

    def open(self, name, mode="rb"):
        return BytesIO(self.objects[name])

    def exists(self, name):
        return name in self.objects

    def delete(self, name):
        self.deleted.append(name)
        self.objects.pop(name, None)

    def url(self, name):
        return f"https://signed.example.test/{name}?signature=test"


def image_upload(image_format="PNG", *, size=(1600, 1200), with_exif=False):
    image = Image.new("RGB", size, color=(30, 100, 180))
    output = BytesIO()
    if with_exif:
        exif = image.getexif()
        exif[270] = "private metadata"
        exif[274] = 6
        image.save(output, format=image_format, exif=exif.tobytes())
    else:
        image.save(output, format=image_format)
    output.seek(0)
    return output


@pytest.fixture
def photo_user(db):
    role = Role.objects.create(code="PHOTO_TEST", name="Photo test")
    return User.objects.create_user(
        email="photo@example.edu",
        password="password",
        role=role,
        first_name="Photo",
        last_name="User",
    )


@pytest.mark.django_db
def test_profile_photo_is_validated_normalized_and_stored_through_object_storage(photo_user):
    backend = MemoryBackend()
    storage = ObjectStorage(backend)

    key = set_profile_photo(
        photo_user,
        image_upload("JPEG", with_exif=True),
        storage=storage,
    )

    assert key.startswith(f"profile-photos/users/{photo_user.pk}/")
    assert key.endswith(".webp")
    photo_user.refresh_from_db()
    assert photo_user.profile_photo_object_key == key
    assert photo_user.profile_photo_updated_at is not None

    with Image.open(BytesIO(backend.objects[key])) as normalized:
        assert normalized.format == "WEBP"
        assert normalized.width <= 1024
        assert normalized.height <= 1024
        assert len(normalized.getexif()) == 0

    assert profile_photo_url(photo_user, storage=storage).startswith("https://signed.example.test/")


@pytest.mark.django_db
def test_profile_photo_replacement_keeps_existing_reference_when_new_storage_fails(photo_user):
    backend = MemoryBackend()
    storage = ObjectStorage(backend)
    photo_user.profile_photo_object_key = "profile-photos/users/existing.webp"
    photo_user.save(update_fields=["profile_photo_object_key", "updated_at"])
    backend.fail_save = True

    with pytest.raises(RuntimeError, match="storage unavailable"):
        set_profile_photo(photo_user, image_upload(), storage=storage)

    photo_user.refresh_from_db()
    assert photo_user.profile_photo_object_key == "profile-photos/users/existing.webp"
    assert backend.deleted == []


@pytest.mark.django_db
def test_profile_photo_validation_rejects_svg_malformed_unsupported_and_oversized_input():
    for content in (
        b"<svg xmlns='http://www.w3.org/2000/svg'></svg>",
        b"not an image",
    ):
        with pytest.raises(ProfilePhotoValidationError):
            normalize_profile_photo(BytesIO(content))

    unsupported = BytesIO()
    Image.new("RGB", (10, 10)).save(unsupported, format="GIF")
    unsupported.seek(0)
    with pytest.raises(ProfilePhotoValidationError, match="format"):
        normalize_profile_photo(unsupported)

    with override_settings(PROFILE_PHOTO_MAX_UPLOAD_BYTES=8):
        with pytest.raises(ProfilePhotoValidationError, match="size limit"):
            normalize_profile_photo(BytesIO(b"123456789"))


@pytest.mark.django_db
def test_profile_photo_db_failure_cleans_new_object_without_deleting_old_object(photo_user):
    backend = MemoryBackend()
    storage = ObjectStorage(backend)
    photo_user.profile_photo_object_key = "profile-photos/users/existing.webp"
    photo_user.save(update_fields=["profile_photo_object_key", "updated_at"])
    original_save = photo_user.save
    photo_user.save = Mock(side_effect=RuntimeError("database unavailable"))

    with pytest.raises(RuntimeError, match="database unavailable"):
        set_profile_photo(photo_user, image_upload(), storage=storage)

    assert len(backend.deleted) == 1
    assert backend.deleted[0] != "profile-photos/users/existing.webp"
    photo_user.save = original_save
    photo_user.refresh_from_db()
    assert photo_user.profile_photo_object_key == "profile-photos/users/existing.webp"


class ProfilePhotoCommitTests(TestCase):
    def setUp(self):
        self.role = Role.objects.create(code="PHOTO_COMMIT_TEST", name="Photo commit test")
        self.user = User.objects.create_user(
            email="photo-commit@example.edu",
            password="password",
            role=self.role,
            first_name="Photo",
            last_name="Commit",
        )
        self.backend = MemoryBackend()
        self.storage = ObjectStorage(self.backend)

    def test_replacement_cleans_old_object_after_commit(self):
        self.user.profile_photo_object_key = "profile-photos/users/old.webp"
        self.user.save(update_fields=["profile_photo_object_key", "updated_at"])

        with self.captureOnCommitCallbacks(execute=True):
            new_key = set_profile_photo(self.user, image_upload(), storage=self.storage)

        assert self.backend.deleted == ["profile-photos/users/old.webp"]
        assert new_key != "profile-photos/users/old.webp"

    def test_removal_clears_reference_and_cleans_object_after_commit(self):
        self.user.profile_photo_object_key = "profile-photos/users/old.webp"
        self.user.save(update_fields=["profile_photo_object_key", "updated_at"])

        with self.captureOnCommitCallbacks(execute=True):
            assert remove_profile_photo(self.user, storage=self.storage)

        self.user.refresh_from_db()
        assert self.user.profile_photo_object_key is None
        assert self.backend.deleted == ["profile-photos/users/old.webp"]
        assert not remove_profile_photo(self.user, storage=self.storage)
