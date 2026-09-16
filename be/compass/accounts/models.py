"""Explicit COMPASS account identity and capability models."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

if TYPE_CHECKING:
    from datetime import datetime


class Role(models.Model):
    """A user's single primary operational identity in COMPASS."""

    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)

    class Meta:
        default_permissions = ()
        ordering = ("code",)

    def __str__(self) -> str:
        return self.code


class Designation(models.Model):
    """An additional institutional appointment or authority."""

    code = models.CharField(max_length=64, unique=True)
    name = models.CharField(max_length=120)
    description = models.TextField(blank=True)

    class Meta:
        default_permissions = ()
        ordering = ("code",)

    def __str__(self) -> str:
        return self.code


class Capability(models.Model):
    """A scope-free action an actor may perform."""

    code = models.CharField(max_length=128, unique=True)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)

    class Meta:
        default_permissions = ()
        ordering = ("code",)

    def __str__(self) -> str:
        return self.code


class UserManager(BaseUserManager):
    """Create users with an explicit primary role and Django password hashing."""

    @classmethod
    def normalize_email(cls, email: str | None) -> str:
        """Normalize only surrounding whitespace and case for identity matching."""

        if email is None:
            return ""
        if not isinstance(email, str):
            raise ValueError("email must be a string")
        return email.strip().lower()

    def clean_email(self, email: str | None) -> str:
        normalized = self.normalize_email(email)
        try:
            return self.model._meta.get_field("email").clean(normalized, None)
        except ValidationError as exc:
            raise ValueError("a valid email address is required") from exc

    def _resolve_role(self, role: Role | str | None) -> Role:
        if role is None:
            raise ValueError("a primary role is required")
        if isinstance(role, str):
            try:
                return Role.objects.using(self._db).get(code=role)
            except Role.DoesNotExist as exc:
                raise ValueError(f"unknown primary role: {role}") from exc
        if not isinstance(role, Role) or role.pk is None:
            raise ValueError("role must be a saved Role or a known role code")
        return role

    def get_by_natural_key(self, username: str) -> User:
        return self.get(email__iexact=self.normalize_email(username))

    async def aget_by_natural_key(self, username: str) -> User:
        return await self.aget(email__iexact=self.normalize_email(username))

    def create_user(
        self,
        email: str,
        password: str | None = None,
        *,
        role: Role | str | None = None,
        first_name: str = "",
        middle_name: str = "",
        last_name: str = "",
        suffix: str = "",
        is_active: bool = True,
    ) -> User:
        if not first_name.strip() or not last_name.strip():
            raise ValueError("first_name and last_name are required")
        if password == "":
            raise ValueError("password must not be blank")
        user = self.model(
            email=self.clean_email(email),
            role=self._resolve_role(role),
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            suffix=suffix,
            is_active=is_active,
        )
        if password is None:
            user.set_unusable_password()
        else:
            user.set_password(password)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """The minimal account identity used by all future COMPASS domains."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(max_length=254, unique=True)
    first_name = models.CharField(max_length=150)
    middle_name = models.CharField(max_length=150, blank=True, default="")
    last_name = models.CharField(max_length=150)
    suffix = models.CharField(max_length=32, blank=True, default="")
    role = models.ForeignKey(
        Role,
        on_delete=models.PROTECT,
        related_name="users",
    )
    is_active = models.BooleanField(default=True)
    profile_photo_object_key = models.CharField(
        max_length=512,
        blank=True,
        null=True,
    )
    profile_photo_updated_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    designations = models.ManyToManyField(
        Designation,
        through="UserDesignation",
        related_name="users",
        blank=True,
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    EMAIL_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                Lower("email"),
                name="accounts_user_email_ci_uniq",
            ),
        ]
        ordering = ("-created_at",)

    def clean(self) -> None:
        super().clean()
        if self.email is not None:
            self.email = self.__class__.objects.normalize_email(self.email)

    def save(self, *args, **kwargs):
        if self.email is not None:
            self.email = self.__class__.objects.normalize_email(self.email)
        return super().save(*args, **kwargs)

    def get_full_name(self) -> str:
        parts = [self.first_name, self.middle_name, self.last_name, self.suffix]
        return " ".join(part.strip() for part in parts if part and part.strip())

    def get_short_name(self) -> str:
        return self.first_name

    def has_capability(self, capability_code: str, *, at: datetime | None = None) -> bool:
        from compass.accounts.services import user_has_capability

        return user_has_capability(self, capability_code, at=at)

    def __str__(self) -> str:
        return self.email


class RoleCapability(models.Model):
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="capability_grants")
    capability = models.ForeignKey(
        Capability,
        on_delete=models.PROTECT,
        related_name="role_grants",
    )

    class Meta:
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                fields=("role", "capability"),
                name="accounts_role_capability_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.role.code} -> {self.capability.code}"


class DesignationCapability(models.Model):
    designation = models.ForeignKey(
        Designation,
        on_delete=models.PROTECT,
        related_name="capability_grants",
    )
    capability = models.ForeignKey(
        Capability,
        on_delete=models.PROTECT,
        related_name="designation_grants",
    )

    class Meta:
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                fields=("designation", "capability"),
                name="accounts_designation_capability_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.designation.code} -> {self.capability.code}"


class UserDesignation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="designation_assignments")
    designation = models.ForeignKey(
        Designation,
        on_delete=models.PROTECT,
        related_name="user_assignments",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                fields=("user", "designation"),
                name="accounts_user_designation_uniq",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user.email} -> {self.designation.code}"


class UserCapabilityOverride(models.Model):
    class Effect(models.TextChoices):
        GRANT = "GRANT", "Grant"
        REVOKE = "REVOKE", "Revoke"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="capability_overrides")
    capability = models.ForeignKey(
        Capability,
        on_delete=models.PROTECT,
        related_name="user_overrides",
    )
    effect = models.CharField(max_length=6, choices=Effect.choices)
    reason = models.CharField(max_length=500)
    expires_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="created_capability_overrides",
    )

    class Meta:
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                fields=("user", "capability"),
                name="accounts_user_capability_override_uniq",
            ),
            models.CheckConstraint(
                condition=models.Q(effect__in=["GRANT", "REVOKE"]),
                name="accounts_override_effect_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.user.email} {self.effect} {self.capability.code}"
