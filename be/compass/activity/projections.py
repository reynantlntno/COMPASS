"""Synchronous, self-only activity projections over ``audit.AuditEvent``."""

from __future__ import annotations

from dataclasses import dataclass

from django.db.models import CharField, Q, Subquery
from django.db.models.functions import Cast

from compass.audit.models import AuditActorType, AuditEvent
from compass.authentication.models import AuthSession, RecoveryCode, TOTPFactor, TrustedSession

from .presenters import (
    ACCOUNT_TARGET,
    MY_ACTIVITY_PRESENTERS,
    SECURITY_ACTIVITY_PRESENTERS,
    ActivityItem,
    ActivityPresenter,
)

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 50
MAX_PAGE_NUMBER = 100_000


class ActivityPaginationError(ValueError):
    """Raised when a user-facing activity page is outside the supported bounds."""


@dataclass(frozen=True, slots=True)
class ActivityPage:
    """A bounded page with deterministic newest-first ordering."""

    items: tuple[ActivityItem, ...]
    page: int
    page_size: int
    has_next: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "items": [item.as_dict() for item in self.items],
            "page": self.page,
            "page_size": self.page_size,
            "has_next": self.has_next,
        }


def _validate_pagination(*, page: int, page_size: int) -> tuple[int, int]:
    if type(page) is not int or page < 1 or page > MAX_PAGE_NUMBER:
        raise ActivityPaginationError(f"page must be an integer between 1 and {MAX_PAGE_NUMBER}")
    if type(page_size) is not int or page_size < 1 or page_size > MAX_PAGE_SIZE:
        raise ActivityPaginationError(f"page_size must be an integer between 1 and {MAX_PAGE_SIZE}")
    return page, page_size


def _owned_target_ids(model, *, user_id):
    """Return a safe string-ID subquery without casting untrusted audit values."""

    return Subquery(
        model.objects.filter(user_id=user_id)
        .order_by()
        .annotate(_activity_target_id=Cast("pk", output_field=CharField(max_length=36)))
        .values("_activity_target_id")
    )


def _target_filter(presenter: ActivityPresenter, *, user_id) -> Q:
    if presenter.target_type == ACCOUNT_TARGET:
        return Q(target_type=ACCOUNT_TARGET, target_id=str(user_id))

    target_models = {
        "auth.session": AuthSession,
        "auth.trusted": TrustedSession,
        "auth.totpfactor": TOTPFactor,
        "auth.recoverycode": RecoveryCode,
    }
    target_model = target_models.get(presenter.target_type)
    if target_model is None:
        # A malformed or incompletely registered presenter must fail closed.
        return Q(pk__in=[])
    return Q(
        target_type=presenter.target_type,
        target_id__in=_owned_target_ids(target_model, user_id=user_id),
    )


def _selection_filter(*, user, presenters: dict[str, ActivityPresenter]) -> Q:
    selection: Q | None = None
    for action, presenter in presenters.items():
        if presenter.actor_scope == "self_actor":
            actor_filter = Q(
                actor_type=AuditActorType.USER,
                actor_user_id=user.pk,
            )
        elif presenter.actor_scope == "system_target":
            actor_filter = Q(
                actor_type=AuditActorType.SYSTEM,
                actor_user__isnull=True,
            )
        elif presenter.actor_scope == "target_user":
            actor_filter = Q(actor_type__in=[AuditActorType.USER, AuditActorType.SYSTEM])
        else:
            # Keep future actor/target policies explicit and fail closed if misconfigured.
            continue

        branch = (
            Q(action=action, outcome__in=presenter.visible_outcomes)
            & actor_filter
            & _target_filter(presenter, user_id=user.pk)
        )
        selection = branch if selection is None else selection | branch

    return selection if selection is not None else Q(pk__in=[])


def _get_activity(
    *,
    user,
    presenters: dict[str, ActivityPresenter],
    page: int,
    page_size: int,
) -> ActivityPage:
    if not getattr(user, "pk", None):
        raise ValueError("a saved user is required")
    page, page_size = _validate_pagination(page=page, page_size=page_size)

    offset = (page - 1) * page_size
    records = list(
        AuditEvent.objects.filter(_selection_filter(user=user, presenters=presenters)).order_by(
            "-occurred_at", "-id"
        )[offset : offset + page_size + 1]
    )
    has_next = len(records) > page_size
    records = records[:page_size]

    items: list[ActivityItem] = []
    for record in records:
        presenter = presenters.get(record.action)
        if presenter is not None:
            items.append(presenter.present(record))

    return ActivityPage(
        items=tuple(items),
        page=page,
        page_size=page_size,
        has_next=has_next,
    )


def get_my_activity(user, *, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE) -> ActivityPage:
    """Return the current user's curated broader activity feed."""

    return _get_activity(
        user=user,
        presenters=MY_ACTIVITY_PRESENTERS,
        page=page,
        page_size=page_size,
    )


def get_security_activity(
    user, *, page: int = 1, page_size: int = DEFAULT_PAGE_SIZE
) -> ActivityPage:
    """Return the current user's curated account-security activity feed."""

    return _get_activity(
        user=user,
        presenters=SECURITY_ACTIVITY_PRESENTERS,
        page=page,
        page_size=page_size,
    )


__all__ = [
    "ActivityPage",
    "ActivityPaginationError",
    "DEFAULT_PAGE_SIZE",
    "MAX_PAGE_NUMBER",
    "MAX_PAGE_SIZE",
    "get_my_activity",
    "get_security_activity",
]
