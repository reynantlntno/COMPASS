"""Celery boundary for security email delivery."""

from __future__ import annotations

import re

from celery import shared_task
from django.contrib.auth.hashers import check_password
from django.utils import timezone

from compass.integrations.mail import Mailer
from compass.tasks import CorrelationTask

_EMAIL_OTP_CODE_RE = re.compile(r"^\d{6}$", re.ASCII)


@shared_task(
    bind=True,
    base=CorrelationTask,
    name="compass.authentication.email_otp.deliver",
)
def deliver_email_otp(self, challenge_id: str, code: str) -> int:
    """Deliver a transient plaintext code; it is never logged or stored by this task."""

    if not isinstance(challenge_id, str) or not challenge_id:
        return 0
    if not isinstance(code, str) or not _EMAIL_OTP_CODE_RE.fullmatch(code):
        return 0
    from compass.authentication.models import EmailOTPChallenge

    challenge = EmailOTPChallenge.objects.filter(pk=challenge_id).first()
    if (
        challenge is None
        or challenge.consumed_at is not None
        or challenge.expires_at <= timezone.now()
        or not check_password(code, challenge.code_hash)
    ):
        return 0
    return Mailer().send(
        subject="Your COMPASS security code",
        body=(
            "Use this COMPASS security code to continue: "
            f"{code}\n\nThis code expires shortly and can be used once."
        ),
        recipients=challenge.email,
    )


__all__ = ["deliver_email_otp"]
