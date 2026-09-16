"""Cloudflare Turnstile server-side verification adapter."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings

logger = logging.getLogger("compass.turnstile")


@dataclass(frozen=True, slots=True)
class TurnstileResult:
    success: bool
    error_codes: tuple[str, ...] = ()
    hostname: str | None = None
    action: str | None = None
    challenge_timestamp: str | None = None
    transport_error: bool = False


class TurnstileConfigurationError(ValueError):
    """Raised when Turnstile is enabled without a usable server secret."""


class TurnstileVerifier:
    def __init__(
        self,
        secret_key: str,
        *,
        timeout_seconds: float = 5.0,
        endpoint: str = "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        expected_hostnames: tuple[str, ...] = (),
        expected_action: str | None = None,
    ) -> None:
        if not secret_key:
            raise TurnstileConfigurationError("Turnstile secret key is required")
        if timeout_seconds <= 0:
            raise ValueError("Turnstile timeout must be positive")
        self.secret_key = secret_key
        self.timeout_seconds = timeout_seconds
        self.endpoint = endpoint
        self.expected_hostnames = tuple(expected_hostnames)
        self.expected_action = expected_action or None

    @classmethod
    def from_settings(cls) -> TurnstileVerifier:
        if not settings.TURNSTILE_ENABLED:
            raise TurnstileConfigurationError("Turnstile is disabled")
        return cls(
            settings.TURNSTILE_SECRET_KEY,
            timeout_seconds=settings.TURNSTILE_TIMEOUT_SECONDS,
            endpoint=settings.TURNSTILE_VERIFY_URL,
            expected_hostnames=tuple(settings.TURNSTILE_EXPECTED_HOSTNAMES),
            expected_action=settings.TURNSTILE_EXPECTED_ACTION or None,
        )

    def verify(
        self,
        token: str,
        *,
        remote_ip: str | None = None,
        expected_hostname: str | None = None,
        expected_action: str | None = None,
    ) -> TurnstileResult:
        if not isinstance(token, str) or not token or len(token) > 2048:
            return TurnstileResult(False, error_codes=("invalid-input-response",))

        form = {"secret": self.secret_key, "response": token}
        if remote_ip:
            form["remoteip"] = remote_ip
        request = Request(
            self.endpoint,
            data=urlencode(form).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read())
        except (HTTPError, URLError, TimeoutError, OSError, ValueError):
            logger.warning(
                "Turnstile verification transport failure",
                extra={"event": "turnstile_transport_failure"},
            )
            return TurnstileResult(False, error_codes=("internal-error",), transport_error=True)

        if not isinstance(payload, dict):
            return TurnstileResult(False, error_codes=("invalid-response",))

        raw_errors = payload.get("error-codes", [])
        errors = tuple(str(error) for error in raw_errors if isinstance(error, str))
        hostname = payload.get("hostname") if isinstance(payload.get("hostname"), str) else None
        action = payload.get("action") if isinstance(payload.get("action"), str) else None
        challenge_timestamp = (
            payload.get("challenge_ts") if isinstance(payload.get("challenge_ts"), str) else None
        )
        if not payload.get("success"):
            return TurnstileResult(False, errors, hostname, action, challenge_timestamp)

        allowed_hostnames = self.expected_hostnames
        selected_hostname = expected_hostname or None
        if selected_hostname:
            allowed_hostnames = (selected_hostname,)
        if allowed_hostnames and hostname not in allowed_hostnames:
            return TurnstileResult(
                False,
                errors + ("hostname-mismatch",),
                hostname,
                action,
                challenge_timestamp,
            )

        selected_action = expected_action or self.expected_action
        if selected_action and action != selected_action:
            return TurnstileResult(
                False,
                errors + ("action-mismatch",),
                hostname,
                action,
                challenge_timestamp,
            )
        return TurnstileResult(True, errors, hostname, action, challenge_timestamp)
