import json
from unittest.mock import patch

from compass.integrations.turnstile import TurnstileVerifier


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_turnstile_verifier_accepts_success_and_checks_context():
    with patch(
        "compass.integrations.turnstile.urlopen",
        return_value=FakeResponse(
            {
                "success": True,
                "hostname": "staging.example.edu",
                "action": "signup",
                "challenge_ts": "2026-09-16T00:00:00Z",
            }
        ),
    ) as open_url:
        result = TurnstileVerifier("server-secret").verify(
            "token",
            remote_ip="203.0.113.10",
            expected_hostname="staging.example.edu",
            expected_action="signup",
        )

    assert result.success is True
    assert result.hostname == "staging.example.edu"
    request = open_url.call_args.args[0]
    assert request.get_method() == "POST"
    assert request.data


def test_turnstile_verifier_rejects_bad_context():
    with patch(
        "compass.integrations.turnstile.urlopen",
        return_value=FakeResponse(
            {"success": True, "hostname": "wrong.example", "action": "other"}
        ),
    ):
        result = TurnstileVerifier("server-secret").verify(
            "token", expected_hostname="staging.example.edu", expected_action="signup"
        )

    assert result.success is False
    assert "hostname-mismatch" in result.error_codes


def test_turnstile_verifier_handles_transport_failure_without_exposing_secret():
    with patch("compass.integrations.turnstile.urlopen", side_effect=TimeoutError):
        result = TurnstileVerifier("server-secret").verify("token")

    assert result.success is False
    assert result.transport_error is True
    assert result.error_codes == ("internal-error",)


def test_turnstile_verifier_does_not_call_provider_for_invalid_token():
    with patch("compass.integrations.turnstile.urlopen") as open_url:
        result = TurnstileVerifier("server-secret").verify("x" * 2049)

    assert result.success is False
    open_url.assert_not_called()
