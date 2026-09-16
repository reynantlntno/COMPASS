from unittest.mock import MagicMock, patch

from django.db import OperationalError


def test_live_endpoint_is_process_only(client):
    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "checks": {"application": "ok"}}
    assert response["X-Request-ID"]


def test_ready_endpoint_checks_postgres(client):
    cursor = MagicMock()
    with patch("compass.api.v1.health.connection.cursor", return_value=cursor) as cursor_factory:
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["checks"]["database"] == "ok"
    cursor_factory.assert_called_once_with()
    cursor.__enter__.return_value.execute.assert_called_once_with("SELECT 1")


def test_ready_endpoint_returns_503_when_postgres_is_unavailable(client):
    cursor = MagicMock()
    cursor.__enter__.side_effect = OperationalError("database unavailable")
    with patch("compass.api.v1.health.connection.cursor", return_value=cursor):
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "checks": {"application": "ok", "database": "failed"},
    }


def test_unknown_api_route_uses_safe_error_envelope(client):
    response = client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    payload = response.json()["error"]
    assert payload["code"] == "not_found"
    assert payload["message"] == "The requested resource was not found."
    assert payload["request_id"] == response["X-Request-ID"]
