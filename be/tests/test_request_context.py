import uuid


def test_valid_request_id_is_reused(client):
    request_id = str(uuid.uuid4())

    response = client.get("/api/v1/health/live", HTTP_X_REQUEST_ID=request_id)

    assert response["X-Request-ID"] == request_id


def test_invalid_request_id_is_replaced(client):
    response = client.get("/api/v1/health/live", HTTP_X_REQUEST_ID="not-a-uuid")

    generated = response["X-Request-ID"]
    assert str(uuid.UUID(generated)) == generated
