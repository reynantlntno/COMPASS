from compass.tasks import infrastructure_noop
from config.celery import app


def test_celery_is_configured_with_redis_and_diagnostic_task():
    assert app.conf.broker_url.startswith("redis://")
    result = infrastructure_noop.apply()

    assert result.get() == {"status": "ok", "request_id": None}
