"""Django Ninja API object and version-one route registration."""

from django.conf import settings
from ninja import NinjaAPI

from compass.account_management.api import router as account_management_router
from compass.activity.api import router as activity_router
from compass.api.v1.health import router as health_router
from compass.authentication.api import router as authentication_router
from compass.common.errors import register_exception_handlers

api = NinjaAPI(
    title="COMPASS API",
    version="1.0.0",
    description=(
        "Authentication, account management, activity, and infrastructure endpoints for COMPASS."
    ),
    openapi_url="/openapi.json" if settings.API_DOCS_ENABLED else None,
    docs_url="/docs" if settings.API_DOCS_ENABLED else None,
)
api.add_router("/health", health_router)
api.add_router("/auth", authentication_router)
api.add_router("/me", activity_router)
api.add_router("/accounts", account_management_router)
register_exception_handlers(api)
