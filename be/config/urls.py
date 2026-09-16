from django.urls import path

from compass.api.v1.router import api
from compass.common.errors import (
    django_bad_request,
    django_not_found,
    django_permission_denied,
    django_server_error,
)

urlpatterns = [path("api/v1/", api.urls)]

handler400 = django_bad_request
handler403 = django_permission_denied
handler404 = django_not_found
handler500 = django_server_error
