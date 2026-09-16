from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "compass.authentication"
    label = "authentication"
    verbose_name = "COMPASS authentication"
