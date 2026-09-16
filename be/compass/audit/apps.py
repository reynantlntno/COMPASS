from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "compass.audit"
    label = "audit"
    verbose_name = "COMPASS Audit Trail"
