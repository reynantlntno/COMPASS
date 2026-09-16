from django.core import mail
from django.test import override_settings

from compass.integrations.mail import Mailer


@override_settings(
    MAILERS={"default": {"BACKEND": "django.core.mail.backends.locmem.EmailBackend"}}
)
def test_mailer_uses_django_mailer_boundary():
    count = Mailer().send("Subject", "Body", ["recipient@example.test"])

    assert count == 1
    assert len(mail.outbox) == 1
    assert mail.outbox[0].subject == "Subject"
