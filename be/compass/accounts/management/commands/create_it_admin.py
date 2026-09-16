"""Create the first COMPASS IT administrator without using Django superusers."""

from __future__ import annotations

import getpass
import sys

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, transaction

from compass.accounts.models import Role, User
from compass.audit.actions import ACCOUNT_CREATED
from compass.audit.context import AuditContext
from compass.audit.models import AuditOutcome
from compass.audit.services import record_event


class Command(BaseCommand):
    help = "Create the initial COMPASS IT_ADMIN account."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True)
        parser.add_argument("--first-name", required=True)
        parser.add_argument("--last-name", required=True)
        parser.add_argument("--middle-name", default="")
        parser.add_argument("--suffix", default="")
        parser.add_argument(
            "--idempotent",
            action="store_true",
            help="Succeed without changes when this exact account already is an IT_ADMIN.",
        )
        parser.add_argument(
            "--password-stdin",
            action="store_true",
            help="Read one password line from standard input instead of prompting twice.",
        )

    def _password(self, *, from_stdin: bool) -> str:
        if from_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
            if not password:
                raise CommandError("password input was empty")
            return password

        password = getpass.getpass("Password: ")
        confirmation = getpass.getpass("Password (again): ")
        if password != confirmation:
            raise CommandError("passwords did not match")
        if not password:
            raise CommandError("blank passwords are not allowed")
        return password

    def handle(self, *args, **options):
        try:
            role = Role.objects.get(code="IT_ADMIN")
        except Role.DoesNotExist as exc:
            raise CommandError(
                "IT_ADMIN role is not synchronized; run sync_identity_policy first"
            ) from exc

        try:
            email = User.objects.clean_email(options["email"])
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        if not options["first_name"].strip() or not options["last_name"].strip():
            raise CommandError("first-name and last-name must not be blank")
        existing = User.objects.filter(email__iexact=email).select_related("role").first()
        if existing is not None:
            if options["idempotent"] and existing.role_id == role.pk:
                self.stdout.write("IT_ADMIN account already exists; no changes made.")
                return
            raise CommandError(
                "an account with this email already exists; refusing to change its role or password"
            )

        password = self._password(from_stdin=options["password_stdin"])
        candidate = User(
            email=email,
            first_name=options["first_name"],
            middle_name=options["middle_name"],
            last_name=options["last_name"],
            suffix=options["suffix"],
            role=role,
        )
        try:
            validate_password(password, candidate)
        except ValidationError as exc:
            raise CommandError("password rejected: " + "; ".join(exc.messages)) from exc

        with transaction.atomic():
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        email=email,
                        password=password,
                        role=role,
                        first_name=options["first_name"],
                        middle_name=options["middle_name"],
                        last_name=options["last_name"],
                        suffix=options["suffix"],
                    )
            except IntegrityError as exc:
                raise CommandError(
                    "the IT_ADMIN account could not be created because the email is already in use"
                ) from exc
            try:
                record_event(
                    context=AuditContext.system(),
                    action=ACCOUNT_CREATED,
                    outcome=AuditOutcome.SUCCESS,
                    target_type="accounts.user",
                    target_id=user.pk,
                    metadata={"role": role.code},
                )
            except IntegrityError as exc:
                raise CommandError(
                    "the IT_ADMIN account could not be created because its audit event "
                    "could not be recorded"
                ) from exc

        self.stdout.write(self.style.SUCCESS("IT_ADMIN account created successfully."))
