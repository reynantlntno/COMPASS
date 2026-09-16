# Generated for the COMPASS Organization & Scope foundation.

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("accounts", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Campus",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code", models.CharField(max_length=32, unique=True)),
                ("name", models.CharField(max_length=160)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("code",), "default_permissions": ()},
        ),
        migrations.CreateModel(
            name="College",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("code", models.CharField(max_length=32)),
                ("name", models.CharField(max_length=160)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("campus", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="colleges", to="organization.campus")),
            ],
            options={"ordering": ("campus__code", "code"), "default_permissions": ()},
        ),
        migrations.AddConstraint(
            model_name="college",
            constraint=models.UniqueConstraint(fields=("campus", "code"), name="organization_college_code_uniq"),
        ),
        migrations.CreateModel(
            name="StudentAffiliation",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("assigned_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="assigned_student_affiliations", to=settings.AUTH_USER_MODEL)),
                ("college", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="student_affiliations", to="organization.college")),
                ("student", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, primary_key=True, related_name="organization_student_affiliation", serialize=False, to=settings.AUTH_USER_MODEL)),
            ],
            options={"default_permissions": ()},
        ),
        migrations.CreateModel(
            name="CounselorResponsibility",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("assigned_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="assigned_counselor_responsibilities", to=settings.AUTH_USER_MODEL)),
                ("college", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, primary_key=True, related_name="counselor_responsibility", serialize=False, to="organization.college")),
                ("counselor", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="organization_counselor_responsibilities", to=settings.AUTH_USER_MODEL)),
            ],
            options={"default_permissions": ()},
        ),
        migrations.CreateModel(
            name="StaffSupervision",
            fields=[
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("assigned_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="assigned_staff_supervisions", to=settings.AUTH_USER_MODEL)),
                ("staff", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, primary_key=True, related_name="organization_staff_supervision", serialize=False, to=settings.AUTH_USER_MODEL)),
                ("supervisor", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="organization_supervised_staff", to=settings.AUTH_USER_MODEL)),
            ],
            options={"default_permissions": ()},
        ),
    ]
