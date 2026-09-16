"""Export and validate the committed COMPASS OpenAPI contract."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from compass.api.contract import validate_openapi_contract
from compass.api.v1.router import api


def _default_output() -> Path:
    return Path(settings.BASE_DIR).parent / "contracts" / "openapi.json"


def _generated_schema() -> dict[str, Any]:
    schema = dict(api.get_openapi_schema())
    validate_openapi_contract(schema)
    return schema


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


class Command(BaseCommand):
    help = "Export or check the deterministic COMPASS OpenAPI contract."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output",
            type=Path,
            default=None,
            help="Output path (defaults to ../contracts/openapi.json from be/).",
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="Fail when the existing artifact differs from the generated schema.",
        )

    def handle(self, *args, **options) -> None:
        output = Path(options["output"]) if options["output"] else _default_output()
        generated = _generated_schema()
        canonical = _canonical_json(generated)
        normalized_generated = json.loads(canonical)

        if options["check"]:
            if not output.is_file():
                raise CommandError(f"OpenAPI contract is missing: {output}")
            try:
                committed = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise CommandError(f"Could not read OpenAPI contract {output}: {exc}") from exc
            if committed != normalized_generated:
                raise CommandError(
                    f"OpenAPI contract is stale: {output}. "
                    "Run export_openapi without --check to update it."
                )
            self.stdout.write(self.style.SUCCESS(f"OpenAPI contract is current: {output}"))
            return

        try:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(canonical, encoding="utf-8")
        except OSError as exc:
            raise CommandError(f"Could not write OpenAPI contract {output}: {exc}") from exc
        self.stdout.write(self.style.SUCCESS(f"Exported OpenAPI contract: {output}"))
