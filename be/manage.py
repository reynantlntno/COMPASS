#!/usr/bin/env python
import os
import sys


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:  # pragma: no cover - only reached before dependencies install
        raise ImportError(
            "Django is not installed. Run `uv sync` in the backend directory first."
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
