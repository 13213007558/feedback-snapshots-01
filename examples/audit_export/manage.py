#!/usr/bin/env python
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "auditcase.settings")

from django.core.management import execute_from_command_line  # noqa: E402

if __name__ == "__main__":
    execute_from_command_line(sys.argv)
