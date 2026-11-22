from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "audit-export-demo-only"  # noqa: S105
DEBUG = True
ALLOWED_HOSTS = []
USE_TZ = True

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "simple_history",
    "auditcase",
]

MIDDLEWARE = []

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "audit.sqlite3",
    }
}

DEFAULT_AUTO_FIELD = "django.db.models.AutoField"
