from pathlib import Path

from csp.constants import NONCE, SELF

TEST_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
TEST_JINJA2_DIR = Path(__file__).resolve().parent / "jinja2"

CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF, NONCE],
    }
}

DATABASES = {
    "default": {
        "NAME": "test.db",
        "ENGINE": "django.db.backends.sqlite3",
    }
}

INSTALLED_APPS = (
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "csp",
)

SECRET_KEY = "csp-test-key"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.jinja2.Jinja2",
        "DIRS": [TEST_JINJA2_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "environment": "csp.tests.environment.environment",
            "extensions": ["csp.extensions.NoncedScript"],
        },
    },
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEST_TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {},
    },
]
