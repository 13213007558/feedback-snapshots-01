from pathlib import Path

from csp.constants import NONCE, SELF

CONTENT_SECURITY_POLICY = {
    "DIRECTIVES": {
        "default-src": [SELF, NONCE],
    }
}

MIDDLEWARE = [
    "csp.middleware.CSPMiddleware",
]

ROOT_URLCONF = "csp.tests.urls"

TEMPLATE_DIR = Path(__file__).parent / "templates"

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
        "DIRS": [TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "environment": "csp.tests.environment.environment",
            "extensions": ["csp.extensions.NoncedScript"],
            "context_processors": ["django.template.context_processors.request"],
        },
    },
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": ["django.template.context_processors.request"],
        },
    },
]
