import os
from pathlib import Path

from advanced_app.security import security_config

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-in-production")
DEBUG = os.environ.get("DEBUG", "True").lower() == "true"
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
]

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.common.CommonMiddleware",
]

ROOT_URLCONF = "advanced_project.urls"
WSGI_APPLICATION = "advanced_project.wsgi.application"

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_TZ = True

GUARD_SECURITY_CONFIG = security_config
