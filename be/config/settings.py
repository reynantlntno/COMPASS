"""Environment-driven Django settings for local-staging and live-staging."""

from pathlib import Path

from compass.common.config import env, env_bool, env_csv, env_float, env_int, required_env

BASE_DIR = Path(__file__).resolve().parent.parent

APP_ENV = env("APP_ENV", "local-staging")
if APP_ENV not in {"local-staging", "live-staging"}:
    raise ValueError("APP_ENV must be either local-staging or live-staging")

IS_LOCAL_STAGING = APP_ENV == "local-staging"
DEBUG = env_bool("DEBUG", IS_LOCAL_STAGING)
if not IS_LOCAL_STAGING and DEBUG:
    raise ValueError("DEBUG must be false in live-staging")

SECRET_KEY = required_env("SECRET_KEY")
ALLOWED_HOSTS = env_csv(
    "ALLOWED_HOSTS",
    ["localhost", "127.0.0.1", "[::1]"] if IS_LOCAL_STAGING else [],
)
if not IS_LOCAL_STAGING and not ALLOWED_HOSTS:
    raise ValueError("ALLOWED_HOSTS is required in live-staging")

CSRF_TRUSTED_ORIGINS = env_csv(
    "CSRF_TRUSTED_ORIGINS",
    ["http://localhost:8080", "http://127.0.0.1:8080"] if IS_LOCAL_STAGING else [],
)
CORS_ALLOWED_ORIGINS = env_csv("CORS_ALLOWED_ORIGINS", [])
TRUSTED_PROXY_CIDRS = env_csv(
    "TRUSTED_PROXY_CIDRS",
    [
        "127.0.0.1/32",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ],
)

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "compass.accounts",
    "compass.audit",
    "compass.authentication",
    "compass.organization",
]

AUTH_USER_MODEL = "accounts.User"

# Passwords are user-chosen credentials, including for the self-service initial setup and
# recovery flow. Django's built-in validators provide length and common-password screening
# without brittle composition rules. Fifteen characters follows current guidance for passwords
# that may be used as a single factor; MFA remains an additional account policy rather than a
# reason to weaken the shared baseline.
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 15},
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

MIDDLEWARE = [
    "compass.common.middleware.RequestContextMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ],
        },
    }
]

POSTGRES_DB = env("POSTGRES_DB", "compass")
POSTGRES_USER = env("POSTGRES_USER", "compass")
POSTGRES_PASSWORD = required_env("POSTGRES_PASSWORD")
POSTGRES_HOST = env("POSTGRES_HOST", "postgres")
POSTGRES_PORT = env_int("POSTGRES_PORT", 5432)
DB_CONN_MAX_AGE = env_int("DB_CONN_MAX_AGE", 60)
DB_CONNECT_TIMEOUT = env_int("DB_CONNECT_TIMEOUT", 5)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": POSTGRES_DB,
        "USER": POSTGRES_USER,
        "PASSWORD": POSTGRES_PASSWORD,
        "HOST": POSTGRES_HOST,
        "PORT": POSTGRES_PORT,
        "CONN_MAX_AGE": DB_CONN_MAX_AGE,
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": {"connect_timeout": DB_CONNECT_TIMEOUT},
    }
}

REDIS_URL = required_env("REDIS_URL")
REDIS_CACHE_URL = required_env("REDIS_CACHE_URL")
REDIS_RATE_LIMIT_URL = required_env("REDIS_RATE_LIMIT_URL")
REDIS_IDEMPOTENCY_URL = required_env("REDIS_IDEMPOTENCY_URL")
REDIS_SOCKET_TIMEOUT = env_float("REDIS_SOCKET_TIMEOUT", 2.0)
RATE_LIMITER_FAIL_OPEN = env_bool("RATE_LIMITER_FAIL_OPEN", False)

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_CACHE_URL,
        "KEY_PREFIX": "compass",
        "TIMEOUT": 300,
    }
}

S3_BUCKET_NAME = required_env("S3_BUCKET_NAME")
S3_ACCESS_KEY_ID = required_env("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = required_env("S3_SECRET_ACCESS_KEY")
S3_ENDPOINT_URL = env("S3_ENDPOINT_URL", "http://minio:9000" if IS_LOCAL_STAGING else None)
S3_REGION_NAME = env("S3_REGION_NAME", "us-east-1")
S3_ADDRESSING_STYLE = env("S3_ADDRESSING_STYLE", "path" if IS_LOCAL_STAGING else "virtual")
if S3_ADDRESSING_STYLE not in {"path", "virtual"}:
    raise ValueError("S3_ADDRESSING_STYLE must be path or virtual")
S3_VERIFY = env_bool("S3_VERIFY", True)
S3_COMMON_OPTIONS = {
    "bucket_name": S3_BUCKET_NAME,
    "access_key": S3_ACCESS_KEY_ID,
    "secret_key": S3_SECRET_ACCESS_KEY,
    "endpoint_url": S3_ENDPOINT_URL,
    "region_name": S3_REGION_NAME,
    "addressing_style": S3_ADDRESSING_STYLE,
    "default_acl": None,
    "querystring_auth": True,
    "file_overwrite": False,
    "signature_version": "s3v4",
    "verify": S3_VERIFY,
}
STORAGES = {
    "default": {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": {**S3_COMMON_OPTIONS, "location": "media"},
    },
    "staticfiles": {
        "BACKEND": "storages.backends.s3.S3Storage",
        "OPTIONS": {**S3_COMMON_OPTIONS, "location": "static"},
    },
}
STATIC_URL = "/static/"
MEDIA_URL = "/media/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_ROOT = BASE_DIR / "media"

SMTP_HOST = env("SMTP_HOST", "mailpit" if IS_LOCAL_STAGING else None)
if not SMTP_HOST:
    raise ValueError("SMTP_HOST is required in live-staging")
SMTP_PORT = env_int("SMTP_PORT", 1025 if IS_LOCAL_STAGING else 587)
SMTP_USERNAME = env("SMTP_USERNAME", "")
SMTP_PASSWORD = env("SMTP_PASSWORD", "")
SMTP_USE_TLS = env_bool("SMTP_USE_TLS", False)
SMTP_USE_SSL = env_bool("SMTP_USE_SSL", False)
if SMTP_USE_TLS and SMTP_USE_SSL:
    raise ValueError("SMTP_USE_TLS and SMTP_USE_SSL cannot both be true")
SMTP_TIMEOUT = env_int("EMAIL_TIMEOUT", 10)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "no-reply@localhost" if IS_LOCAL_STAGING else None)
if not DEFAULT_FROM_EMAIL:
    raise ValueError("DEFAULT_FROM_EMAIL is required in live-staging")
MAILERS = {
    "default": {
        "BACKEND": "django.core.mail.backends.smtp.EmailBackend",
        "OPTIONS": {
            "host": SMTP_HOST,
            "port": SMTP_PORT,
            "username": SMTP_USERNAME,
            "password": SMTP_PASSWORD,
            "use_tls": SMTP_USE_TLS,
            "use_ssl": SMTP_USE_SSL,
            "timeout": SMTP_TIMEOUT,
        },
    }
}

TURNSTILE_ENABLED = env_bool("TURNSTILE_ENABLED", not IS_LOCAL_STAGING)
TURNSTILE_SECRET_KEY = env("TURNSTILE_SECRET_KEY", "")
TURNSTILE_VERIFY_URL = env(
    "TURNSTILE_VERIFY_URL",
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
)
TURNSTILE_TIMEOUT_SECONDS = env_float("TURNSTILE_TIMEOUT_SECONDS", 5.0)
TURNSTILE_EXPECTED_HOSTNAMES = env_csv("TURNSTILE_EXPECTED_HOSTNAMES", [])
TURNSTILE_EXPECTED_ACTION = env("TURNSTILE_EXPECTED_ACTION", "")
if TURNSTILE_ENABLED and not TURNSTILE_SECRET_KEY:
    raise ValueError("TURNSTILE_SECRET_KEY is required when TURNSTILE_ENABLED is true")

# Authentication uses a separate server-managed opaque session rather than Django's signed
# session cookie. The credential-bearing cookies are scoped to the API and are never readable by
# browser JavaScript. A deployment may choose SameSite=None for a separately hosted SPA, but it
# must then also use Secure cookies.
AUTH_SESSION_COOKIE_NAME = env("AUTH_SESSION_COOKIE_NAME", "compass_session")
AUTH_SESSION_COOKIE_PATH = env("AUTH_SESSION_COOKIE_PATH", "/api/")
AUTH_SESSION_COOKIE_DOMAIN = env("AUTH_SESSION_COOKIE_DOMAIN", None)
AUTH_TRUSTED_COOKIE_NAME = env("AUTH_TRUSTED_COOKIE_NAME", "compass_trusted")
AUTH_TRUSTED_COOKIE_PATH = env("AUTH_TRUSTED_COOKIE_PATH", "/api/v1/auth")
AUTH_LOGIN_CHALLENGE_COOKIE_NAME = env(
    "AUTH_LOGIN_CHALLENGE_COOKIE_NAME", "compass_login_challenge"
)
AUTH_LOGIN_CHALLENGE_COOKIE_PATH = env("AUTH_LOGIN_CHALLENGE_COOKIE_PATH", "/api/v1/auth/mfa")
AUTH_COOKIE_SAMESITE = env("AUTH_COOKIE_SAMESITE", "Lax")
if AUTH_COOKIE_SAMESITE not in {"Lax", "Strict", "None"}:
    raise ValueError("AUTH_COOKIE_SAMESITE must be Lax, Strict, or None")
AUTH_COOKIE_SECURE = env_bool("AUTH_COOKIE_SECURE", not IS_LOCAL_STAGING)
if not IS_LOCAL_STAGING and not AUTH_COOKIE_SECURE:
    raise ValueError("AUTH_COOKIE_SECURE must be true in live-staging")
if AUTH_COOKIE_SAMESITE == "None" and not AUTH_COOKIE_SECURE:
    raise ValueError("AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAMESITE is None")

AUTH_SESSION_AGE_SECONDS = env_int("AUTH_SESSION_AGE_SECONDS", 14 * 24 * 60 * 60)
AUTH_TRUSTED_SESSION_AGE_SECONDS = env_int("AUTH_TRUSTED_SESSION_AGE_SECONDS", 30 * 24 * 60 * 60)
AUTH_LOGIN_CHALLENGE_AGE_SECONDS = env_int("AUTH_LOGIN_CHALLENGE_AGE_SECONDS", 5 * 60)
AUTH_SESSION_LAST_USED_WRITE_INTERVAL_SECONDS = env_int(
    "AUTH_SESSION_LAST_USED_WRITE_INTERVAL_SECONDS", 5 * 60
)
AUTH_RECENT_MFA_WINDOW_SECONDS = env_int("AUTH_RECENT_MFA_WINDOW_SECONDS", 10 * 60)
AUTH_MAX_SESSION_LIST_SIZE = env_int("AUTH_MAX_SESSION_LIST_SIZE", 100)

# MFA policy is deliberately separate from capabilities. An enrolled TOTP factor is an explicit
# user opt-in and requires MFA at login; role-specific mandatory MFA can be enabled later through
# this configuration without changing the authentication/session model.
AUTH_MFA_REQUIRED_ROLE_CODES = env_csv("AUTH_MFA_REQUIRED_ROLE_CODES", [])
AUTH_TOTP_ISSUER_NAME = env("AUTH_TOTP_ISSUER_NAME", "COMPASS")
AUTH_TOTP_INTERVAL_SECONDS = env_int("AUTH_TOTP_INTERVAL_SECONDS", 30)
AUTH_TOTP_VALID_WINDOW = env_int("AUTH_TOTP_VALID_WINDOW", 1)
AUTH_TOTP_DIGITS = env_int("AUTH_TOTP_DIGITS", 6)
if AUTH_TOTP_INTERVAL_SECONDS < 1 or AUTH_TOTP_VALID_WINDOW < 0 or AUTH_TOTP_DIGITS != 6:
    raise ValueError("TOTP interval/window must be valid and AUTH_TOTP_DIGITS must be 6")
AUTH_TOTP_ENCRYPTION_KEY = env("AUTH_TOTP_ENCRYPTION_KEY", "")
if not IS_LOCAL_STAGING and not AUTH_TOTP_ENCRYPTION_KEY:
    raise ValueError("AUTH_TOTP_ENCRYPTION_KEY is required in live-staging")

AUTH_EMAIL_OTP_TTL_SECONDS = env_int("AUTH_EMAIL_OTP_TTL_SECONDS", 10 * 60)
AUTH_EMAIL_OTP_MAX_ATTEMPTS = env_int("AUTH_EMAIL_OTP_MAX_ATTEMPTS", 5)
AUTH_EMAIL_OTP_RESEND_INTERVAL_SECONDS = env_int("AUTH_EMAIL_OTP_RESEND_INTERVAL_SECONDS", 60)
AUTH_EMAIL_OTP_MAX_SENDS = env_int("AUTH_EMAIL_OTP_MAX_SENDS", 5)
AUTH_EMAIL_OTP_CODE_LENGTH = env_int("AUTH_EMAIL_OTP_CODE_LENGTH", 6)
if (
    AUTH_EMAIL_OTP_TTL_SECONDS < 1
    or AUTH_EMAIL_OTP_MAX_ATTEMPTS < 1
    or AUTH_EMAIL_OTP_RESEND_INTERVAL_SECONDS < 1
    or AUTH_EMAIL_OTP_MAX_SENDS < 1
    or AUTH_EMAIL_OTP_CODE_LENGTH != 6
):
    raise ValueError("email OTP settings must be positive and use six-digit codes")

# Turnstile is enabled by default for anonymous high-abuse flows in live-staging. Local tests and
# local-staging remain usable with the explicit local default, while live deployments can opt out
# only by setting a documented security policy deliberately.
AUTH_TURNSTILE_LOGIN_REQUIRED = env_bool("AUTH_TURNSTILE_LOGIN_REQUIRED", not IS_LOCAL_STAGING)
AUTH_TURNSTILE_EMAIL_OTP_REQUIRED = env_bool(
    "AUTH_TURNSTILE_EMAIL_OTP_REQUIRED", not IS_LOCAL_STAGING
)

IDEMPOTENCY_TTL_SECONDS = env_int("IDEMPOTENCY_TTL_SECONDS", 86_400)
IDEMPOTENCY_MAX_RESPONSE_BYTES = env_int("IDEMPOTENCY_MAX_RESPONSE_BYTES", 1_048_576)
API_DOCS_ENABLED = env_bool("API_DOCS_ENABLED", IS_LOCAL_STAGING)
CADDY_MAX_REQUEST_BODY_SIZE = env("CADDY_MAX_REQUEST_BODY_SIZE", "10MB")

PROFILE_PHOTO_MAX_UPLOAD_BYTES = env_int("PROFILE_PHOTO_MAX_UPLOAD_BYTES", 5 * 1024 * 1024)
PROFILE_PHOTO_MAX_OUTPUT_BYTES = env_int("PROFILE_PHOTO_MAX_OUTPUT_BYTES", 2 * 1024 * 1024)
PROFILE_PHOTO_MAX_DIMENSION = env_int("PROFILE_PHOTO_MAX_DIMENSION", 1024)
PROFILE_PHOTO_MAX_PIXELS = env_int("PROFILE_PHOTO_MAX_PIXELS", 25_000_000)
PROFILE_PHOTO_WEBP_QUALITY = env_int("PROFILE_PHOTO_WEBP_QUALITY", 85)

LANGUAGE_CODE = "en-us"
TIME_ZONE = env("TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_SSL_REDIRECT = not IS_LOCAL_STAGING
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not IS_LOCAL_STAGING
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_NAME = env("CSRF_COOKIE_NAME", "compass_csrf")
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = not IS_LOCAL_STAGING
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_PATH = "/"
CSRF_USE_SESSIONS = False
SECURE_HSTS_SECONDS = 0 if IS_LOCAL_STAGING else 31_536_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not IS_LOCAL_STAGING
SECURE_HSTS_PRELOAD = not IS_LOCAL_STAGING

CELERY_BROKER_URL = env("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", REDIS_CACHE_URL)
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
CELERY_ENABLE_UTC = True
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_SEND_SENT_EVENT = False
CELERY_WORKER_SEND_TASK_EVENTS = False
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_IMPORTS = ("compass.tasks",)
CELERY_BEAT_SCHEDULE = {}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"json": {"()": "compass.common.json_logging.JsonFormatter"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "json"}},
    "loggers": {
        "compass": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "django.server": {"handlers": ["console"], "level": "INFO", "propagate": False},
        "celery": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
