from pathlib import Path
import os

import dj_database_url
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(BASE_DIR / '.env')

SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'dev-secret-key')
DEBUG = os.getenv('DJANGO_DEBUG', '1') == '1'

allowed_hosts = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')
ALLOWED_HOSTS = [host.strip() for host in allowed_hosts if host.strip()]

# Allow Railway public host automatically when deployed.
railway_public_domain = os.getenv('RAILWAY_PUBLIC_DOMAIN', '').strip()
if railway_public_domain:
    ALLOWED_HOSTS.append(railway_public_domain)

# Normalize accidental scheme prefixes and remove duplicates.
ALLOWED_HOSTS = list(
    dict.fromkeys(
        host.replace('https://', '').replace('http://', '').strip().rstrip('/')
        for host in ALLOWED_HOSTS
        if host and host.strip()
    )
)

CORS_ALLOWED_ORIGINS = [
    'https://seerahpodadmin-frontend.vercel.app',
]

CORS_ALLOWED_ORIGIN_REGEXES = [
    r'^https:\/\/.*\.vercel\.app$',
]

CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = [
    'https://seerahpodadmin-frontend.vercel.app',
]


INSTALLED_APPS = [
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'api.middleware.AdminAccessMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'core.wsgi.application'
ASGI_APPLICATION = 'core.asgi.application'


# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.postgresql',
#         'NAME': os.getenv('POSTGRES_DB', 'design1'),
#         'USER': os.getenv('POSTGRES_USER', 'postgres'),
#         'PASSWORD': os.getenv('POSTGRES_PASSWORD', 'postgres'),
#         'HOST': os.getenv('POSTGRES_HOST', 'localhost'),
#         'PORT': os.getenv('POSTGRES_PORT', '5432'),
#     }
# }

database_url = os.getenv("DATABASE_URL", "").strip()
if database_url:
    DATABASES = {
        "default": dj_database_url.parse(database_url, conn_max_age=600),
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("PGDATABASE", os.getenv("POSTGRES_DB", "design1")),
            "USER": os.getenv("PGUSER", os.getenv("POSTGRES_USER", "postgres")),
            "PASSWORD": os.getenv(
                "PGPASSWORD",
                os.getenv("POSTGRES_PASSWORD", "postgres"),
            ),
            "HOST": os.getenv("PGHOST", os.getenv("POSTGRES_HOST", "localhost")),
            "PORT": os.getenv("PGPORT", os.getenv("POSTGRES_PORT", "5432")),
        }
    }


AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Google OAuth (Admin login)
# This should match the OAuth 2.0 Client ID used by the admin frontend (VITE_GOOGLE_CLIENT_ID).
GOOGLE_OAUTH_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID', '').strip()

# Google OAuth (Mobile app login)
# Preferred client ID for /api/v1/auth/google/* endpoints used by the Flutter app.
# Falls back to GOOGLE_OAUTH_CLIENT_ID in view code if unset.
GOOGLE_OAUTH_MOBILE_CLIENT_ID = os.getenv('GOOGLE_OAUTH_MOBILE_CLIENT_ID', '').strip()

# Billing verification (Google Play)
GOOGLE_PLAY_SERVICE_ACCOUNT_JSON = os.getenv('GOOGLE_PLAY_SERVICE_ACCOUNT_JSON', '').strip()
GOOGLE_PLAY_SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_PLAY_SERVICE_ACCOUNT_FILE', '').strip()
GOOGLE_PLAY_STRICT_VERIFY = os.getenv('GOOGLE_PLAY_STRICT_VERIFY', '0') == '1'


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


# Email delivery (used by login/setup 2FA code emails)
EMAIL_BACKEND = os.getenv(
    'EMAIL_BACKEND',
    'django.core.mail.backends.console.EmailBackend',
).strip()
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'no-reply@seerahpod.local').strip()
EMAIL_HOST = os.getenv('EMAIL_HOST', '').strip()
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '').strip()
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '').strip()
EMAIL_USE_TLS = _env_bool('EMAIL_USE_TLS', default=True)
EMAIL_USE_SSL = _env_bool('EMAIL_USE_SSL', default=False)
