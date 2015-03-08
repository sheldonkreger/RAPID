from RAPID.RAPID.settings.base import *

BASE_SITE_URL = 'https://rapidpivot.com'

ALLOWED_HOSTS = []

DEBUG = False
TEMPLATE_DEBUG = False

CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True

# Email Settings
EMAIL_USE_TLS = True
EMAIL_HOST = retrieve_secret_configuration("EMAIL_HOST")
EMAIL_HOST_USER = retrieve_secret_configuration("EMAIL_USER")
EMAIL_HOST_PASSWORD = retrieve_secret_configuration("EMAIL_PASS")
EMAIL_PORT = retrieve_secret_configuration("EMAIL_PORT")


# Basic Logging Configuration
# https://docs.djangoproject.com/en/1.7/topics/logging/
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': 'RAPID.log',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}