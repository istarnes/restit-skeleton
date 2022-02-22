"""
Django settings for django rest project.

Generated by 'django-admin startproject' using Django 3.0.5.

For more information on this file, see
https://docs.djangoproject.com/en/3.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.0/ref/settings/
"""

import os
import socket
from version import *

HOSTNAME = socket.gethostname()

DEFAULT_AUTO_FIELD='django.db.models.AutoField'

SILENCED_SYSTEM_CHECKS = ["1_6.W001", "admin.E410"]

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'ilovebeer@@#)*butlikesecrets1234better'

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROOT = BASE_DIR

CONFIG_PATH = os.path.join(os.path.dirname(BASE_DIR), "config")

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = '/media/'

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
SITE_STATIC_ROOT = os.path.join(BASE_DIR, 'site_static')
STATIC_DATA_ROOT = os.path.join(BASE_DIR, 'site_static', 'json')

# URL prefix for static files.
STATIC_URL = 'static/'
STATIC_URL_SECURE = 'static/'

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

STATICFILES_DIRS = [
    SITE_STATIC_ROOT,
    STATIC_ROOT
]

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.0/howto/deployment/checklist/

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

AUTH_USER_MODEL = 'account.User'

ALLOWED_HOSTS = ['*']

CSRF_FAILURE_VIEW = "rest.views.csrf_failure"

PASSWORD_HISTORY = True
LOCK_PASSWORD_ATTEMPTS = 3
LOCK_TIME = 30
PASSWORD_EXPIRES_DAYS = 360

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]

MIDDLEWARE = [
    # 'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'rest.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'rest.middleware.GlobalRequestMiddleware',
    'rest.middleware.CorsMiddleware',
    'auditlog.middleware.LogRequest',
]

ROOT_URLCONF = 'urls'

PROCESS_LOCALE=True


# TEMPLATES = [
#     {
#         'BACKEND': 'django.template.backends.django.DjangoTemplates',
#         'DIRS': [],
#         'APP_DIRS': True,
#         'OPTIONS': {
#             'context_processors': [
#                 'django.template.context_processors.debug',
#                 'django.template.context_processors.request',
#                 'django.contrib.auth.context_processors.auth',
#                 'django.contrib.messages.context_processors.messages',
#             ],
#         },
#     },
# ]

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            # insert your TEMPLATE_DIRS here
            os.path.join(BASE_DIR, 'site_template'),
        ],
        # 'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                # Insert your TEMPLATE_CONTEXT_PROCESSORS here or use this
                # list if you haven't customized them:
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                # "django.core.context_processors.request",
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                # 'sekizai.context_processors.sekizai',
                # 'webcore.context_processors.urls',
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
            ],
            'loaders':[
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ],
            'debug':True
        },

    },
]

WSGI_APPLICATION = 'wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.0/ref/settings/#databases


# Password validation
# https://docs.djangoproject.com/en/3.0/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/3.0/topics/i18n/

DEFAULT_LANGUAGE="en"
TIME_ZONE = 'UTC'
os.environ['TZ'] = 'UTC'
LANGUAGE_CODE = 'en-us'
USE_TZ = False

SITE_ID = 1
USE_I18N = True
USE_L10N = True


