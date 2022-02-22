from .safelogging import LogLimitFilter, suppress_allowed_hosts

AUDITLOG_RETENTION_DAYS = 14

DEBUG_REST_INPUT = True
DEBUG_REST_OUTPUT = True
DEBUG_WORLDPAY = True

# one email per XX seconds
LOGLIMIT_RATE = 10

# uses keys to detect which errors are the same
LOGLIMIT_MAX_KEYS = 100

# uses cache if it's available
LOGLIMIT_CACHE_PREFIX = 'LOGLIMIT'

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '%(name)s.%(funcName)s %(asctime)s %(levelname)s %(message)s'
        },
        'normal': {
            'format': '%(asctime)s %(module)s %(levelname)s %(message)s'
        },
        'simple': {
            'format': '%(asctime)s %(levelname)s %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
        'loglimit': {
            '()': LogLimitFilter,
        },
        'allowed_hosts': {
            '()': 'django.utils.log.CallbackFilter',
            'callback': suppress_allowed_hosts,
        },
    },
    'handlers': {
        'null': {
            'level':'DEBUG',
            'class':'logging.NullHandler',
        },
        'console':{
            'level':'INFO',
            'class':'logging.StreamHandler',
            'formatter': 'verbose'
        },
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false', 'allowed_hosts', 'loglimit'],
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django': {
            'handlers':['null'],
            'propagate': True,
            'level':'INFO',
        },

        'django.security': {
            'handlers': ['mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },

        'django.request': {
            'handlers': ['console', 'mail_admins'],
            'level': 'INFO',
            'propagate': False,
        },

        'app':{
            'handlers': ['console', 'mail_admins'],
            'level':'INFO'
        }
    }
}
