import os

# REDIS is used for sessions, and async messaging (via websockets)
REDIS_SERVER = "localhost"
REDIS_PORT = 6379

CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': '{}:{}'.format(REDIS_SERVER, REDIS_PORT)
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],
        },
    },
}

WS4REDIS_CONNECTION = {
    'host': REDIS_SERVER,
    'port': REDIS_PORT,
}

SESSION_REDIS = {
    'host': REDIS_SERVER,
    'port': REDIS_PORT,
}

DATABASE_ROUTERS = []

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'sqlite.db'),
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
        'ATOMIC_REQUESTS': False,
        "connect_timeout": 60,
        'OPTIONS': {
            'timeout': 60,
        }

    },
    'analytics': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'sqlite_monitoring.db'),
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
        'ATOMIC_REQUESTS': False,
        "connect_timeout": 60,
        'OPTIONS': {
            'timeout': 60,
        }
    },
    'paylytics': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'sqlite_paylytics.db'),
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
        'ATOMIC_REQUESTS': False,
        "connect_timeout": 60,
        'OPTIONS': {
            'timeout': 60,
        }
    }
}
