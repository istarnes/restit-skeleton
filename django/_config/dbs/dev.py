"""
The Dev Database is where bleeding edge development is pushed and systems tested.
It is not meant for certification or QA.
"""

# REDIS is used for sessions, and async messaging (via websockets)
REDIS_SERVER = "localhost"
REDIS_PORT = 6379

CACHES = {
    'default': {
        'BACKEND': 'redis_cache.RedisCache',
        'LOCATION': '{}:{}'.format(REDIS_SERVER, REDIS_PORT)
    }
}

WS4REDIS_CONNECTION = {
    'host': REDIS_SERVER,
    'port': REDIS_PORT,
}

SESSION_REDIS = {
    'host': REDIS_SERVER,
    'port': REDIS_PORT,
}

# This router helps direct to readonly vs read/write
DATABASE_ROUTERS = []


# We use Auro db cluster with a readonly
# paylytics is being deprecated out
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'DBNAME',
        'USER': 'DBUSER',
        'PASSWORD': 'PASSWORD',
        'HOST': 'HOST',
        'PORT': '5432'
    },
    'readonly': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'DBNAME',
        'USER': 'DBUSER',
        'PASSWORD': 'PASSWORD',
        'HOST': 'HOST',
        'PORT': '5432'
    },
}




