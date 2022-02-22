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

DATABASE_ROUTERS = []

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

