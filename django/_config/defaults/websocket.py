from django.core.exceptions import PermissionDenied

def get_allowed_channels(request, channels):
    if not request.user or not request.user.is_authenticated:
        return []
        # raise PermissionDenied('Not allowed to subscribe nor to publish on the Websocket!')
    return channels

WS4REDIS_ALLOWED_CHANNELS = get_allowed_channels

WEB_SOCKETS = True

SESSION_ENGINE = 'redis_sessions.session'
SESSION_REDIS_PREFIX = 'session'

WEBSOCKET_URL = '/ws/'
WS4REDIS_EXPIRE = 30

WS4REDIS_HEARTBEAT = '--heartbeat--'

WS4REDIS_PREFIX = 'flow'

# WS4REDIS_SUBSCRIBER = 'rest.RemoteEvents.RedisSubscriber'
WSGI_APPLICATION = 'ws4redis.django_runserver.application'

# WS4REDIS_CONNECTION = {
#     'host': 'redis.example.com',
#     'port': 16379,
#     'db': 17,
#     'password': 'verysecret',
# }

WS4REDIS_APPS = ('ws4redis', )
