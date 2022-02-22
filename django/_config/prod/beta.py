from _config.prod.defaults import *

SERVER_NAME = "beta.example.io"
SITE_LABEL = "API Server"
BASE_URL = 'http://{0}/'.format(SERVER_NAME)
BASE_URL_SECURE = 'https://{0}/'.format(SERVER_NAME)

CAN_MIGRATE = False
REST_DEBUGGER=True

DEBUG_REST_END_POINTS=[
    "/rpc/account",
    ]

# this will generate a log per user
AUDITLOG_LOGGER_BY_USER = False
AUDITLOG_LOGGER_BY_TERMINAL = True

# this will not log lists requests
AUDITLOG_LOG_NO_LIST = True


# task queue subscriptions to handle
TQ_WORKERS = 32
TQ_SUBSCRIBE = [
    "tq_web_request",
    "tq_hook",
]

# what periodics jobs should this server handle
# this should be deprecated to task queue
PERIODIC_APPS = []

WATCHDOG_SETTINGS = {
    "memory": {
        "load": 90,
        "action": "touch {}/.git/index".format(ROOT)
    }
}
