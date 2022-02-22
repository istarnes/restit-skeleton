from _config.dev.defaults import *

CAN_MIGRATE = True

SERVER_NAME = "test.example.io"
SITE_LABEL = "Test"
BASE_URL = 'http://{0}/'.format(SERVER_NAME)
BASE_URL_SECURE = 'https://{0}/'.format(SERVER_NAME)

REST_DEBUGGER=True

# task queue subscriptions to handle
TQ_WORKERS = 4
TQ_SUBSCRIBE = [
    "tq_web_request",
    "tq_model_handler",
    "tq_hook",
    "tq_app_handler",
    "tq_app_handler_medialib",
    "tq_app_handler_reporting",
    "tq_app_handler_transmit",
    "tq_app_handler_update",
    "tq_app_handler_cleanup",
    "tq_app_handler_monitor",
    "tq_app_handler_priority"
]

PERIODIC_APPS = ["support", "taskqueue", "auditlog"]

FACTORY_GENERATOR = True  # allow auto generation of new merchants

REKOG_COLLECTION_ID = "dev-rekog-faces"

# ALLOWS STAFF TO DELETE DATABASE TABLES
CAN_NUKE_DATABASE = False

DEBUG_REST_END_POINTS=[
    "/rpc/account",
    "/rpc/auditlog/plog"
    ]

# this will generate a log per user
AUDITLOG_LOGGER_BY_USER = True
AUDITLOG_LOGGER_BY_TERMINAL = True
# this will not log lists requests
AUDITLOG_LOG_NO_LIST = True

AUDITLOG_PRUNE_DAYS = 30*6
