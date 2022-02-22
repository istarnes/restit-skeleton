from _config.defaults import *
from _config.dbs.local import *

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'a89opL5x75SYWsVKtOYPwQ575IpVzq0Ji69UeAJgWWerUM0zkSMzOdv94jxf5Oo0'


CAN_MIGRATE = True

PERIODIC_APPS = []

TQ_SUBSCRIBE = ["tq_web_request", "tq_model_handler"]

NOTIFY_REST_ERRORS=True
PERSISTENT_LOG_PRINT = True

DEBUG_REST_OUTPUT=True
DEBUG_REST_INPUT=True
DEBUG_WORLDPAY=True
DEBUG_DATETIME=False

DEBUG_REST_END_POINTS = [
    "/rpc/account",
    "/rpc/auditlog/plog"
]

DEBUG = True
SOCIAL_AUTH_RAISE_EXCEPTIONS = True
RAISE_EXCEPTIONS = True

SITE_LABEL = "LOCAL"
# DEBUG_SLOWDOWN = 0.25
DEBUG_SLOWDOWN = 0.0

SERVER_NAME = "localhost:8000"

BASE_URL = 'http://{0}/'.format(SERVER_NAME)
BASE_URL_SECURE = 'http://{0}/'.format(SERVER_NAME)

MEDIALIB_STORE = {}
MEDIALIB_DEFAULT_STORE = 'file:///{0}'.format(AWS_S3_BUCKET)

RENDER_AMI = None
CAN_NUKE_DATABASE = True


USER_METADATA_PROPERTIES = {
    "permissions":{
        "on_change":"on_permission_change"
    },
    "permissions.manage_casino":{
        "requires":"manage_staff",
        "notify": "manage_staff"
    },
    "permissions.qc_refund":{
        "requires":"manage_staff",
        "notify": "manage_staff"
    },
    "permissions.manage_staff":{
        "requires":"manage_staff",
        "notify": "manage_staff"
    },
    "permissions.rest_errors":{
        "requires":"manage_staff",
        "notify": "manage_staff"
    }
}

