from _config.defaults import *
from _config.dbs.prod import *


DEBUG = False

# what periodics jobs should this server handle
# this should be deprecated to task queue
PERIODIC_APPS = []

# does this server run a task queue and if so how many works
TQ_WORKERS = 0
# which tasks should this server subscribe to
TQ_SUBSCRIBE = []

LOCK_PASSWORD_ATTEMPTS = 3
LOCK_TIME = 1800
PASSWORD_EXPIRES_DAYS = 90
# logout after no activity for X days
LOGOUT_AFTER_DAYS = 4
# disable after no activity for X days
DISABLE_AFTER_DAYS = 90

PAYJOURNAL_DB = "analytics"

SLACK_ENABLED = True # only for testing
SLACK_CHANNEL = "payauth"

GIT_KEY = "hookswhat"

# allow session keys outside of cookies
SESSION_KEY_SECURE = False
SESSION_COOKIE_SAMESITE="None"
SESSION_COOKIE_SECURE=True
CSRF_COOKIE_SECURE=True

SESSION_ENGINE = 'redis_sessions.session'
SESSION_REDIS_PREFIX = 'session'

NOTIFY_REST_ERRORS=True
PERSISTENT_LOG_PRINT = False

DEBUG_REST_OUTPUT=True
DEBUG_REST_INPUT=False
DEBUG_WORLDPAY=True
DEBUG_DATETIME=False

DEBUG_REST_END_POINTS=[
    "/rpc/account",
    "/rpc/pushit"
]

CORS_SHARING_ALLOWED_ORIGINS = '*'
CORS_SHARING_ALLOWED_METHODS = ['POST','GET','OPTIONS', 'PUT', 'DELETE']


USER_METADATA_PROPERTIES = {
    "secrets": {
        "hidden": True,
        "notify": "user_audit"
    },
    "permissions":{
        "on_change":"on_permission_change"
    },
    "permissions.view_all_groups":{
        "requires":"manage_staff",
        "notify": "user_audit"
    }
}

"""
we support every branch here as the update script will check the branch and
abort if the update is not for the right branch.
"""
GIT_PROJECTS = {
    "restit-skeleton": [
        {
            "branch": "master",
            "updater": "/opt/restit/update.sh"
        },
    ],
}