
DEBUG_REST_OUTPUT=False
DEBUG_REST_INPUT=False
DEBUG_WORLDPAY=False
# show rest debugger on raw REST pages
REST_DEBUGGER=False

# used for API contacts
CONTACT_DEFAULT_SOURCE = "casinomoney"
CONTACT_EXTRA = ["traffic", "business", "company", "application", "city"]


MY_FEED = ["content.share", "content.like", "account.follow"]
GLOBAL_FEED = []

NO_SCRAPE_DOMAINS = ["localhost"]

CONTENT_KINDS = (
    ('S', 'Selfie'),
    ('I', 'Image'),
    ('V', 'Video'),
    ('E', 'Remote URL')
)

CONTENT_STATES = (
    (0, "Inactive"),
    (1, "Deleted"),
    (50, "Archived"),
    (100, "Not Approved"),
    (150, "Removed Nudity"),
    (151, "Removed Copyright"),
    (152, "Removed Other"),
    (199, "No Trend"),
    (200, "Active"),
)

CONTENT_FLOW_STATES = (
    (0, "Sent"),
    (1, "Read"),
    (50, "Archived"),
    (100, "Ignored"),
    (200, "Published"),
)

CONTENT_FLOW_MESSAGE_STATES = (
    (0, "Sent"),
    (1, "Read"),
    (50, "Archived"),
    (200, "Responded"),
)

# STATISTICS MODULE MAPPINGS
# _aliases specifies lookup table for each component/action set.
#   'COMPONENT.ACTION': {
#       'ALIAS_TO': ('ALIAS_FROM', TYPE),
#       ...
#   },
STAT_ALIASES = {
        'account.invite': {
            'email': ('str1', str),
        },
        'account.confirm': {
            'email': ('str1', str),
        },
        'account.created': {
            'method': ('str1', str)
        },
        'account.login': {
        },
        'content.comment': {
            'content': ('int1', 'content.Content'),
            'comment': ('int2', 'comment.Comment'),
        },
        'content.view': {
            'content': ('int1', 'content.Content'),
        },
        'content.share': {
            'content': ('int1', 'content.Content'),
            'website': ('str1', str),
        },
        'content.like': {
            'content': ('int1', 'content.Content'),
        },
        'content.dislike': {
            'content': ('int1', 'content.Content'),
        },
        'content.rate': {
            'content': ('int1', 'content.Content'),
        },
        'content.unrate': {
            'content': ('int1', 'content.Content'),
        }
    }


AUDIT_LOG_FILTERS = {
    "bm2": "sanatize_pan",
    "bm127.10": "sanatize_all"
}

SOFTWARE_VERSIONS = {
    "nginx":"nginx -v 2>&1  | cut -d'/' -f 2",
    "openssl":"openssl version | cut -d' ' -f 2",
    "python": "python -V 2>&1 | cut -d' ' -f 2",
    "redis": "redis-server -v | cut -d' ' -f3 | cut -d'=' -f 2",
    "ssh": "ssh -V 2>&1 | cut -d',' -f1",
    "django": "django-admin --version"
}


