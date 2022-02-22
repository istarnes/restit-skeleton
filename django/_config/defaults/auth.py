
TWILIO_SID = "XXXX"
TWILIO_AUTH_TOKEN = "XXXX"
TELEPHONY_DEFAULT_SRC = "+XXXX"
TELEPHONY_555_TO = "+19496065381"
TELEPHONY_DEFAULT_SMS_RESPONSE = "To speak to a representative call 1-800-XXX-XXXX"
TELEPHONY_HANDLERS = {

}

SOCIAL_AUTH_EXPIRATION = False

SOCIAL_AUTH_ALLOW_NEW = True

ALLOW_USER_LOGIN = True
ALLOW_SOCIAL_LOGIN = False
ALLOW_FACEBOOK_LOGIN = False
ALLOW_GOOGLE_LOGIN = True
ALLOW_TWITTER_LOGIN = False
ALLOW_INSTAGRAM_LOGIN = False

# don't let social auth directly update picture field
SOCIAL_AUTH_PROTECTED_USER_FIELDS = ['picture']
SOCIAL_AUTH_ASSOCIATE_BY_MAIL = True
SOCIAL_AUTH_ALLOW_NULL_EMAIL = True
SOCIAL_AUTH_SESSION_EXPIRATION = False
SOCIAL_AUTH_LOCATION_BY_IP = True

LOGIN_URL          = '/login/'
LOGIN_REDIRECT_URL = '/logged-in/'
LOGIN_ERROR_URL    = '/login/'
SOCIAL_AUTH_NEW_USER_REDIRECT_URL = '/'

# LOGGED IN URLS
PUBLIC_URL = "/"
HOME_URL = "/"
MOBILE_URL = "/"
MOBILE_HOME = "/"
DEFAULT_GROUP_KIND = "merchant"

################################
#   SOCIAL AUTH SETTINGS
################################

# fix for 1.6 and social auth issues
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
)

SOCIAL_AUTH_ENABLED_BACKENDS = (
    'facebook',
    'google',
    'yahoo',
    'twitter',
    'instagram',
    'linkedin'
)
# INSTAGRAM
SOCIAL_AUTH_INSTAGRAM_KEY = ''
SOCIAL_AUTH_INSTAGRAM_SECRET = ''
SOCIAL_AUTH_INSTAGRAM_AUTH_EXTRA_ARGUMENTS = {'scope': 'likes comments relationships'}

# TWITTER
SOCIAL_AUTH_TWITTER_KEY = ''
SOCIAL_AUTH_TWITTER_SECRET = ''
# SPECIFIC ACCOUNT SETTINGS FOR POSTING
TWITTER_ACCESS_TOKEN = "3005375150-"
TWITTER_ACCESS_TOKEN_SECRET = ""
TWITTER_HANDLE = "@controltheflow"

# FACEBOOK
SOCIAL_AUTH_FACEBOOK_KEY = ''
FACEBOOK_APP_ID = SOCIAL_AUTH_FACEBOOK_KEY
SOCIAL_AUTH_FACEBOOK_SECRET = ''
# new permission is user_posts
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email', 'user_friends', 'read_insights', 'publish_actions', 'read_stream']

# LINKEDIN
SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY = ""
SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET = ""
SOCIAL_AUTH_LINKEDIN_OAUTH2_SCOPE = ['r_basicprofile', 'r_emailaddress', 'w_share']
SOCIAL_AUTH_LINKEDIN_OAUTH2_FIELD_SELECTORS = ['email-address', 'headline', 'industry']
SOCIAL_AUTH_LINKEDIN_OAUTH2_EXTRA_DATA = [('id', 'id'),
                       ('first-name', 'first_name'),
                       ('last-name', 'last_name'),
                       ('email-address', 'email_address'),
                       ('headline', 'headline'),
                       ('industry', 'industry')]
# SPECIFIC ACCOUNT SETTINGS
LINKEDIN_SECRET_KEY = ""
LINKEDIN_API_KEY = ""

# GOOGLE OAUTH2 - NOT WE USE A CUSTOM GOOGLE AUTH MECHANISM TO PULL EXTRA DATA
SOCIAL_AUTH_GOOGLE_KEY = '1007627077826-qakln5j86pgcv4dpl5470dvch6lk48vi.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_SECRET = 'KMoQRtdECxIR7gnBJMF-V8Vj'
SOCIAL_AUTH_GOOGLE_SCOPE = []
#SOCIAL_AUTH_GOOGLE_OAUTH_EXTRA_SCOPE     = ['https://www.googleapis.com/auth/youtube.readonly', 'https://www.googleapis.com/auth/youtube.upload']
SOCIAL_AUTH_GOOGLE_EXTRA_ARGUMENTS = {'access_type':'offline'}
SOCIAL_AUTH_GOOGLE_USE_UNIQUE_USER_ID = True

# GOOGLE_OAUTH2_MOBILE_ID		= ''
# GOOGLE_OAUTH2_MOBILE_SECRET	= ''
# GOOGLE_OAUTH2_USE_UNIQUE_USER_ID = True
# GOOGLE_OAUTH_EXTRA_ARGUMENTS = {'access_type':'offline'}

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'account.pipeline.social_user',
    'account.pipeline.associate_by_email',
    'social_core.pipeline.user.get_username',
    'account.pipeline.create_user',
    'account.pipeline.associate_user',
    # 'social_core.pipeline.social_auth.associate_user',
    # 'social_core.pipeline.social_auth.load_extra_data',
    'account.pipeline.load_extra_data',
    'account.pipeline.update_user_details',
    'account.pipeline.set_profile_pic',
    'account.pipeline.save_session',
)


YOUTUBE_DEVELOPER_KEY = ""
