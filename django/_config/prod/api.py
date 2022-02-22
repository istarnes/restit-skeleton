from _config.prod.defaults import *

SERVER_NAME = "api.example.io"
SITE_LABEL = SERVER_NAME[:SERVER_NAME.find('.')]
BASE_URL = 'http://{0}/'.format(SERVER_NAME)
BASE_URL_SECURE = 'https://{0}/'.format(SERVER_NAME)

