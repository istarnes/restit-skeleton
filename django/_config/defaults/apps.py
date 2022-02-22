

INSTALLED_APPS = [
    # NOTE: ORDER MATTERS!
    #
    # templates from earlier modules can override later ones.
    #
    # specify project-specific modules first
    # then other django modules.
    #
    'account',
    "taskqueue",

    # ADD PROJECT MODULES HERE

    # END PROJECT MODULES
    'pushit',
    'location',
    'auditlog',
    'medialib',
    'rest',
    'sessionlog',
    'notify',
    'telephony',
    'example',

    # 'suit',

    'django.contrib.humanize',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',

]
