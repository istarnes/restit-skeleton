import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
# entry point for the Django loop
from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
