from .views import *

from django.conf.urls.defaults import *
from django.shortcuts import render

from rest.decorators import include_urlpatterns

urlpatterns = [
    url(r'^activity_report$', showActivityReport),
]

# urlpatterns += include_urlpatterns(r'^', __package__ + '.rpc')

