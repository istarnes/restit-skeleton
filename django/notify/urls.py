from django.conf.urls.defaults import *
from django.shortcuts import render

from .views import *
from rest.decorators import include_urlpatterns

from django.conf import settings


if settings.DEBUG:
    urlpatterns = [
        url(r'^test/$', showNotificationTest,),
        url(r'^test/(?P<kind>\w.+)$', showNotificationTest,)
    ]

urlpatterns += include_urlpatterns(r'^', __package__ + '.rpc')

