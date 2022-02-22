# from django.conf.urls import url, include, path, re_path
from django.urls import path, include
from django.conf.urls.static import serve, static
from django.conf import settings
from django.contrib import admin
from django.views.static import *
from django.contrib.staticfiles import finders
import os
from rest.views import _returnResults

admin.autodiscover()


def serve_static(request, path):
    result = finders.find(path)
    if not result:
        print("NO FOUND")
        raise Http404("PATH: {0} NOT FOUND".format(path))

    if result and type(result) in [list, tuple]:
        result = result[0]

    fullpath = os.path.realpath(result)

    statobj = os.stat(fullpath)
    if not was_modified_since(request.META.get('HTTP_IF_MODIFIED_SINCE'),
                              statobj.st_mtime, statobj.st_size):
        return HttpResponseNotModified()
    content_type, encoding = mimetypes.guess_type(fullpath)
    content_type = content_type or 'application/octet-stream'
    response = FileResponse(open(fullpath, 'rb'), content_type=content_type)
    response["Last-Modified"] = http_date(statobj.st_mtime)
    if stat.S_ISREG(statobj.st_mode):
        response["Content-Length"] = statobj.st_size
    if encoding:
        response["Content-Encoding"] = encoding
    return response


urlpatterns = [
    path('rpc/', include('rest.urls')),
    path('admin/', admin.site.urls),
    path('robots.txt', serve, {'path': 'robots.txt', 'document_root': settings.STATICFILES_DIRS[0]}),
    path('favicon.ico', serve, {'path': 'favicon.ico', 'document_root': settings.STATICFILES_DIRS[0]}),
    # path('static/', static, {'path': 'static/', 'document_root': settings.STATIC_ROOT}),
]

if settings.DEBUG:
    print(settings.STATIC_URL)
    urlpatterns = urlpatterns + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
print(urlpatterns)

def handler404(request, exception):
    return _returnResults(request, dict(error="endpoint not found", status=404), status=404)


def handler500(request, exception=None):
    return _returnResults(request, dict(error=str(exception), status=500), status=500)


def handler403(request, exception=None):
    return _returnResults(request, dict(error=str(exception), status=403), status=403)


def handler400(request, exception=None):
    return _returnResults(request, dict(error=str(exception), status=400), status=400)
