from rest import decorators as rd
from rest.views import restPermissionDenied, restStatus, restGet
from .models import TODO


@rd.url(r'^todo$')
@rd.url(r'^todo/(?P<pk>\d+)$')
@rd.login_required
def rest_on_todo(request, pk=None):
    return TODO.on_rest_request(request, pk)


@rd.urlGET(r'^helloworld$')
def rest_on_helloworld(request):
    # this is a public api call that supports only GET METHOD
    echo_message = request.DATA.get("echo", None)  # the request.DATA extension makes it easy to get request data
    if echo_message is not None:
        return restGet(request, dict(echo_reply=echo_message))  # echo the message back into the response
    return restStatus(request, True)  # just return the status true

