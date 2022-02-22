from rest import decorators as rd
from rest.views import restPermissionDenied, restStatus
from account.models import Member, AuthToken


@rd.url(r'^member$')
@rd.url(r'^member/(?P<pk>\d+)$')
@rd.login_required
def rest_on_member(request, pk=None):
    return Member.on_rest_request(request, pk)


@rd.url(r'^member/me$')
@rd.login_optional
def member_me_action(request):
    if not request.user.is_authenticated:
        return restPermissionDenied(request, "not authenticated")
    if request.method == "GET":
        request.session['ws4redis:memberof'] = request.member.getGroupUUIDs()
        return request.member.on_rest_get(request)
    elif request.method == "POST":
        return request.member.on_rest_post(request)
    return restStatus(request, False, error="not supported")


@rd.url(r'^authtoken$')
@rd.url(r'^authtoken/(?P<pk>\d+)$')
@rd.login_required
def rest_on_authtoken(request, pk=None):
    return AuthToken.on_rest_request(request, pk)

