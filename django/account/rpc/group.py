from rest import decorators as rd
from account.models import Group, Membership


@rd.url(r'^group$')
@rd.url(r'^group/(?P<pk>\d+)$')
@rd.login_required
def rest_on_group(request, pk=None):
    return Group.on_rest_request(request, pk)


@rd.url(r'^membership$')
@rd.url(r'^membership/(?P<pk>\d+)$')
@rd.login_required
def rest_on_membership(request, pk=None):
    return Membership.on_rest_request(request, pk)


