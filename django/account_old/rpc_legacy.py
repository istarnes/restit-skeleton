from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import permission_required
from django.contrib.auth.tokens import default_token_generator
from django.db.models import Q
from django import forms

from social_django.models import UserSocialAuth
from social_django.utils import load_strategy, load_backend

from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.forms import PasswordResetForm

from rest.decorators import *
from rest.views import *
from rest import search
from rest import helpers
import random

from errorcatcher.exceptions import *

from .models import *
from .forms import *

from flow.models import EmailTrack, UserInvite

from medialib.utils import *
from medialib.models import MediaLibrary, MediaItem

from content.models import ContentShare

import django.middleware.csrf

import copy
import re
import string


def getGroupByID(request, group_uuid):
    result = Group.objects.filter(pk=group_uuid).first()
    if not result:
        return restStatus(request, False, error="no match")
    if not result.isMember(request.user) and not request.user.is_staff:
        return restPermissionDenied(request)
    return restGet(request, result, **Group.getGraph("default"))


def getMemberGroup(request):
    member = Member.getByUser(request.user)
    if "group_id" in request.DATA:
        group_id = request.DATA['group_id']
        group = member.getGroup(group_id)
    elif "group" in request.DATA:
        group_id = request.DATA['group']
        group = member.getGroup(group_id)
    else:
        group = member.getDefaultGroup()
    if not group:
        raise NotAuthorized
    return member, group

def getUser(request, item_id):
    member = Member.objects.filter(pk=item_id).last()
    graph = request.DATA.get("graph", "basic")

    if not member:
        return restPermissionDenied(request)
    if request.user.id != item_id:
        if not request.member.canSee(member):
            return restPermissionDenied(request)

    if not request.user.is_staff:
        graph = "basic"

    return restGet(request, member, **Member.getGraph(graph))


@urlGET (r'^user/(?P<user_id>\d+)$')
@login_required
def getUserById(request, user_id):
    """
    | param: user_id = the id of the user your are looking up

    | Return: user_graph

    | Get a graph of the specified user
    """
    if request.method == "POST":
        return postUserId(request, user_id)
    return getUser(request, user_id)

@urlGET (r'^user/details$')
@login_required
def getUserDetails(request):
    """
    | param: user_id = the id of the user your are looking up

    | Return: user_graph

    | Get a graph of the specified user
    """
    if request.user.is_staff:
        ret = Member.objects.all()
        if "search" in request.DATA:
            q = request.DATA.get("search")
            sq = search.get_query(q, ["first_name", "last_name", "email"])
            ret = ret.filter(sq)
        det_graph = copy.deepcopy(user_graph)
        det_graph['fields'] += [
            'email',
            'first_name',
            'last_name',
        ]
        det_graph['recurse_into'] += [
            'properties',
            "social_details"
        ]
        return restList(request, ret, **det_graph)
    return restPermissionDenied(request)

@urlPOST (r'^user/(?P<user_id>\d+)$')
@urlPOST (r'^user/$')
@login_required
def postUserId(request, user_id=None):
    """
    | param: user_id = id of the user we are updating
    | param: email = update the email
    | param: first_name = update the first_name
    | param: last_name = update the last_name
    | param: profile_img = update the profile image (file)

    | Return: status + error

    | update the user
    """
    if user_id:
        member = Member.objects.filter(pk=user_id).first()
    else:
        member = request.member

    if member.id != request.user.id:
        me = Member.getByUser(request.user)
        if not me.canEdit(member):
            return restPermissionDenied(request)

    if "disable" in request.DATA and request.DATA.get("disable") in [1, '1', 'Y', 'true']:
        # THIS WILL DISALBE THE ACCOUNT THE MEMBER BELONGS TO
        member.disable(request.user)
        return restStatus(request, True)

    member.saveFromRequest(request)

    graph_name = "default"
    if member.id == request.user.id:
        graph_name = "me"
        oldpassword = request.DATA.get("oldpassword")
        if oldpassword:
            password = request.DATA.get("newpassword")
            if password and not request.user.check_password(oldpassword):
                return restStatus(request, False, "old password is not correct")
            request.user.set_password(password)
            request.user.save()
    return restGet(request, member, **Member.getGraph(graph_name))

@urlGET (r'^user/(?P<username>[\w.@+-]+)$')
@urlGET (r'^user/(?P<username>[\w.@+-]+)/$')
def getUserByUsername(request, username):
    """
    | param: user_id = the id of the user your are looking up

    | Return: user_graph

    | Get a graph of the specified user
    """
    if not request.user.is_authenticated:
        print("USER IS NOT AUTHENTICATED ACCESSING ME")

    if username == "me" and request.user and request.user.is_authenticated:
        ret = Member.getByUser(request.user)
        request.session['ws4redis:memberof'] = ret.getGroupUUIDs()
    else:
        ret = Member.objects.filter(username=username).first()
    if ret is None:
        return restStatus(request, False, error="user not found")

    if request.user and request.user.id == ret.id:
        return restGet(request, ret, **Member.getGraph("me"))
    return restGet(request, ret, **Member.getGraph("default"))

# @urlDELETE (r'^user/(?P<item_id>\d+)$')
# @login_required
# def deleteUser(request, item_id):
# 	"""
# 	| param: user_id = id of the user we are updating

# 	| Return: status + error

# 	| disables the users account
# 	"""
# 	ret = get_object_or_404(Member, pk=item_id)
# 	if request.user.id != ret.id:
# 		# not our own object, we have to having matching groups
# 		member = Member.getByUser(request.user)
# 		if not member.canEdit(ret):
# 			raise NotAuthorized
# 	ret.delete();
# 	return restStatus(request, True);


@urlGET (r'^user$')
@urlGET (r'^user/$')
@login_required
def getUsers(request):
    """
    | param: search = free text to search for users

    | Return: user_list_graph

    | return a list of users in the system.
    """
    # for security reasons you can only get one group at a time that you have access to
    # member, group = getMemberGroup(request)
    graph = request.DATA.get("graph", "basic")
    is_active = request.DATA.get("is_active", 1)
    if not request.user.is_staff:
        graph = "basic"

    qset = Member.objects.filter(is_active=is_active)

    if request.DATA.get(["staffonly", "staff"]):
        qset = qset.filter(is_staff=True)
    elif request.group:
        qset = qset.filter(memberships__group=request.group)

    q = request.DATA.get(["search", "q"])
    if q:
        sq = search.get_query(q, ["first_name", "last_name", "email"])
        qset = qset.filter(sq)

    return restList(request, qset, **Member.getGraph(graph))


@urlGET (r'^group/(?P<group_uuid>[a-zA-Z0-9_.-]+)/members$')
@urlGET (r'^group/(?P<group_uuid>[a-zA-Z0-9_.-]+)/members/$')
@login_required
def getGroupMembers(request, group_uuid):
    result = Group.objects.filter(uuid=group_uuid).first()
    if not result:
        return restStatus(request, False, error="no match")
    if not result.isMember(request.user):
        return restPermissionDenied(request)
    res = result.memberships.all()

    return restList(request, res, **Group.getGraph("default"))

# @urlGET (r'^membership$')
# @login_required
# def getMemberships(request):
# 	member, group = getMemberGroup(request)

# 	ret = Membership.objects.filter(group=group, member__is_active=True)

# 	if 'search' in request.DATA:
# 		q = request.DATA.get("search")
# 		sq = search.get_query(q, ["member__first_name", "member__last_name"])
# 		ret = ret.filter(sq)

# 	fields=[
# 		'id',
# 		('member.id', 'member_id'),
# 		'member.username',
# 		'member.email',
# 		'member.first_name',
# 		'member.last_name',
# 		('member.date_joined', 'created',),
# 		'member.modified',
# 		'member.profile_image',
# 		'member.thumbnail',
# 		'role',
# 		'group',
# 		'status'
# 	]


# 	assocs = request.DATA.get("associates", "")
# 	managers = request.DATA.get("managers", "")

# 	if len(assocs) and assocs[0] in ["1", "Y", "y", "T", "t"]:
# 		ret = ret.filter(role__iexact="associate").order_by("-status__id")

# 	if len(managers) and managers[0] in ["1", "Y", "y", "T", "t"]:
# 		ret = ret.filter(role__in=["Manager", "Admin", "Owner", "GM", "GSM"])

# 	return restList(request, ret,
# 		recurse_into=[
# 			'status',
# 			('member', ''),
# 			'member.properties'
# 		],
# 		fields=fields)

@urlPOST (r'^legacy/membership/(?P<membership_id>\d+)$')
@login_required
def postMembership(request, membership_id):
    """
    | param: membership_id = id of the membership to update
    | param: email = use the email as the lookup

    | Return: status + error

    | Update a membership
    """
    me = Member.getByUser(request.user)
    membership = Membership.objects.filter(pk=membership_id).first()
    if membership is None:
        return restPermissionDenied(request)

    group = membership.group
    my_ms = group.getMembership(me)
    full_edit = False
    if request.user.is_staff:
        full_edit = True
    elif my_ms and (my_ms.hasPerm("membership.edit") or my_ms.isManager()):
        full_edit = True

    if (full_edit or me == membership.member) and "state" in request.DATA:
        # partial edit of only state
        state = request.DATA.get("state", 0)
        membership.state = state
        membership.save()
        return restStatus(request, True)

    if not full_edit:
        return restPermissionDenied(request)

    if request.DATA.get("disable", field_type=bool):
        # THIS WILL DISALBE THE ACCOUNT THE MEMBER BELONGS TO
        membership.member.disable(request.user)
        return restStatus(request, True)

    role = request.POST.get("role", None)
    if role != None and membership.role != role:
        membership.role = role
        membership.save()

    membership.member.saveFromRequest(request)
    pwd = request.DATA.get("password")
    pwd2 = request.DATA.get("password2")
    if pwd2 and pwd2 == pwd:
        # TODO check allow insecure passwords
        if len(pwd2) < 5:
            return restStatus(request, False, error="password must be atleast 5 characters")
        membership.member.set_password(pwd)
        membership.member.save()

    if "reset_password" in request.DATA:
        # ok lets send a reset password
        membership.member.sendResetPassword()
    elif "resend_invite" in request.DATA:
        membership.member.sendInvite(me, group=group, is_new=False)
    return restStatus(request, True)

@urlGET (r'^legacy/membership$')
@urlGET (r'^legacy/membership/$')
@login_required
def listMemberships(request):
    me = Member.getByUser(request.user)
    res = me.memberships.filter(state__gte=-10)
    if "kind" in request.DATA:
        res = res.filter(group__kind=request.DATA.get("kind", "org"))
    return restList(request, res.order_by("-created"), **Membership.getGraph("detailed"))

@urlGET (r'^legacy/membership/(?P<membership_id>\d+)$')
@urlGET (r'^legacy/membership/me-(?P<group_id>\d+)$')
@login_required
def getMembership(request, membership_id=None, group_id=None):
    me = Member.getByUser(request.user)
    if membership_id:
        membership = Membership.objects.filter(pk=membership_id).first()
        if not membership:
            return restStatus(request, False, error="does not exist")
    elif group_id:
        membership = Membership.objects.filter(group__pk=group_id, member=me).first()
        if not membership:
            if not me.is_staff:
                return restStatus(request, False, error="does not exist")
            group = Group.objects.filter(pk=group_id).last()
            membership = group.addMembership(me, "admin")
            membership.addPerm("admin")
    else:
        return restStatus(request, False, error="permision denied")


    if me.is_staff or membership.group.isMember(me):
        graph = request.DATA.get("graph", "basic")
        return restGet(request, membership, **Membership.getGraph(graph))
    return restStatus(request, False, error="permision denied")

@urlPOST (r'^legacy/group/invite/(?P<group_id>\d+)$')
@login_required
def legacy_inviteToGroup(request, group_id):
    # get the email for the person we are inviting
    me = request.member
    group = Group.objects.filter(pk=group_id).first()
    if not group:
        return restPermissionDenied(request)

    ms = group.getMembership(me)
    if not request.user.is_staff and (not ms or not ms.isManager()):
        return restPermissionDenied(request)

    email = request.DATA.get("email")
    uname = request.DATA.get("username")
    is_new = request.DATA.get("isnew")
    if not email and uname and "@" in uname:
        email = uname
        uname = uname.split("@")[0]
    elif not uname and email:
        if "@" not in email:
            uname = email
            email = None
        else:
            uname = email.split("@")[0]

    password = request.DATA.get("password")
    if password:
        if len(password) < 5:
            return restStatus(request, False, error="password must be atleast 5 characters")

    name = request.DATA.get("name")

    if not name:
        first_name = request.DATA.get('first_name')
        last_name = request.DATA.get('last_name')
        if first_name and last_name:
            name = "{0} {1}".format(first_name, last_name)
    elif ' ' in name:
        first_name = name.split(' ')[0]
        last_name = " ".join(name.split(' ')[1:])
    elif '.' in name:
        first_name = name.split('.')[0]
        last_name = name.split('.')[1]
    else:
        first_name = name
        last_name = ""

    # if "email" not in request.DATA:
    # 	return restStatus(request, False, error="requires invite email")

    if email and not helpers.isValidEmail(email):
        return restStatus(request, False, error="invalid email")
    elif not email and not name:
        return restStatus(request, False, error="invalid/missing data: name")
    elif not email:
        if not uname:
            email = "{0}@invalid.{1}.com".format(name.replace(" ", ""), group.name.replace(" ", ""))
        else:
            email ="{0}@invalid.{1}.com".format(uname, group.name.replace(" ", ""))

    if not request.user.is_staff:
        # verify me has permision to add people to group
        meship = group.getMembership(me)
        if not meship:
            return restPermissionDenied(request)

        if not meship.isManager():
            return restPermissionDenied(request)

    # now we need to see if the user exists already
    user = Member.objects.filter(username=uname).first()
    if is_new and user:
        return restStatus(request, False, error="user already exists")
    is_new = False
    if not user:
        if not password and not email:
            return restStatus(request, False, error="requires invite email")

        user = Member()
        user.set_username(uname)
        user.set_email(email)
        data = request.DATA.asDict()
        user.last_login = datetime.now()
        user.saveFromDict(request, request.DATA.asDict(), request.FILES, email=user.email, username=user.username, first_name=first_name, last_name=last_name)
        user.set_password(password)
        user.save()

        is_new = True

    # get permissions we want to grant
    perms = []
    role = request.DATA.get("role", "guest")
    for field in request.POST:
        if field.startswith("perms."):
            value = int(request.POST.get(field, 0))
            if value > 0:
                fields = field.split(".")
                perm = fields[1]
                if perm == "admin":
                    role = "admin"
                perms.append(perm)
    if group.isMember(user):
        return restStatus(request, False, error="already a member")
    new_ms = group.addMembership(user, role)
    # set state to invited
    new_ms.state = -10
    new_ms.save()
    if role not in perms:
        perms.append(role)

    for perm in perms:
        if new_ms.role == "guest":
            new_ms_role = perm
            new_ms.save()
        new_ms.addPerm(perm)

    if role in ["manager", "admin"]:
        # if not new we need to send them an email to accept the invite to the group
        message = request.DATA.get("message", "Join the team!")
        invite = UserInvite.send(me, email, group=group, user=user, message=message, is_new=is_new)
        if invite:
            return restGet(request, user, **Member.getGraph("default"))
        return restStatus(request, False, error="unkown error, our support team is looking into it!")
    return restGet(request, user, **Member.getGraph("default"))

@urlPOST (r'^invite')
@login_required
def inviteEmail(request):
    """
    | param: username = use the username as the lookup
    | param: email = use the email as the lookup

    | Return: status + error

    | Send an invitation to some to join
    """
    member = None
    if request.user.is_authenticated:
        member = Member.getByUser(request.user)

    if "email" not in request.DATA:
        return restStatus(request, False, error="missing email parameter");
    email = request.DATA.get("email")
    if "@" not in email:
        return restStatus(request, False, error="missing email parameter");

    obj, created = Invited.objects.get_or_create(email=email)
    if created:
        obj.member = member
        obj.save()

    return restStatus(request, True)

@urlPOST (r'^(?P<user_id>\d+)/follow$')
@urlPOST (r'^(?P<user_id>\d+)/follow/$')
@login_required
def doFollow(request, user_id):
    user = Member.objects.filter(pk=user_id).first()
    if user is None:
        return restStatus(request, False, error="user does not exist")
    request.user.member.follow(user)
    return restStatus(request, True)

@urlPOST (r'^(?P<user_id>\d+)/unfollow$')
@urlPOST (r'^(?P<user_id>\d+)/unfollow/$')
@login_required
def doUnfollow(request, user_id):
    user = Member.objects.filter(pk=user_id).first()
    if user is None:
        return restStatus(request, False, error="user does not exist")
    request.user.member.unfollow(user)
    return restStatus(request, True)

@urlPOST (r'^(?P<member_id>\d+)/feed$')
@urlPOST (r'^(?P<member_id>\d+)/feed/$')
@login_required
def saveFeed(request, member_id=None):
    if member_id is None:
        member_id = request.user.id
    member = Member.objects.filter(pk=member_id).first()
    if member is None:
        return restStatus(request, False, error="no such member")
    action = request.DATA.get("action", None)
    component = request.DATA.get("component", None)
    key = request.DATA.get("key", 0)
    if action and component:
        # (cls, owner, component, key, action, related_user)
        MemberFeed.log(member, None, component, key, action, request.user)
        return restStatus(request, True)
    return restStatus(request, False, error="requires action and component")



@urlGET (r'^membership/(?P<membership_id>\d+)/posts$')
@login_required
def getPosts(request, membership_id):
    me, group = Member.getMemberGroup(request)
    membership = Membership.objects.filter(pk=membership_id).first()
    if not membership:
        return restStatus(request, False, error="does not exist")
    if me.is_staff or membership.group.isMember(me):
        shares = membership.member.content_shares.filter(verified=True, content__group=membership.group)
        return restList(request, shares, **ContentShare.getGraph("default"))
    return restStatus(request, False, error="permision denied")







