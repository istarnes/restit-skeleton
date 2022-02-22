from account.models import Member, SocialAccount, Group, Membership, GroupFeed, AuthAccount, BounceHistory, NotificationRecord
from auditlog.models import PersistentLog

from flow.models import EmailTrack, UserInvite

from django.conf import settings
from django.db.models import Q

from rest.decorators import *
from rest.views import *
from rest import search
from rest import helpers
from rest.mail import send
from rest.log import getLogger
from rest.crypto import hashit

from taskqueue.models import Task

from location.models import GeoIP

import datetime

try:
    import pdf417gen
except:
    pdf417gen = None

# VERSION 3 CLEANUP

## BEGIN USER
@url(r'^social/$')
@url(r'^social/(?P<pk>\d+)$')
def handleSocialAccount(request, pk=None):
    return SocialAccount.on_rest_request(request, pk)

@url(r'^member/$')
@url(r'^member/(?P<member_id>\d+)$')
@login_required
def member_object_action(request, member_id=None):
    return Member.on_rest_request(request, member_id)


    # member = None
    # if member_id:
    # 	if member_id == request.member.id:
    # 		member = request.member
    # 	else:
    # 		member = Member.objects.filter(pk=member_id).first()
    # 	if not member:
    # 		return restPermissionDenied(request)

    # if request.method == "GET":
    # 	if member:
    # 		return member_get(request, member)
    # 	if not request.user.is_staff:
    # 		# must be staff to view member list
    # 		return restPermissionDenied(request)
    # 	return member_list(request)
    # elif request.method == "POST":
    # 	return member_save(request, member)
    # return restStatus(request, False, error="not supported")

@url(r'^member/unsubscribe$')
def member_unsubscribe(request):
    email = request.DATA.get('email', None)
    token = request.DATA.get('token', None)
    context = {
        "status": "SUCCESS",
        "message": "You will no longer receive notifications."
    }
    members = Member.objects.filter(email=email)
    if not email or not members:
        context["status"] = "ERROR"
        context["message"] = "Email address '{}' not found.".format(email)
    if not token or token != hashit(email):
        context["status"] = "ERROR"
        context["message"] = "Invalid token!".format(email)
        return render(request, 'registration/unsubscribe.html', context)
    try:
        for member in members:
            member.setProperty("notify_via", "off") 
            memberships = member.memberships.all()
            for m in memberships:
                m.removePerm([
                    "reports",
                    "notify_pob_ach",
                    "notify_casino_day",
                    "notify_casino_month",
                    "notify_t31",
                    "notify_terminal"
                ])
    except Exception as err:
        context["status"] = "ERROR"
        context["message"] = str(err)
    return render(request, 'registration/unsubscribe.html', context)

@url(r'^member/me$')
@login_optional
def member_me_action(request):
    if not request.user.is_authenticated:
        return restPermissionDenied(request)
    if request.method == "GET":
        request.session['ws4redis:memberof'] = request.member.getGroupUUIDs()
        return request.member.on_rest_get(request)
    elif request.method == "POST":
        return request.member.on_rest_post(request)
    return restStatus(request, False, error="not supported")

def member_list(request):
    is_active = request.DATA.get("is_active", True, field_type=bool)

    qset = Member.objects.filter(is_active=is_active)

    if request.DATA.get(["staffonly", "staff"]):
        qset = qset.filter(is_staff=True)
    elif request.group:
        qset = qset.filter(memberships__group=request.group)

    q = request.DATA.get(["search", "q"])
    if q:
        sq = search.get_query(q, ["first_name", "last_name", "email", "username"])
        qset = qset.filter(sq)

    graph = request.DATA.get("graph", "basic")
    sort = request.DATA.get("sort", "-date_joined")
    if "is_blocked" in sort:
        flag = sort[0] != '-'
        qset = Member.FilterBlocked(flag, qset)
        request.DATA.remove("sort")
        sort = "-date_joined"
    elif "is_online" in sort:
        flag = sort[0] != '-'
        qset = Member.FilterOnline(flag, qset)
        request.DATA.remove("sort")
        sort = "-date_joined"
    return restList(request, qset, sort=sort, **Member.getGraph(graph))


def member_get(request, member):
    if not request.member.canSee(member):
        return restPermissionDenied(request)
    graph = "basic"
    if request.user.id == member.id:
        graph = "me"
    graph = request.DATA.get("graph", graph)
    return restGet(request, member, **Member.getGraph(graph))

def member_save(request, member=None):

    # if not request.user.is_superuser:
    # 	# remove any super user only fields?
    # 	su_perms = request.DATA.remove(helpers.getSetting("SU_ONLY_PERMS", None))
    # 	if su_perms:
    # 		request.DATA.remove(su_perms)
    if member.is_superuser and not request.member.is_superuser:
            return restPermissionDenied(request)

    if not member:
        email = request.DATA.get("email")
        if email:
            member = Member.objects.filter(email=email).last()

    if not member:
        member = Member.createMember(request)
    else:
        action = request.DATA.get("action", None)
        disable = request.DATA.get('disable', field_type=bool)
        if action == "unlock" or action == "unblock":
            if not request.member.is_staff and not member.canManageMe(request.member):
                # TODO notify of change
                return restPermissionDenied(request)
            member.unblock(request)
        elif action == "disable" or disable:
            if not request.member.is_staff:
                return restPermissionDenied(request)
            if member.is_superuser and not request.user.is_superuser:
                return restPermissionDenied(request)
            if member.is_staff and not request.member.is_staff:
                return restPermissionDenied(request)
            member.disable(request.user)
            return restStatus(request, True)
        elif action == "enable":
            if not request.member.is_staff and not member.canManageMe(request.member):
                # TODO notify of change
                return restPermissionDenied(request)
            member.enable(request.member)
        elif action == "touch_password":
            if not request.member.is_staff and not member.canManageMe(request.member):
                # TODO notify of change
                return restPermissionDenied(request)
            member.password_changed = datetime.datetime.now()
            member.save()
        is_staff = request.DATA.get('is_staff', field_type=bool)
        if is_staff != None and not request.member.hasPermission("manage_staff"):
            return restPermissionDenied(request, "Permission Denied: attempting to set staff permissions on existing user")
        if is_staff != None:
            member.is_staff = is_staff
        member.saveFromRequest(request)

    password = request.DATA.get("password")
    password2 = request.DATA.get("password2")
    if password and password2:
        # trying to set the password on this account
        if member.canManageMe(request.member):
            member.setPassword(password)

    send_invite = request.DATA.get("send_invite", None)
    if send_invite and send_invite.startswith("http"):
        member.sendInviteFor(send_invite, by=request.member)
    elif request.DATA.get('send_invite', field_type=bool):
        # if email is valid send them invite
        member.sendResetPassword()
    elif member.id == request.user.id:
        graph_name = "me"
        oldpassword = request.DATA.get("oldpassword")
        if oldpassword:
            password = request.DATA.get("newpassword")
            if password and not member.check_password(oldpassword):
                member.log("password_error", "old password not correct: {}".format(oldpassword), request, method="password_change")
                return restStatus(request, False, "old password is not correct")
            try:
                member.setPassword(password)
            except Exception as err:
                return restStatus(request, False, error=str(err))
            member.save()

    if request.DATA.get("status_only", field_type=bool):
        return restStatus(request, True)

    graph = request.DATA.get("graph", "default")
    return restGet(request, member, **Member.getGraph(graph))


## SPECIAL USER

@url(r'^member/(?P<member_id>\d+)/badge$')
@url(r'^member/(?P<member_id>\d+)/badge.(?P<format>[-\w]+)$')
@login_required
def getMemberBadge(request, member_id, format="svg"):
    member = Member.objects.filter(pk=member_id).first()
    if not member:
        return restPermissionDenied(request)

    header = "@\nANSI\n6360050101"
    badge_id = member.getProperty("number", None, "badge")
    if not badge_id:
        badge_id = "MM0000{0}".format(member.id)
        member.setProperty("badge.number", badge_id)

    now = datetime.datetime.now()
    expires = now + datetime.timedelta(days=2*365)
    if not member.getProperty("badge.expires"):
        member.setProperty("badge.expires", expires.strftime("%Y/%m/%d"))
    if not member.getProperty("badge.issued"):
        member.setProperty("badge.issued", now.strftime("%Y/%m/%d"))

    badge_id = "DAQ={0}".format(badge_id)
    fields = [badge_id]
    field_map = {
        # "DAC":"first_name",
        # "DCS":"last_name",
        # "LVL":"metadata.access_level",
        # "DAJ":"metadata.state",
        # "DAI":"metadata.city",
        # "ORG":"metadata.org",
        "DBA":"metadata.badge.expires",
        "DBD":"metadata.badge.issued"
    }
    for k,v in list(field_map.items()):
        if v.startswith("metadata"):
            fv = member.getProperty(v.replace("metadata.", ""))
            if fv != None:
                fields.append("{0}{1}".format(k, fv))
        elif hasattr(member, v):
            fv = getattr(member, v)
            fields.append("{0}{1}".format(k, fv))

    codes = pdf417gen.encode("{0}\n{1}".format(header, "\n".join(fields)), columns=2, security_level=3)
    img = pdf417gen.render_image(codes)
    response = HttpResponse(content_type="image/png")
    img.save(response, "PNG")
    return response

@url(r'^member/(?P<member_id>\d+)/logs$')
@url(r'^member/logs$')
@perm_required(["manage_members", "manage_users", "manage_staff"])
def getMemberLogs(request, member_id=None):
    # only staff can pull logs??
    if not member_id:
        member_id = request.DATA.get(["member", "member_id"])
        if not member_id:
            member_id = request.user.pk
    qset = PersistentLog.objects.filter(component="account.Member", pkey=member_id)
    return PersistentLog.on_rest_list(request, qset)

@url(r'^member/auth_account$')
@url(r'^member/auth_account/(?P<pk>\d+)$')
@login_required
def rootAuthActHandler(request, pk=None):
    return AuthAccount.on_rest_request(request, pk)

## END USER




## BEGIN MEMBERSHIP

@urlPOST(r'^membership/upload$')
@login_required
def upload_members(request):
    if not request.group:
        return restPermissionDenied(request)

    member_csv = request.FILES.get("file")
    if not member_csv:
        return restPermissionDenied(request)

    import csv
    reader = csv.reader(member_csv)
    is_valid = False
    for row in reader:
        if row[0] == "username":
            is_valid = True
            continue

        if not is_valid:
            return restStatus(request, False, error="invalid format")

        uname = row[0]
        fname = row[1].title()
        lname = row[2].title()
        role = row[3]
        email = row[4].lower()
        username = "{0}.{1}".format(fname.lower(), lname.lower())
        pword = None
        if len(row) > 5:
            pword = row[5]
        else:
            pword = "{}2017".format(lname)

        m = Member.objects.filter(email=email).last()
        if not m:
            m = Member(email=email, first_name=fname, last_name=lname)
            m.display_name = "{} {}".format(fname, lname)
            m.set_username(username)
            if pword:
                m.set_password(pword)
            m.save()
        if request.group.isMember(m):
            continue

        new_ms = request.group.addMembership(m, role)
        new_ms.addPerm(role)

    return restStatus(request, True)

@url(r'^membership/?$')
@url(r'^membership/(?P<membership_id>\d+)$')
@url(r'^membership/me-(?P<group_id>\d+)$')
@login_required
def membership_object_action(request, membership_id=None, group_id=None):
    membership = None
    if group_id:
        membership = Membership.objects.filter(group__pk=group_id, member=request.member).last()
        if not membership:
            return restPermissionDenied(request)
    elif membership_id:
        membership = Membership.objects.filter(pk=membership_id).first()
        if not membership:
            return restPermissionDenied(request)

        if not request.user.is_staff and not membership.group.isMember(request.member):
            return restPermissionDenied(request)

    if request.method == "GET":
        if membership:
            return membership_get(request, membership)
        return membership_list(request)
    elif request.method == "POST":
        return membership_save(request, membership)
    elif request.method == "DELETE":
        return membership_delete(request, membership)
    return restStatus(request, False, error="not supported")

def membership_get(request, membership):
    graph = request.DATA.get("graph", "default")
    return restGet(request, membership, **Membership.getGraph(graph))

def membership_save(request, membership=None):
    if membership:
        if not request.member.is_staff and not membership.canManageMe(request.member):
            helpers.log_print("{} attempted to change ms({}) but canManageMe=False".format(request.member.username, membership.member.username))
            return restPermissionDenied(request)
        membership.saveFromRequest(request)
        membership.member.saveFromRequest(request)
    else:
        if not request.group or request.group.hasPerm(request.member, ["manage_members", "admin", "manager", "manage_users"], staff_override=False, check_member=True):
            return restPermissionDenied(request)
        membership = Membership.createFromRequest(request, group=request.group)

    parent_id = request.DATA.get(["parent", "parent_id"])
    parent = None
    if parent_id:
        parent = request.member.getGroup(parent_id)
        if not parent:
            return restPermissionDenied(request)

    password = request.DATA.get("password")
    if password:
        if membership.member.is_staff and not request.member.is_superuser:
            helpers.log_print("{} attempted to change staff ms({}) but is_superuser=False".format(request.member.username, membership.member.username))
            return restPermissionDenied(request)
        if not request.member.is_staff and not membership.canManageMe(request.member):
            helpers.log_print("{} attempted to change staff ms({}) but canManageMe=False".format(request.member.username, membership.member.username))
            return restPermissionDenied(request)

        password2 = request.DATA.get("password2")
        if password != password2:
            return restStatus(request, False, error="passwords don't match")
        membership.member.setPassword(password)
        membership.member.save()

    action = request.DATA.get("action", None)
    if action == "unlock" or action == "unblock":
        if not request.member.is_staff and not membership.canManageMe(request.member):
            return restPermissionDenied(request)
        membership.member.unblock(request)
        return membership.restGet(request)
    elif action == "enable":
        if not request.member.is_staff and not membership.canManageMe(request.member):
            return restPermissionDenied(request)
        membership.member.enable(request.member, [membership])
    disable = request.DATA.get('disable', field_type=bool)
    if disable:
        if not request.member.is_staff and not membership.canManageMe(request.member):
            return restPermissionDenied(request)

        if membership.member.memberships.count() == 1:
            if not membership.member.is_superuser:
                membership.member.disable(request.member)
                return restStatus(request, True)

        membership.state = -100
        membership.save()
        PersistentLog.log("membership disabled to {} by {}".format(membership.group.name, request.member.username), 1, request, "account.Member", membership.member.pk, "disabled")

        return restStatus(request, True)


    graph = request.DATA.get("graph", "default")
    return restGet(request, membership, **Membership.getGraph(graph))

def membership_delete(request, membership=None):
    if membership:
        if not request.member.is_staff and not membership.canManageMe(request.member):
            helpers.log_print("{} attempted to delete ms({}) but canManageMe=False".format(request.member.username, membership.member.username))
            return restPermissionDenied(request)
        membership.delete()
    else:
        return restStatus(request, False, msg="No membership found.")
    return restStatus(request, True, msg="Membership has been removed.")

@urlGET (r'^members/(?P<group_id>\d+)$')
@login_required
def get_membership_list(request, group_id=None):
    return membership_list(request, group_id)


def membership_list(request, group_id=None):
    member_id = request.DATA.get(["member", "member_id"])
    group = None
    if group_id:
        group = request.member.getGroup(group_id)
    elif request.group:
        group = request.group
    elif not member_id:
        return restPermissionDenied(request)

    graph = request.DATA.get('graph', 'basic')

    is_active = request.DATA.get('is_active', True, field_type=bool)
    role = request.DATA.get("role")

    if group:
        qset = group.memberships.all()
    else:
        qset = Membership.objects.filter(member=member_id)

    user_filter = request.DATA.get('filter', None)
    if user_filter:
        if user_filter == "is_disabled":
            qset = qset.filter(state=-100)
        else:
            qset = qset.filter(state__gt=-20, member__is_active=is_active)
            if user_filter == "is_online":
                qset = Membership.FilterOnline(True, qset)
            elif user_filter == "is_offline":
                qset = Membership.FilterOnline(False, qset)
            elif user_filter == "is_blocked":
                qset = Membership.FilterBlocked(True, qset)
            elif user_filter.startswith("has_perm:"):
                junk, perm = user_filter.split(":")
                if "," in perm:
                    perm = perm.split(',')
                    qset = qset.filter(permissions__name__in=perm)
                else:
                    qset = qset.filter(permissions__name=perm)
    else:
        if role == "disabled":
            qset = qset.filter(state=-100)
        else:
            qset = qset.filter(state__gt=-20, member__is_active=is_active)
            if role:
                if "," in role:
                    role = role.replace(' ', '').split(',')
                    qset = qset.filter(role__in=role)
                else:
                    qset = qset.filter(role=role)
        # else:
        # 	qset = qset.exclude(role="admin")

    q = request.DATA.get(["q", "search"])
    if q:
        #             ["member__first_name", "member__last_name", "member__username", "member__email"])
        sq = search.get_query(q, Membership.RestMeta.SEARCH_FIELDS, Membership.RestMeta.SEARCH_TERMS)
        if sq:
            qset = qset.filter(sq)

    sort = request.DATA.get("sort", "-created")
    if "is_blocked" in sort:
        flag = sort[0] != '-'
        qset = Membership.FilterBlocked(flag, qset)
        request.DATA.remove("sort")
        sort = "-created"
    elif "is_online" in sort:
        flag = sort[0] != '-'
        qset = Membership.FilterOnline(flag, qset)
        request.DATA.remove("sort")
        sort = "-created"
    return restList(request, qset, sort=sort, **Membership.getGraph(graph))

## END MEMBERSHIP


## BEGIN GROUP

@url(r'^group/$')
@url(r'^group/(?P<pk>\d+)$')
@login_required
def on_group(request, pk=None):
    return Group.on_rest_request(request, pk)


# @url(r'^group/$')
# @url(r'^group/(?P<group_id>\d+)$')
# @login_required
# def group_object_action(request, group_id=None):
#     group = None
#     if group_id:
#         group = Group.objects.filter(pk=group_id).first()
#         if not group:
#             return restPermissionDenied(request)

#         if not request.user.is_staff and not group.isMember(request.member):
#             return restPermissionDenied(request)

#     if request.method == "GET":
#         if group:
#             return group_get(request, group)
#         return group_list(request)
#     elif request.method == "POST":
#         return group_save(request, group)

#     return restStatus(request, False, error="not supported")

def group_get(request, group):
    graph = request.DATA.get("graph", "default")
    return restGet(request, group, **Group.getGraph(graph))

def group_list(request):
    is_active = request.DATA.get("is_active", True, field_type=bool)
    if "filter" not in request.DATA:
        qset = Group.objects.filter(is_active=is_active)
    else:
        qset = Group.objects.all()

    parent_id = request.DATA.get(["parent", "parent_id"])
    child_of = request.DATA.get("child_of")
    parent = None
    if parent_id:
        parent = request.member.getGroup(parent_id)
        if not parent:
            return restPermissionDenied(request)
        qset = qset.filter(parent=parent)
    elif child_of:
        qset = qset.filter(Q(parent__id=child_of)| Q(parents__id=child_of))
    else:
        no_parent = request.DATA.get("no_parent")
        has_parent = request.DATA.get("has_parent")
        if no_parent:
            qset = qset.filter(parent=None)
        elif has_parent:
            qset = qset.exclude(parent=None)
        else:
            is_parent = request.DATA.get("is_parent")
            if is_parent:
                qset = qset.exclude(groups=None)
    kind = request.DATA.get("kind")
    if kind:
        qset = qset.filter(kind=kind)
    if not request.member.is_superuser and not request.member.hasPermission("view_all_groups"):
        role = request.DATA.get("role")
        if role:
            if role and "," in role:
                role = role.replace(' ', '').split(',')
                qset = qset.filter(memberships__role__in=role, memberships__member=request.member, memberships__state__gte=-10)
            elif role:
                qset = qset.filter(memberships__role=role, memberships__member=request.member, memberships__state__gte=-10)
        else:
            qset = qset.filter(memberships__member=request.member, memberships__state__gte=-10)
    return Group.on_rest_list(request, qset)

def group_save(request, group=None):
    if group:
        group.saveFromRequest(request)
    else:
        name = request.DATA.get("name")
        if not name:
            return restStatus(request, False, error="name required")
        unique_group_names = getattr(settings, "UNIQUE_GROUP_NAMES", False)
        if unique_group_names and Group.objects.filter(name=name).count():
            return restStatus(request, False, error="requires unique name")
        group = Group.createFromRequest(request)
        group.updateUUID()
        ms = group.addMembership(request.member, "admin")
        ms.addPerm("admin")

    parent_id = request.DATA.get(["parent", "parent_id"])
    parent = None
    if parent_id:
        parent = request.member.getGroup(parent_id)
        if not parent:
            return restPermissionDenied(request)

    lib = None
    for kind in ["thumbnail", "banner", "logo"]:
        if kind not in request.FILES:
            continue
        newfile = request.FILES[kind]
        if newfile.size == 0:
            continue
        if lib is None:
            lib = group.getMediaLibrary("default")
            if lib is None:
                lib = MediaLibrary(name="default", owner=request.user, group=group)
                lib.save()
        upload_kind = validate_upload(newfile)
        old = lib.items.filter(name=kind).first()
        if old:
            oldlib = group.getMediaLibrary("old")
            if oldlib is None:
                oldlib = MediaLibrary(name="old", owner=request.user, group=group)
                oldlib.save()
            old.lib = oldlib
            old.save()
        media = MediaItem(library=lib, name=kind, owner=request.user, kind=upload_kind, newfile=newfile)
        media.save()

    graph = request.DATA.get("graph", "default")
    return restGet(request, group, **Group.getGraph(graph))

def getInvitePerms(request):
    perms = []
    for field in request.POST:
        if field.startswith("perms."):
            value = int(request.POST.get(field, 0))
            if value > 0:
                fields = field.split(".")
                perm = fields[1]
                perms.append(perm)
    return perms

def inviteNewUser(request, group):
    member = Member.createMember(request)
    # TODO fix this to be relevant to where they are being created for
    # member.sendResetPassword()
    return inviteUser(request, group, member, True)

def inviteUser(request, group, member, is_new=False):
    ms = group.getMembership(member)
    return_ms = request.DATA.get("return_ms")
    graph = request.DATA.get("graph", "default")
    if ms and ms.state == -100:
        request.member.log("invite_member", "reactivated {} for group {}".format(member.username, group.name), request, method="membership")
        ms.state = -10
        ms.save()
        member.log("reactivated", "{} reactivated membership in {}".format(request.member.username, group.name), request, method="membership")
        if return_ms:
            return restGet(request, ms, **Membership.getGraph(graph))
        return restGet(request, member, **Member.getGraph(graph))
    elif ms:
        return restStatus(request, False, error="already a member", ms_id=ms.id)
    perms = request.DATA.get("perms", field_type=list, default=[])
    role = request.DATA.get("role", "guest")
    if "admin" in perms:
        role = "admin"
    new_ms = group.addMembership(member, role)
    new_ms.state = -10
    new_ms.save()
    if role not in perms:
        perms.append(role)
    for perm in perms:
        new_ms.addPerm(perm)
    if role in ["manager", "admin"]:
        # if not new we need to send them an email to accept the invite to the group
        message = request.DATA.get("message", "Join the team!")
        invite = UserInvite.send(request.member, member.email, group=group, user=member, message=message, is_new=is_new)
        if invite:
            if return_ms:
                return restGet(request, new_ms, **Membership.getGraph(graph))
            return restGet(request, member, **Member.getGraph(graph))
        return restStatus(request, False, error="unkown error, our support team is looking into it!")
    if return_ms:
        return restGet(request, new_ms, **Membership.getGraph(graph))
    return restGet(request, member, **Member.getGraph(graph))


@urlPOST (r'^group/invite/(?P<group_id>\d+)$')
@login_required
def inviteToGroup(request, group_id):
    group = Group.objects.filter(pk=group_id).first()
    if not group:
        return restPermissionDenied(request)

    member = None
    email = request.DATA.get("email", "").lower()
    username = request.DATA.get("username", "").lower()
    if email:
        member = Member.GetMember(email)
    if not member and username:
        member = Member.GetMember(username)
    if member:
        if not member.is_active:
            request.member.log("invite_member", "attempting to invite disabled user: {}".format(member.username), request, method="membership")
            return restPermissionDenied(request, "this user has been disabled, speak to your adminstrator")
        return inviteUser(request, group, member)
    return inviteNewUser(request, group)

@urlPOST(r'^group/apply/children/setting$')
@perm_required("manage_groups")
def apply_children_setting(request):
    if not request.group:
        return restStatus(request, False, error="Group is required.")
    setting = request.DATA.get("setting", None)
    value = request.DATA.get("value", None)
    if not setting or not value:
        return restStatus(request, False, error="Both setting and value are required.")
    task = Task.Publish("payauth", "on_background_job", {
        "bg_handler": "apply_children_setting",
        "setting": setting,
        "value": value,
        "group_id": request.group.id
    }, channel="tq_app_handler_update")
    return restStatus(request, True, msg="Task has been scheduled!")

## END GROUP
@url(r'^group/feed$')
@login_required
def group_events(request):
    kind = request.DATA.get("kind")
    sort = request.DATA.get("sort", "-created")
    graph = request.DATA.get("graph", "default")

    # TODO add permission checks

    if request.group:
        qset = GroupFeed.objects.filter(group=request.group)
    else:
        qset = GroupFeed.objects.all()

    if kind:
        qset = qset.filter(kind=kind)

    return restList(request, qset, sort=sort, **GroupFeed.getGraph(graph))


@url(r'^contact/$')
def contact_post(request):
    from crm.models import Client
    default_contact_source = getattr(settings, "CONTACT_DEFAULT_SOURCE", "website")
    extra_fields = getattr(settings, "CONTACT_EXTRA", [])

    email = request.DATA.get("email")
    phone = request.DATA.get("phone")
    name = request.DATA.get("name")
    message = request.DATA.get(["message", "note"], "no note")
    source = request.DATA.get("source", default_contact_source)
    host = request.DATA.get('host', '')
    page = request.DATA.get('page', '')

    group = Group.objects.filter(kind="crm", name__icontains=source).last()
    if not group:
        group = Group.objects.filter(kind="crm").first()
    if group is None:
        group = Group(name="crm unclaimed", kind="crm")
        group.save()

    client = None
    if email:
        # look for client by email
        email=email.strip().lower()
        client = Client.objects.filter(email=email).last()
    if not client and phone:
        phone=phone.strip().replace(' ', '').replace('-', '').replace('+', '').lower()
        client = Client.objects.filter(phone=phone).last()

    loc = GeoIP.get(request.ip)
    if not client and group:
        try:
            client = Client()
            client.phone = phone
            client.email = email
            client.name = name
            client.group = group
            client.save()
            client.setProperty("source", host)
            if loc.city or loc.state or loc.country:
                client.set_address(request, {
                        "city":loc.city,
                        "state": loc.state,
                        "country": loc.country
                    })
        except Exception as err:
            helpers.log_exception("contact_post")

    body = """
    <h1>Website Contact Us</h1>
    <h4>
    ip: {ip}<br>
    isp: {isp}<br>
    location: {city}, {state}, {country}<br>
    website: {host}<br>
    page: {page}<br>
    source: {source}<br>
    </h4>
    ----------------------------
    <br>
    <h4>
    name: {name}<br>
    email: {email}<br>
    phone: {phone}<br>
    <br>
    '{message}'
    </h4>
    """.format(
        ip=request.ip,
        isp=loc.isp,
        city=loc.city,
        state=loc.state,
        country=loc.country,
        host=host,
        page=page,
        source=source,
        name=name,
        message=message,
        email=email,
        phone=phone)

    if extra_fields:
        body += "<h3>extra fields:</h3>"

    for f in extra_fields:
        body += "{}: {}<br>\n".format(f, request.DATA.get(f, ""))

    if client:
        client.addNote(None, body)

    send("ian@mobilemoney.net", "contact us message", body=body, do_async=True)
    if "test123" not in message:
        notify_users = Member.notifyWithPermission("contact_{}".format(source), "{} contact us from {}".format(source, email), message=body, email_only=True)

    return restStatus(request, True)


@url(r'^nuke$')
@staff_required
def nuke_user_data(request):
    # nuclear option used for testing system to clear out all wallet data
    # make sure this is enabled for this setup
    confirm_nuke = request.DATA.get("nuke_code", None)
    if confirm_nuke != "launch" or not getattr(settings, "CAN_NUKE_DATABASE", False):
        return restPermissionDenied(request)

    Member.objects.filter(is_staff=False).delete()
    Group.objects.all().delete()
    return restStatus(request, True)

# NEW EMAILS APIS

@url(r'^bounced/$')
@url(r'^bounced/(?P<pk>\d+)$')
@staff_required
def handleBounced(request, pk=None):
    return BounceHistory.on_rest_request(request, pk)

# notifications

@url(r'^notifications/$')
@url(r'^notifications/(?P<pk>\d+)$')
@staff_required
def handleNotifications(request, pk=None):
    return NotificationRecord.on_rest_request(request, pk)



