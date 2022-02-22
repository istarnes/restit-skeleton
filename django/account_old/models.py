from django.db import models
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.sessions.models import Session
from django.db.models import Avg, Max, Min, Count, Sum, Q
from social_django.utils import load_strategy

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth.models import Permission as MasterPermission
from django.contrib.auth.hashers import (
    check_password, is_password_usable, make_password,
)

from django.conf import settings

from rest.middleware import get_request
from rest.models import RestModel, MetaDataModel, MetaDataBase, RestValidationError, PermisionDeniedException
from rest import helpers as rest_helpers
from rest import RemoteEvents
from rest.views import restPermissionDenied
from rest.crypto import hashit
from django.utils.http import int_to_base36
from hashids import Hashids

import string
from datetime import datetime, timedelta
import time
import pytz
import re
import hashlib
import uuid

from rest import mail as rest_mail
from account import socialapi

from django.db import models
from django.contrib.auth.models import AbstractUser

from social_django.models import UserSocialAuth

from auditlog.models import PersistentLog
from sessionlog.models import SessionLog

try:
    import pyotp
except Exception:
    pyotp = None

# we need bigger usernames, in particular for RemoteMember
AbstractUser._meta.get_field('username').max_length = 128

class User(AbstractUser, RestModel):
    class Meta:
        db_table = 'auth_user'

    class RestMeta:
        NO_SHOW_FIELDS = ["password"]

    def getMember(self):
        return Member.getByUser(self)

    def getGroups(self):
        return Group.objects.filter(memberships__member=self, memberships__state__gte=-10).distinct()

    def getGroupIDs(self):
        return self.getGroups().values_list("pk", flat=True)

    def getGroupUUIDs(self):
        return self.getGroups().values_list("uuid", flat=True)

    def log(self, action, message, request=None, group=None, path=None, method=None):
        # message, level=0, request=None, component=None, pkey=None, action=None, group=None, path=None, method=None
        component = "account.Member"
        pkey = self.id
        PersistentLog.log(message=message, level=1, action=action, request=request, component=component, pkey=pkey, group=group, path=path, method=method)

    @staticmethod
    def getMemberGroup(request, get_default=False, get_session=True):
        if request.user.is_anonymous:
            return None, None
        member = Member.getByUser(request.user)
        group_id =  request.session.get("group_id")
        gid = request.DATA.get(["group_id", "group"])
        if not gid and get_session:
            gid = group_id
        group = None
        if hasattr(request, "group"):
            group = request.group
        if gid:
            group = member.getGroup(gid)
        if not group and get_default:
            group = member.getDefaultGroup()

        member.touchActivity()

        if not group:
            return member, None

        if group.id != group_id:
            request.session["group_id"] = group.id
        return member, group


class RemoteMember(User):
    """
    Used for remote authentication.  This user exists in another system.
    """
    remote_id = models.IntegerField(db_index=True)
    remote_host = models.CharField(db_index=True, max_length=128)
    def update(self, **kwargs):
        self.__dict__.update(kwargs)

    def is_authenticated(self):
        return True

    def hasPermission(self, perm):
        return self.hasPerm(self, perm)

    def hasPerm(self, perm):
        if not self.metadata:
            return False
        perms = self.metadata.get("permissions", {})
        if isinstance(perm, list):
            for i in perm:
                if self.hasPerm(i):
                    return True
            return False
        return int(perms.get(perm, 0)) > 0

    def getMembershipFor(self, group_id):
        for ms in self.memberships.filter(state__gte=-10):
            gid = rest_helpers.getValueForKeys(ms, "group.id", None)
            if gid == group_id:
                return rest_helpers.UberDict.fromdict(ms)
        return None

    def isMemberOf(self, group_id):
        ms = self.getMembershipFor(group_id)
        if not ms:
            return False
        return ms.state > -11

    def hasGroupPerm(self, group_id, perm):
        if group_id is None:
            return False
        if not isinstance(group_id, int) and getattr(group_id, "id"):
            group_id = group_id.id

        ms = self.getMembershipFor(group_id)
        if not ms or ms.state < -10:
            return False
        return perm in ms.perms


class Member(User, RestModel, MetaDataModel):
    """
    Member information -- registered users account details
    """
    class RestMeta:
        NO_SHOW_FIELDS = ["password"]
        SEARCH_FIELDS = ["username", "email", "first_name", "last_name"]
        VIEW_PERMS = ["is_staff"]
        # note the | will check collection parameter...
        #	trailing "." will check if the collection has the key set to true
        SEARCH_TERMS = ["username", "email",
            "first_name", "last_name",
            "last_activity#datetime", "date_joined#datetime",
            "is_staff",
            ("notify_via", "properties|notify_via"),
            ("phone", "properties|phone"),
            ("perms", "properties|permissions.")]
        UNIQUE_LOOKUP = ["username", "email"]
        METADATA_FIELD_PROPERTIES = getattr(settings, "USER_METADATA_PROPERTIES", None)

        GRAPHS = {
            "simple": {
                "fields":[
                    'id',
                    ('get_full_name', 'full_name'),
                    'first_name',
                    'last_name',
                    'initials',
                    'username',
                    'requires_topt'
                ]
            },
            "base": {
                "fields":[
                    'uuid',
                    'display_name',
                    ('get_full_name', 'full_name'),
                    'first_name',
                    'last_name',
                    'initials',
                    'username',
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'requires_topt',
                    'last_login',
                    'last_activity',
                    ('date_joined', 'created'),
                    ("hasLoggedIn", "has_logged_in"),
                    'thumbnail',
                    'profile_image',
                    'has_topt'
                ]
            },
            "basic": {
                "fields":[
                    'id',
                    'is_online',
                    'is_blocked',
                    'email',
                ],
                "graphs":{
                    "self":"base",
                },
            },
            "default": {
                "graphs":{
                    "self":"base",
                    "groups":"basic"
                }
            },
            "detailed": {
                "extra": ["metadata", "password_expires_in"],
                "graphs": {
                    "self":"basic",
                    "groups":"basic"
                }
            },
            "me": {
                "extra": [("getSessionID", "session_key")],
                "graphs": {
                    "self":"detailed",
                }
            },
            "rauth":{
                "extra": ["metadata"],
                "graphs": {
                    "self":"basic",
                    "memberships": "rauth"
                }
            },
            "abstract": {
                "fields":[
                    ('uuid', 'id'),
                    'username',
                    ('get_full_name', 'name'),
                ],
            },
        }

    uuid = models.CharField(db_index=True, max_length=64, blank=True, default="")

    modified = models.DateTimeField(auto_now=True)
    default_membership = models.ForeignKey("Membership", related_name="+", blank=True, null=True, default=None, on_delete=models.CASCADE)

    invite_token = models.CharField(max_length=64, blank=True, null=True, default=None, db_index=True)
    picture = models.ForeignKey("medialib.MediaItem", blank=True, null=True, help_text="Profile picture", related_name='+', on_delete=models.CASCADE)
    display_name = models.CharField(max_length=64, blank=True, null=True, default=None)

    password_changed = models.DateTimeField(blank=True, null=True, default=None)
    last_activity = models.DateTimeField(blank=True, null=True, default=None)
    requires_topt = models.BooleanField(blank=True, null=True, default=False)

    @property
    def initials(self):
        if self.first_name and self.last_name:
            return "{}{}".format(self.first_name[0], self.last_name[0])
        return None

    @property
    def is_online(self):
        return self.activeConnections()

    @property
    def is_blocked(self):
        when = RemoteEvents.hget("users:blocked:username", self.username)
        if not when:
            return False
        # check if still blocked
        now = time.time()
        if now - float(when) > settings.LOCK_TIME:
            self.unblock()
            return False
        return True

    @property
    def has_topt(self):
        token = self.getProperty("totp_token", category="secrets", default=None)
        return token is not None

    @property
    def password_expires_in(self):
        # this is returned in hours
        if self.password_changed is None:
            self.password_changed = datetime.now()
            self.save()
        days = (datetime.now() - self.password_changed).days
        return settings.PASSWORD_EXPIRES_DAYS - days

    def on_permission_change(self, key, value, old_value, category):
        # we want to log both the person changing permissions
        # and those being changed
        request = RestModel.getActiveRequest()
        perm = key
        reason = ""

        if "reason" in request.DATA:
            reason = request.DATA.get("reason").strip()

        if request.member:
            if value in [None, 0, '0']:
                self.log("remove_perm", "{} removed perm {}; {}".format(request.user.username, perm, reason), method="permissions")
                request.member.log("removed_perm", "removed perm {} for {}; {}".format(perm, self.username, reason), method="permissions")
            else:
                self.log("add_perm", "{} added perm {}; {}".format(request.user.username, perm, reason), method="permissions")
                request.member.log("gave_perm", "gave perm {} for {}; ".format(perm, self.username, reason), method="permissions")
        else:
            if value in [None, 0, '0']:
                self.log("remove_perm", "system removed perm {}".format(perm), method="permissions")
            else:
                self.log("add_perm", "system added perm {}".format(perm), method="permissions")

    def touchActivity(self, force=False, last_login=False):
        is_dirty = False
        update_last_activity = datetime.now() - timedelta(minutes=5)
        if force or not self.last_activity or (self.last_activity and self.last_activity < update_last_activity):
            self.last_activity = datetime.now()
            is_dirty = True
        if last_login:
            update_last_login = datetime.now() - timedelta(hours=1)
            if not self.last_login or (self.last_login and self.last_login < update_last_login):
                self.last_login = datetime.now()
                self.last_activity = self.last_login
                is_dirty = True
        if is_dirty:
            self.save()

    def isLoggedIn(self):
        return self.activeConnections()

    def recordFailedLogin(self, request):
        c = RemoteEvents.hincrby("users:failed:username", self.username, 1)
        if c >= settings.LOCK_PASSWORD_ATTEMPTS-1:
            self.block("multiple incorrect password attempts", request=request)
        c = RemoteEvents.hincrby("users:failed:ip", request.ip, 1)

    def recordSuccessLogin(self, request):
        RemoteEvents.hdel("users:failed:username", self.username)
        RemoteEvents.hdel("users:failed:ip", request.ip)

    def hasPasswordExpired(self):
        now = datetime.now()
        if self.password_changed is None:
            self.password_changed = now
            self.save()
        return now - self.password_changed > timedelta(days=settings.PASSWORD_EXPIRES_DAYS)

    def login(self, password=None, request=None):
        if not self.is_active or self.is_blocked:
            return False
        # can force login
        if not request:
            request = get_request()
        if password:
            if not self.checkPassword(password):
                # invalid password
                self.recordFailedLogin(request)
                return False
            else:
                self.recordSuccessLogin(request)
        self.user_ptr.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(request, self.user_ptr)
        self.locateByIP(request.ip)
        return True

    def getActiveSessions(self):
        return SessionLog.objects.filter(user__id=self.pk, is_closed=False)

    def getSessionCount(self):
        return self.getActiveSessions().count()

    def logout(self, request=None, all_sessions=False, older_then=None):
        if not request:
            request = get_request()
        if request and request.member == self:
            auth_logout(request)
        else:
            qset = self.getActiveSessions()
            if older_then:
                age = datetime.now() - timedelta(days=older_then)
                qset = qset.filter(created__lte=age)
            for slog in qset:
                slog.logout()

    # time based one time passwords / GOOGLE Authenticator
    def totp_getSecret(self, reset=False):
        token = self.getProperty("totp_token", category="secrets", default=None)
        if token is None or reset:
            token = pyotp.random_base32()
            self.setProperty("totp_token", token, category="secrets")
        return token

    def totp_getURI(self):
        # this should only be used one time during setup
        token = self.totp_getSecret(reset=True)
        totp = pyotp.TOTP(token)
        return totp.provisioning_uri(name=self.username, issuer_name=settings.SITE_LABEL)

    def totp_verify(self, code, window=1):
        token = self.totp_getSecret()
        totp = pyotp.TOTP(token)
        return totp.verify(code, valid_window=window)

    def block(self, reason, request=None):
        if not request:
            request = get_request()
        PersistentLog.log("account blocked, {}".format(reason), 1, request, "account.Member", self.pk, "blocked")
        RemoteEvents.hset("users:blocked:username", self.username, time.time())

    def unblock(self, request=None):
        if not request:
            request = get_request()
        if request and request.user.is_authenticated:
            who = request.user.username
        else:
            who = "time"
        PersistentLog.log("account unblocked by {}".format(who), 1, request, "account.Member", self.pk, "unblocked")
        RemoteEvents.hdel("users:blocked:username", self.username)
        RemoteEvents.hdel("users:failed:username", self.username)

    def checkPassword(self, password):
        return self.check_password(password)

    def sendChangeEvent(self, component, component_id, name="user.change", custom=None):
        if not custom:
            custom = {}
        custom["member_id"] = self.id
        RemoteEvents.sendToUser(self,
            name,
            component=component,
            component_id=component_id,
            custom=custom)

    @staticmethod
    def RecordInvalidLogin(request, username=None):
        # this records events when a username doesn't even exist
        if not username:
            username = request.DATA.get("username", None)
        if username:
            RemoteEvents.hset("users:failed:username", username, 0)

    @staticmethod
    def FilterOnline(is_online, qset):
        ids = list(RemoteEvents.smembers("users:online"))
        if is_online:
            qset = qset.filter(pk__in=ids)
        else:
            qset = qset.exclude(pk__in=ids)
        return qset

    @staticmethod
    def FilterBlocked(is_blocked, qset):
        ids = list(RemoteEvents.hgetall("users:blocked:username"))
        if is_blocked:
            qset = qset.filter(username__in=ids)
        else:
            qset = qset.exclude(username__in=ids)
        return qset

    @staticmethod
    def GetInvalidLoginCount(request):
        # this returns the number of invalid logins for a IP or username
        if not username:
            username = request.DATA.get("username", None)
        if username:
            cu = RemoteEvents.hget("users:failed:username", username, 0)
        else:
            cu = 0
        ci = RemoteEvents.hget("users:failed:ip", request.ip, 0)
        return max(ci, cu)

    def activeConnections(self):
        c = RemoteEvents.hget("users:online:connections", self.id)
        if c:
            return int(c)
        return 0

    def hasLoggedIn(self):
        if not self.last_login or not self.date_joined:
            return False

        if (self.last_login-self.date_joined).total_seconds() > 2:
            return self.has_usable_password() or self.social_auth.count()
        return False

    def updateUUID(self):
        self.uuid = Hashids().encrypt(self.id)
        self.save()

    def getSessionID(self, request=None):
        if not request:
            request = get_request()
        if request:
            return request.session.session_key

    def getMediaLibrary(self, name, create=True):
        MediaLibrary = RestModel.restGetModel("medialib", "MediaLibrary")
        lib = MediaLibrary.objects.filter(owner=self, name="User Avatars").first()
        if not lib and create:
            lib = MediaLibrary(owner=self, name="User Avatars")
            lib.save()
        return lib

    def merge(self, other_member, destroy=False):
        for ms in other_member.memberships.all():
            ms.member = self
            ms.save()

    def addPermission(self, perm):
        self.setProperty(perm, 1, "permissions")

    def removePermission(self, perm):
        self.setProperty(perm, None, "permissions")

    def hasPermission(self, perm):
        return self.hasPerm(perm)

    def hasPerm(self, perm):
        if isinstance(perm, list):
            for i in perm:
                if self.hasPerm(i):
                    return True
            return False
        return self.getProperty(perm, 0, "permissions", bool)

    def hasGroupPerm(self, group, perm):
        if group is None:
            return False
        ms = self.getMembershipFor(group)
        if ms is None or ms.state < -10:
            return False
        return ms.hasPerm(perm)

    @staticmethod
    def GetMember(username):
        if "@" in username:
            m = Member.objects.filter(email=username.lower()).last()
            if m:
                return m
        return Member.objects.filter(username=username.lower()).last()

    @staticmethod
    def GetWithPermission(perm, email_list=False):
        if type(perm) is list:
            queries = [Q(properties__category="permissions", properties__key=p, properties__value="1") for p in perm]
            query = queries.pop()
            for item in queries:
                query |= item
            qset = Member.objects.filter(is_active=True).filter(query).distinct()
        else:
            qset = Member.objects.filter(is_active=True).filter(properties__category="permissions", properties__key=perm, properties__value="1")

        if email_list:
            return list(qset.exclude(email__icontains="invalid").values_list('email', flat=True))
        return qset

    # BEGIN --- REST SET OVERRIDES
    # set_ called for other fields
    @classmethod
    def on_rest_list_filter(cls, request, qset=None):
        # to view users in the system one must be staff or restricted to group view
        is_active = request.DATA.get("is_active", default=True, field_type=bool)
        if qset is None:
            qset = Member.objects.all()
        if request.DATA.get(["staffonly", "staff"]):
            if not request.member.hasPerm("manage_staff") and not request.member.hasPerm("ticket_admin"):
                raise PermisionDeniedException()
            qset = qset.filter(is_staff=True)
        elif request.group:
            # check if has permission to view this group
            if not request.group.isMember(request.member):
                # not a member lets check if staff
                if not request.member.is_staff and not request.member.hasPerm(["manage_users"]):
                    raise PermisionDeniedException()
            qset = qset.filter(memberships__group=request.group)
        else:
            # this means we are filtering all
            if not request.member.is_staff and not request.member.hasPerm(["manage_users"]):
                # filter only for those we are members of
                qset = qset.filter(memberships__member=request.member)

        user_filter = request.DATA.get("user_filter")
        if user_filter:
            if user_filter == "is_staff":
                qset = qset.filter(is_staff=True, is_active=is_active)
            elif user_filter == "is_superuser":
                qset = qset.filter(is_superuser=True, is_active=is_active)
            elif user_filter == "is_online":
                qset = qset.filter(is_active=is_active)
                qset = Member.FilterOnline(True, qset)
            elif user_filter == "not_online":
                qset = qset.filter(is_active=is_active)
                qset = Member.FilterOnline(False, qset)
            elif user_filter == "is_blocked":
                qset = qset.filter(is_active=is_active)
                qset = Member.FilterBlocked(True, qset)
            elif user_filter == "not_blocked":
                qset = qset.filter(is_active=is_active)
                qset = Member.FilterBlocked(False, qset)
            elif user_filter == "is_disabled":
                qset = qset.filter(is_active=False)
            elif user_filter == "notify_off":
                qset = qset.filter(properties__category=None, properties__key__in="notify_via", properties__value="off")
            elif user_filter.startswith("has_perm:"):
                qset = qset.filter(is_active=is_active)
                k, v = user_filter.split(":")
                v = [a.strip() for a in v.split(',')]
                qset = qset.filter(properties__category="permissions", properties__key__in=v, properties__int_value=1)
        else:
            qset = qset.filter(is_active=is_active)

        sort = request.DATA.get("sort", "-date_joined")
        if "is_blocked" in sort:
            flag = sort[0] != '-'
            qset = Member.FilterBlocked(flag, qset)
            request.DATA.remove("sort")
            request.DATA.set("sort", "-date_joined")
        elif "is_online" in sort:
            flag = sort[0] != '-'
            qset = Member.FilterOnline(flag, qset)
            request.DATA.remove("sort")
            request.DATA.set("sort", "-date_joined")
        return qset

    def on_rest_get(self, request):
        graph = request.DATA.get("graph", "default")
        # check permissions
        if not request.member.canSee(self):
            graph = "abstract"
            raise PermisionDeniedException("attempting to view user: {}".format(self.username))
        if request.user.id == self.id:
            graph = "me"
        return self.restGet(request, graph)

    def on_rest_post(self, request):
        # throw an error if we don't have permissions to save
        if self.id != None and not request.member.canEdit(self):
            raise PermisionDeniedException()
        return super(Member, self).on_rest_post(request)

    @classmethod
    def createFromRequest(cls, request, **kwargs):
        # check if this user can create new users
        member = Member.createMember(request)
        send_invite = request.DATA.get("send_invite", None)
        if send_invite and send_invite.startswith("http"):
            member.sendInviteFor(send_invite, by=request.member)
        elif request.DATA.get('send_invite', field_type=bool):
            # if email is valid send them invite
            member.sendResetPassword()
        return member

    @staticmethod
    def createMember(request, **kwargs):
        '''returns None if not foreignkey, otherswise the relevant model'''
        user = Member(**kwargs)
        user.last_login = datetime.today()
        username = request.DATA.get("username", "").strip()
        email = request.DATA.get("email", "").lower().strip()
        password = request.DATA.get('password', '').strip()
        if username:
            user.set_username(username)
            if not user.email:
                user.set_email(email)
        else:
            user.set_username(email)

        name = request.DATA.get("name", "").strip()
        if name:
            user.set_name(name)
        elif email:
            name = email.split('@')[0]
            if "." in name:
                names = name.replace('.', ' ')
                user.set_name(names)
            else:
                user.set_name(name)
        if password:
            user.setPassword(password)
        user.save()
        user.updateUUID()
        is_staff = request.DATA.get('is_staff', field_type=bool)
        if is_staff and not request.member.hasPermission("manage_staff"):
            raise PermisionDeniedException("Permission Denied: attempting to create staff user")
        user.saveFromRequest(request, files=request.FILES, __is_new=True, **kwargs)
        return user

    def set_is_staff(self, value):
        request = self.getActiveRequest()
        if not request.member.hasPermission("manage_staff"):
            raise PermisionDeniedException("Permission Denied: attempting to set staff user")
        self.is_staff = int(value)

    def set_disable(self, value):
        if value != None and value in [1, '1', True, 'true']:
            self.set_action("enable")
        self.set_action("disable")

    def set_action(self, value):
        action = value
        request = self.getActiveRequest()
        if action in ["unlock", "unblock"]:
            if not request.member.is_staff and not self.canManageMe(request.member):
                raise PermisionDeniedException("Permission Denied: attempting to unlock user")
            self.unblock(request)
        elif action == "disable":
            if self.is_superuser and not request.user.is_superuser:
                raise PermisionDeniedException("Permission Denied: attempting to disable super user")
            if self.is_staff and not request.member.is_staff:
                raise PermisionDeniedException("Permission Denied: attempting to disable staff user")
            if not request.member.is_staff and not self.canManageMe(request.member):
                raise PermisionDeniedException("Permission Denied: attempting to dsiable user")
            self.disable(request.user)
        elif action == "enable":
            if not request.member.is_staff and not self.canManageMe(request.member):
                raise PermisionDeniedException("Permission Denied: attempting to enable user")
            self.enable(request.member)
        elif action == "touch_password":
            if not request.member.is_staff and not self.canManageMe(request.member):
                raise PermisionDeniedException("Permission Denied: attempting to touch password")
            self.password_changed = datetime.now()
            self.save()
        elif action == "update_password_next":
            # force the user to update password on next login
            if not request.member.is_staff and not self.canManageMe(request.member):
                raise PermisionDeniedException("Permission Denied: attempting to touch password")
            self.password_changed = datetime.now() - timedelta(days=settings.PASSWORD_EXPIRES_DAYS-1)
            self.save()

    def set_name(self, value):
        if not value:
            return
        print(("setting name: {0}".format(value)))
        names = value.split(' ')
        self.first_name = names[0].title()
        if len(names) > 1:
            self.last_name = " ".join(names[1:]).title()
        self.display_name = value.title()

    @staticmethod
    def verifyUsername(username, exclude=None):
        qs = Member.objects.filter(username=username)
        if exclude:
            qs.exclude(pk=exclude)
        return qs.count() == 0

    def set_username(self, value, generate=True):
        # we force our usernames to be the sames as the email
        value = value.lower()
        value = value.replace(' ', '.')
        if '@' in value:
            uname = self.username
            self.username = None
            self.set_email(value)
            if self.username is None:
                self.username = uname
        elif self.username != value:
            orig_value = value
            if generate:
                for i in range(0, 20):
                    if Member.verifyUsername(value, self.id):
                        self.username = value
                        return True
                    value = "{}{}".format(orig_value, i)
            else:
                if Member.verifyUsername(value, self.id):
                    self.username = value
                    return True
            raise RestValidationError("username '{}'' already exists!".format(value))

    def set_newpassword(self, value):
        print("setting new password")
        request = self.getActiveRequest()
        if not request:
            raise RestValidationError("requires request to continue")
        old_password = request.DATA.get("oldpassword", None)
        if not old_password:
            request.member.log("password_error", "requires oldpassword to change password", method="password_change")
            raise RestValidationError("requires oldpassword to continue")
        # verify we have the old password correct
        if not self.checkPassword(old_password):
            # invalid password
            request.member.log("password_error", "incorrect oldpassword to change password", method="password_change")
            raise RestValidationError("old password is not correct")
        self.set_password(value)

    def set_password(self, value):
        """
        this is tricky because we need to call set_password on the User model
        """
        print("setting password")
        request = self.getActiveRequest()
        if not request.member.canEdit(self):
            request.member.log("permission_denied", "attempting to set password for user: {}".format(self.username), method="password_change")
            raise PermisionDeniedException("Permission Denied: attempting to change password")
        if request.member.id != self.id:
            self.log("modified_by", "password changed by: {}".format(request.member.username), method="password_change")
            request.member.log("member_edit", "{} password changed".format(self.username), method="password_change")
            self.setPassword(value, skip_history=True)
        else:
            self.setPassword(value)

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_password):
            super(Member, self).set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["password"])
        return check_password(raw_password, self.password, setter)

    def setPassword(self, value, skip_history=False):
        """
        if (this.length > 6) score++;
        if (this.length > 11) score++;
        if (this.length > 15) score++;

        //if this has both lower and uppercase characters give 1 point
        if ( ( this.match(/[a-z]/) ) && ( this.match(/[A-Z]/) ) ) score++;

        //if this has at least one number give 1 point
        if (this.match(/\d+/)) score++;

        //if this has at least one special caracther give 1 point
        if ( this.match(/[!@#$%^&*.]/) ) score++;

        """
        score = 0
        score += 1 if len(value) > 6 else 0
        score += 1 if len(value) > 11 else 0
        score += 1 if len(value) > 15 else 0
        score += 1 if re.match(r'.*[a-z]', value) and re.match(r'.*[A-Z]', value) else 0
        score += 1 if re.match(r'.*\d+', value) else 0
        score += 1 if re.match(r'.*[!@#$%^&*.]', value) else 0
        if score < 3:
            self.log("password_error", "password is weak or duplicate", method="password_change")
            raise RestValidationError("password is weak or duplicate")
        if not skip_history and hasattr(settings, "PASSWORD_HISTORY") and settings.PASSWORD_HISTORY:
            hashed_password = PasswordHistory.HashPassword(value)
            # this means you can never reuse the same password
            if self.password_history.filter(password=hashed_password).count():
                self.log("password_error", "password already used", method="password_change")
                raise RestValidationError("password already used")
            if not self.id:
                self.save()
            PasswordHistory(owner=self, password=hashed_password).save()
        # self.set_password(value)
        super(Member, self).set_password(value)
        self.password_changed = datetime.now()
        self.save()
        self.log("password_changed", "password changed", method="password_change")
        return True

    def set_email(self, value):
        # we force our usernames to be the sames as the email
        # basic validation
        if value != None:
            value = value.lower()

        if self.email == value:
            return

        if "@" not in value or "." not in value:
            raise RestValidationError("Invalid Email")

        # verify there is not another account with this email
        qs = Member.objects.filter(email=value)
        if self.id:
            qs.exclude(pk=self.id)
        if qs.count():
            raise RestValidationError("user with email {} already exists!".format(value))

        if self.email:
            self.log("email_changed", "email changed from {} to {}".format(self.email, value), method="email_change")
        self.email = value

        if self.username:
            if "@" in self.username:
                if Member.verifyUsername(value, self.id):
                    self.username = value
            return True

        if len(value) > 250:
            value = value.split("@")[0]
        if Member.verifyUsername(value, self.id):
            self.username = value
        else:
            raise RestValidationError("email to username '{}' already exists!".format(value))
# upload__ called for files
    def upload__picture(self, value, name):
        if value is None:
            # for some reason the user does not want an avatar?
            self.picture = None
            return

        lib = self.getMediaLibrary("User Avatars")
        MediaItem = RestModel.restGetModel("medialib", "MediaItem")
        kind = MediaItem.guessMediaKind(value)
        if not kind == 'I':
            raise RestValidationError('Invalid file type')

        img = MediaItem(library=lib, name="Profile Image", owner=self, kind=kind, newfile=value)
        img.save()
        self.picture = img


    # END --- REST SET OVERRIDES


    def getAccessTokens(self, provider):
        link = self.getSocialLink(provider)
        if link:
            return link.tokens
        return None

    def getAccessToken(self, provider):
        link = self.getSocialLink(provider)
        if link:
            return link.extra_data.get("access_token")
        return None

    def thumbnail(self):
        return self.picture_url(60)

    def large_thumbnail(self):
        return self.picture_url(500)

    def small_thumbnail(self):
        return self.picture_url(60)

    def profile_image(self):
        return self.picture_url(1240)

    def picture_url(self, size=None, request=None):
        if not request:
            request = get_request()
        if not self.picture:
            return None
        if (not size) and request and request.DATA:
            size = request.DATA.get('user_thumbnail_size', None)
        if size:
            ret = self.picture.image_larger(int(size))
        else:
            ret = self.picture.thumbnail_large()
        if not ret:
            return None
        return ret.view_url(request=request, expires=None)

    def getDefaultMembership(self):
        if self.default_membership:
            return self.default_membership
        if self.memberships.count():
            return self.memberships.all().last()
        return None

    def groups(self, kind=None):
        qset = Group.objects.filter(memberships__member=self, memberships__state__gte=-10)
        if kind:
            qset = qset.filter(kind=kind)
        return qset.distinct()

    def canManageMe(self, member):
        if isinstance(member, Membership):
            # this is a membership
            member = member.member
        return member.canEdit(self)

    def canSee(self, user):
        if user.id == self.id or self.hasPerm(["manage_staff", "manage_users"]):
            return True
        # mygroups = Group.objects.filter(memberships__member=self, memberships__state__gte=-10)
        # return mygroups.filter(memberships__member__pk=user.pk).count()
        return False # enforce strict user perms

    def canEdit(self, user, allow_self_edit=True):
        if isinstance(user, Membership):
            # this is a membership
            user = user.member
        if allow_self_edit and user.id == self.id:
            return True
        if user.is_staff:
            # only super user can edit staff users
            return self.is_superuser or self.hasPerm("manage_staff")
        if self.hasPerm(["manage_users", "manage_staff"]):
            return True
        # we need to find any groups these users have in common
        # then find if the request.member is a manager or hasPerm admin or manager
        common_groups = user.groups().filter(memberships__member=self)
        if common_groups.count():
            # we have some common groups lets see if self is a admin or manager
            qset = self.memberships.filter(group__in=common_groups).filter(Q(permissions__name__in=["admin", "manager", "manage_members"])|Q(role__icontains="manager"))
            return qset.count() > 0
        return False

    def isMemberOf(self, group, include_parents=True):
        ms = self.getMembershipFor(group, include_parents)
        return ms is not None

    def getMembershipFor(self, group, include_parents=True):
        # django should auto filter by group_id if int
        if group is None:
            return None
        if include_parents:
            qset = self.memberships.filter(Q(group=group) | Q(group__parent=group) | Q(group__children=group))
            if qset is not None:
                # the order of the above query is not logical, so we must do it ourselves
                # there is most likely only a few groups in this list
                # if we have a ms in the desired group lets return that
                # this logic should be less hard on db
                group_id = group
                if not isinstance(group_id, (int, str)):
                    group_id = group.id
                for ms in qset:
                    if ms.group_id == group_id:
                        return ms
                return qset.first()
            # now check by children
        return self.memberships.filter(group=group)

    def getGroup(self, group_id, include_parents=True):
        # now we want to verify we are a member of this group or a parent group
        if self.hasPerm("view_all_groups"):
            return Group.objects.filter(pk=group_id).first()
        ms = self.getMembershipFor(group_id, include_parents)
        if ms is not None:
            if ms.group.id != group_id:
                # this means we got a parent ms, so lets turn the group itself
                return Group.objects.filter(pk=group_id).first()
            else:
                return ms.group
        return None

    def createMyDefaultGroup(self):
        group, created = Group.objects.get_or_create(name=self.username, kind="private")
        if created:
            self.default_membership = group.addMembership(self, "admin")
            self.save()
        return group

    def getDefaultGroup(self):
        ms = self.getDefaultMembership()
        if ms:
            return ms.group
        return None

    def getGroups(self):
        return Group.objects.filter(memberships__member=self, memberships__state__gte=-10).distinct()

    def notify(self, template=None, context=None, subject=None, message=None, email_only=True, sms_msg=None, force=False, from_email=settings.DEFAULT_FROM_EMAIL):
        from telephony.models import SMS
        # do not allow if account is not active
        if not self.is_active and not force:
            return False
        via = self.getProperty("notify_via", "all")
        phone = self.getProperty("phone")
        email = self.email
        valid_email = email != None and "@" in email and "invalid" not in email
        allow_sms = not email_only and phone and (force or via in ["all", "sms"])
        allow_email = valid_email and (force or via in ["all", "email"])
        if not allow_email and not allow_sms:
            return False

        if allow_email:
            ctx = {
                'to': self.email,
                'to_token': hashit(self.email),
                'from': from_email,
                'timezone': "America/Los_Angeles"
            }

            if context:
                subject = context.get("subject", subject)
                message = context.get("message", message)
                ctx.update(context)

            from_email = ctx.get("from", None)
            rest_mail.send([self.email],
                subject,
                message,
                from_email=from_email,
                template=template,
                context=ctx,
                do_async=True
            )
            self.log("notified", subject, method=self.email)

        if allow_sms:
            if not sms_msg and subject:
                sms_msg = subject
            if not sms_msg and message:
                sms_msg = message
            SMS.send(phone, sms_msg)
            self.log("notified", subject, method=phone)
        return True

    def disable(self, by, reason="", notify=True):
        self.is_active = False
        self.save()
        self.memberships.update(state=-100)

        [s.delete() for s in Session.objects.all() if s.get_decoded().get('_auth_user_id') == self.pk]
        # notify account disabled
        subject = "MEMBER {} DISABLED BY {}".format(self, by)
        accounts = []
        body = "{}<br>\ndisabled from: ".format(reason)
        for m in self.memberships.all():
            accounts.append(m.group.name)
        body += "<br>\n".join(accounts)
        self.log("disabled", "account disabled by {}, {}".format(by.username, reason), method="disabled")
        if notify:
            Member.notifyWithPermission("user_audit", subject, message=body, email_only=True)

    def enable(self, by, memberships=None):
        if not self.is_active:
            self.is_active = True
            self.save()
        # notify account disabled
        subject = "MEMBER {} RE-ENABLED BY {}".format(self, by)
        body = "enabled for: "
        if memberships is None:
            memberships = self.memberships.all()

        accounts = []
        for m in memberships:
            m.state = 10
            m.save()
            accounts.append(m.group.name)
        body += "<br>\n".join(accounts)
        self.log("enabled", "account enabled by {}".format(by.username), method="enabled")
        Member.notifyWithPermission("user_audit", subject, message=body, email_only=True)


    def locateByIP(self, ip):
        try:
            loc = GeoIP.get(ip)
        except:
            return

        if loc:
            if not self.getProperty("city", None, "location"):
                self.setProperty("city", loc.city, "location")
                self.setProperty("state", loc.state, "location")
                self.setProperty("country", loc.country, "location")
            self.setProperty("current_city", loc.city, "location")
            self.setProperty("current_state", loc.state, "location")
            self.setProperty("current_country", loc.country, "location")

            self.setProperty("lat", loc.lat, "location")
            self.setProperty("lng", loc.lng, "location")

    def __unicode__(self):
        return self.username

    def getUser(self):
        return self.user_ptr

    @property
    def full_name(self):
        return self.get_full_name()

    @staticmethod
    def getByUser(user):
        member = Member.objects.filter(pk=user.pk).first()
        if member is None:
            member = Member(user_ptr = user)
            for f in user._meta.local_fields: setattr(member, f.name, getattr(user, f.name))
            member.save()
        return member

    @staticmethod
    def generateUsername(email, first_name, last_name):
        username = email
        if email and "@" in email:
            username = email.split('@')[0]
        elif first_name and last_name:
            username = "{0}.{1}".format(first_name, last_name).replace(" ", ".")
        elif first_name:
            username = "{0}".format(first_name).replace(" ", ".")
        elif last_name:
            username = "{0}".format(last_name).replace(" ", ".")
        else:
            username = "noname"

        valid = string.ascii_letters + string.digits + '@+-_.'
        username = str(username).lower().translate(None, string.maketrans(valid, ' '*len(valid)))[:30]
        i = 0
        while Member.objects.filter(username=username).exists():
            ilen = len("%d" % i)
            username = "%s%d" % (username[:(30-ilen)], i)
            i += 1
        return username

    def sendResetPassword(self):
        if not self.uuid:
            self.updateUUID()

        rest_mail.render_to_mail("registration/password_reset_email", {
            'settings':settings,
            'user': self,
            'subject':"{0} Password Reset".format(settings.SITE_LABEL),
            'from': settings.DEFAULT_FROM_EMAIL,
            'to': [self.email],
            'uuid': self.uuid,
            'token': self.createInviteToken()
        })

    def createInviteToken(self):
        return default_token_generator.make_token(self)

    def checkInviteToken(self, token):
        return default_token_generator.check_token(self, token)

    def sendInviteFor(self, website, **kwargs):
        c = {
            'settings':settings,
            'website': website,
            'subject':kwargs.get("subject", "Invited to {}".format(website)),
            'from': settings.DEFAULT_FROM_EMAIL,
            "body": kwargs.get("body", None),
            'to': self.email,
            'by': kwargs.get("by", None),
            'user': self
        }
        rest_mail.render_to_mail("email/invite_website", c)

    def sendInvite(self, by, group=None, message="", is_new=True, template=None):
        """
        This method will set the users account to not active and
        send a confirmation email request
        """
        UserInvite = RestModel.restGetModel("flow", "UserInvite")
        return UserInvite.send(by, self.email, name=self.get_full_name(), group=group, user=self, message=message, is_new=is_new, template=template)

    def info(self):
        info = self.properties.filter(category=None)
        res = {}
        for i in info:
            res[i.key] = i.value
        return res

    def location(self):
        info = self.properties.filter(category="location")
        if info.exists():
            res = {}
            for i in info:
                res[i.key] = i.value
            return res
        return None

    def biostats(self):
        info = self.properties.filter(category="biostats")
        if info.exists():
            res = {}
            for i in info:
                res[i.key] = i.value
            return res
        return None

    def sendSMS(self, msg):
        from telephony.models import SMS
        phone = self.getProperty("phone")
        if not phone or len(phone) < 7:
            return False
        SMS.send(phone, msg)
        return True

    @staticmethod
    def getByUUID(uuid):
        if uuid is None:
            return None
        member = Member.objects.filter(uuid=uuid).first()
        if member:
            return member
        if uuid.isdigit():
            member = Member.objects.filter(id=uuid).first()
        return member

    @staticmethod
    def notifyWithPermission(perm, subject, message=None, template=None, context=None, email_only=False, sms_msg=None, force=False):
        NotificationRecord.notify(Member.GetWithPermission(perm), subject, message, template, context, email_only, sms_msg, force)

    @staticmethod
    def sendEmail(members=None, subject="Notification", template="email/base", body="", context={}, master_perm=None):
        c = {
            'settings':settings,
            'subject':subject,
            'from': settings.DEFAULT_FROM_EMAIL,
            "body": body,
            'sent_to': None,
        }
        sent_to = []
        c.update(context)
        if members:
            for m in members:
                valid_email = m.email != None and "@" in m.email and "invalid" not in m.email
                if not valid_email:
                    continue
                # print m.email
                c["to"] = m.email
                sent_to.append(m.email)
                c["user"] = m
                rest_mail.render_to_mail(template, c)
        else:
            members = Member.objects.all()

        if master_perm:
            c["to"] = Member.GetWithPermission(master_perm, email_list=True)
            c["sent_to"] = c["to"]
            if c["to"]:
                rest_mail.render_to_mail(template, c)

class SocialUser(Member):
    class Meta:
        proxy = True

    class RestMeta:
        NO_SHOW_FIELDS = ["password"]

        METADATA_FIELD_PROPERTIES = getattr(settings, "USER_METADATA_PROPERTIES", None)

        GRAPHS = {
            "default": {
                "extra": ["metadata", "password_expires_in"],
                "fields":[
                    'id',
                    'is_online',
                    'is_blocked',
                    'email',
                    'uuid',
                    'display_name',
                    ('get_full_name', 'full_name'),
                    'first_name',
                    'last_name',
                    'initials',
                    'username',
                    'is_active',
                    'is_staff',
                    'is_superuser',
                    'last_login',
                    ('date_joined', 'created'),
                    ("hasLoggedIn", "has_logged_in"),
                    'thumbnail',
                    'profile_image'
                ]
            },
            "detailed": {
                "extra": ["metadata", "password_expires_in"],
                "graphs": {
                    "self":"basic",
                    "groups":"basic"
                }
            },
            "list": {
                "extra": [("getSessionID", "session_key")],
                "graphs": {
                    "self":"default",
                }
            }
        }

    def setAvatar(self, url, source=None):
        """
        This method scrapes the avatar url and caches it locally
        It also creates a rendition called 'source' that keeps the original url
        """
        if not url:
            return None
        if source:
            self.setProperty("{0}_avatar".format(source), url, "social")
        # now we could check the source, or we could just create a new copy of the image?
        if self.picture:
            mediarend = self.picture.get("source")
            if not mediarend or (mediarend and mediarend.url != url):
                self.picture.updateFromURL(url)
        else:
            MediaItem = RestModel.restGetModel("medialib", "MediaItem")
            picture = MediaItem.CreateFromURL(url, self, kind='I')
            if picture:
                self.picture = picture
                self.picture.state = 200
                self.picture.save()
                self.save()


    def updateAvatar(self, platform=None):
        # this attempts to scrape the users latest avatar picture
        if platform:
            url = socialapi.getAvatarFor(platform, self)
            if url != None:
                self.setAvatar(url, platform)
                return True
            return False

        # no platform passed lets go through social links until we find an avatar
        for l in self.social_auth.all():
            if self.updateAvatar(l.provider):
                return True
        return False

    @staticmethod
    def getByUser(user):
        member = SocialUser.objects.filter(pk=user.pk).first()
        if member is None:
            member = SocialUser(user_ptr = user)
            for f in user._meta.local_fields: setattr(member, f.name, getattr(user, f.name))
            member.save()
        return member

    def setAudienceSize(self, platform, size):
        if size:
            self.setProperty("{0}_audience".format(platform), sz, "social")
            self.updateAudienceTotal()

    def updateAudienceTotal(self):
        total = 0
        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            total += int(self.getProperty("{0}_audience".format(platform), 0, "social"))
        self.getProperty("audience".format(platform), total, "social")

    def updateEngagementTotal(self):
        total = 0
        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            total += int(self.getProperty("{0}_engagement".format(platform), 0, "social"))
        self.getProperty("engagement".format(platform), total, "social")

    def fetchEngagementSize(self, platform=None):
        if platform:
            if platform == "google":
                platform = "googleplus"
            # now lets check out content shares
            val = self.content_shares.filter(shared_to=platform).aggregate(total_engagement=Sum('engagement'),total_views=Sum('views'))
            self.setProperty("{0}_engagement".format(platform), val["total_engagement"], "social")
            self.setProperty("{0}_views".format(platform), val["total_views"], "social")
            return val["total_engagement"], val["total_views"]

        total_engagement = 0
        total_views = 0
        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            engagement, views = self.fetchEngagementSize(platform)
            total_engagement += engagement
            total_views += views
        self.setProperty("engagement", total_engagement, "social")
        self.setProperty("views", total_views, "social")

    def fetchAudienceSize(self, platform=None, access_token=None):
        if platform:
            size = socialapi.getAudienceSizeFor(platform, self, access_token)
            if size != None:
                self.setProperty("{0}_audience".format(platform), size, "social")
            return size

        total = 0
        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            sz = self.fetchAudienceSize(platform)
        self.setProperty("audience", total, "social")


    def refreshSocialToken(self, provider):
        link = self.getSocialLink(provider)
        if link is None:
            return None

        django_stategy = load_strategy()
        if link.provider != "google":
            link.refresh_token(django_stategy)
            return link

        data = link.extra_data
        mobile_token = None
        refresh_token = self.getSocialRefreshToken(link)

        access_token = None
        if refresh_token:
            try:
                link.refresh_token(django_stategy)
                return link
            except:
                print("refreshSocialToken(refresh_token) FAILED trying mobile_token")

        if "mobile_token" in link.extra_data and link.extra_data.get("mobile_token") != None:
            mobile_token = link.extra_data.get("mobile_token")
        else:
            mobile_token = self.getProperty("{0}_mobile_token".format(link.provider), None)

        if mobile_token and hasattr(settings, "GOOGLE_OAUTH2_MOBILE_ID"):
            response = youtube.refreshToken(mobile_token, settings.GOOGLE_OAUTH2_MOBILE_ID, settings.GOOGLE_OAUTH2_MOBILE_SECRET)
            if response:
                backend = link.get_backend()
                link.extra_data.update(backend.AUTH_BACKEND.extra_data(self, link.uid, response))
                link.save()
                return link
        return None

    def getSocialMobileToken(self, provider):
        link = self.getSocialLink(provider)
        if link is None:
            return None

        if "mobile_token" in link.extra_data and link.extra_data.get("mobile_token") != None:
            return link.extra_data.get("mobile_token")
        return self.getProperty("{0}_mobile_token".format(link.provider), None)

    def getSocialRefreshToken(self, provider):
        link = self.getSocialLink(provider)
        if link is None:
            return None

        if "refresh_token" in link.extra_data and link.extra_data.get("refresh_token") != None:
            return link.extra_data.get("refresh_token")
        return self.getProperty("{0}_refresh_token".format(link.provider), None)

    def getSocialLinks(self):
        links = []
        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            links.append(platform)
        return links

    SOCIAL_MAP = {
        "linkedin":"linkedin-oauth2",
        "google":"googleplus",
    }

    def getSocialLink(self, provider):
        if type(provider) in [str, str]:
            if provider in self.SOCIAL_MAP:
                provider = self.SOCIAL_MAP[provider]
            link = UserSocialAuth.objects.filter(provider=provider, user=self).first()
            if link:
                return link
            return None
        return provider

    def social_details(self, request=None):
        links = {}

        for l in self.social_auth.all():
            refresh_token = self.getSocialRefreshToken(l)
            mobile_token = self.getSocialMobileToken(l)
            platform = l.provider
            platform = platform.split('-')[0]
            links[platform] = {
                "uid": l.uid,
                "refresh_token": refresh_token,
                "mobile_token": mobile_token,
                "email": self.getProperty("{0}_email".format(platform))
                }
        return links

    def social_links(self, request=None):
        if not request:
            request = get_request()
        links = {}
        if "auth_backend" in request.session:
            links["current"] = request.session['auth_backend']
        else:
            links["current"] = None

        for l in self.social_auth.all():
            refresh_token = self.getSocialRefreshToken(l)
            platform = l.provider
            platform = platform.split('-')[0]
            links[platform] = {
                "has_refresh_token": refresh_token != None,
                "login_backend": links["current"] == platform,
                "email": self.getProperty("{0}_email".format(platform))
                }
        return links


    def follow(self, user):
        if not self.isFollowing(user):
            obj = MemberToMember(owner=self, follow=user)
            obj.save()
            MemberFeed.log(user, "member", 0, "follow", self)
            # Stat.log(request=request, component="content", action=kind,
            # 	subtype=content.content_kind,
            # 	content=content,
            # 	user=request.user)


    def unfollow(self, user):
        rel = self.following.filter(follow=user).first()
        if rel:
            rel.delete()
            MemberFeed.log(user, "member", 0, "unfollow", self)
            # Stat.log(request=request, component="content", action=kind,
            # 	subtype=content.content_kind,
            # 	content=content,
            # 	user=request.user)

    def isFollowing(self, user=None, request=None):
        """returns if the current auth user is following"""
        if user is None:
            if not request:
                request = get_request()
            user = request.user
        return self.following.filter(follow=user).exists()


    def amFollowing(self, user=None, request=None):
        """returns if the current auth user is following"""
        if user is None:
            if not request:
                request = get_request()
            user = request.user
        return user.member.following.filter(follow=self).exists()

    def followersCount(self):
        return self.followers.count()

    def followingCount(self):
        return self.followers.count()

    def social_stats(self, backend=None):
        """
        backend is None
        returns the total number of friends for all the linked accounts
        """
        stats = {}
        atotal = 0
        etotal = 0
        vtotal = 0
        ptotal = 0
        ctotal = 0

        for l in self.social_auth.all():
            platform = l.provider
            platform = platform.split('-')[0]
            audience = self.getProperty("{0}_audience".format(platform), 0, "social")
            atotal += int(audience)
            engagement = self.getProperty("{0}_engagement".format(platform), 0, "social")
            etotal += int(engagement)
            views = self.getProperty("{0}_views".format(platform), 0, "social")
            vtotal += int(views)
            clicks = self.getProperty("{0}_clicks".format(platform), 0, "social")
            ctotal += int(clicks)
            posts = self.getProperty("{0}_posts".format(platform), 0, "social")
            ptotal += int(posts)


            stats[platform] = {
                "uid": l.uid,
                "email": self.getProperty("{0}_email".format(platform), None, "social"),
                "avatar": self.getProperty("{0}_avatar".format(platform), None, "social"),
                "audience": audience,
                "engagement": engagement,
                "views": views,
                "clicks": clicks,
                "posts": posts
            }

            if platform.lower() in ["twitter", "instagram"]:
                stats[platform]["username"] = self.getProperty("{0}_username".format(platform), None, "social")

        stats["total_audience"] = atotal
        stats["total_engagement"] = etotal
        stats["total_views"] = vtotal
        stats["total_clicks"] = ctotal
        stats["total_posts"] = ptotal

        request = get_request()
        if request:
            if "auth_backend" in request.session:
                stats["auth_with"] = request.session['auth_backend']
            else:
                stats["auth_with"] = "password"
        return stats

class MemberMetaData(MetaDataBase):
    parent = models.ForeignKey(Member, related_name="properties", on_delete=models.CASCADE)

class PasswordHistory(models.Model):
    created = models.DateTimeField(auto_now_add=True, editable=False)
    owner = models.ForeignKey(Member, related_name="password_history", on_delete=models.CASCADE)
    password = models.CharField(max_length=255)

    @staticmethod
    def HashPassword(password):
        return hashlib.sha512((settings.SECRET_KEY + password).encode('utf-8')).hexdigest()

class MemberToMember(models.Model):
    created = models.DateTimeField(auto_now_add=True, editable=False)
    owner = models.ForeignKey(Member, related_name="following", on_delete=models.CASCADE)
    follow = models.ForeignKey(Member, related_name="followers", on_delete=models.CASCADE)

class MemberFeed(models.Model):
    owner = models.ForeignKey(Member, related_name="feed", on_delete=models.CASCADE)
    group = models.ForeignKey("Group", blank=True, null=True, default=None, related_name="+", on_delete=models.CASCADE)
    component = models.SlugField(max_length=32, null=True, blank=True, db_index=True)
    action = models.SlugField(max_length=32, db_index=True)

    related_user = models.ForeignKey(Member, related_name="+", null=True, blank=True, default=None, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True, editable=False)

    key = models.IntegerField(help_text="ID to the content instance")
    extra = models.CharField(max_length=64, null=True, blank=True, default=None)

    @classmethod
    def log(cls, owner, group, component, key, action, related_user, extra=None):
        if not isinstance(owner, Member):
            owner = owner.member

        if related_user and not isinstance(related_user, Member):
            related_user = related_user.member

        obj = MemberFeed(owner=owner, group=group, component=component, key=key, action=action, related_user=related_user, extra=extra)
        obj.save()
        return obj

class Group(models.Model, RestModel, MetaDataModel):
    """
    Group Model allows for the grouping of other models and works with Member throug Membership Model

    parent allows for tree based heirachy of groups
    children allows for manytomany relationships with other groups
    kind is heavily used to filter different kinds of groups
    """
    uuid = models.CharField(db_index=True, max_length=64, blank=True, null=True, default=None)
    name = models.CharField(db_index=True, max_length=200)
    short_name = models.CharField(max_length=60, null=True, blank=True, default=None)
    kind = models.CharField(db_index=True, max_length=80, default="org")
    location = models.ForeignKey("location.Address", default=None, null=True, blank=True, on_delete=models.CASCADE)
    parent = models.ForeignKey("Group", default=None, null=True, blank=True, related_name="groups", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True, blank=True)
    # this is the new model for groups having multiple parents
    children = models.ManyToManyField("self", related_name="parents", symmetrical=False)

    class RestMeta:
        SEARCH_FIELDS = [
            "name",
            "short_name",
        ]
        POST_SAVE_FIELDS = ["child_of"]
        GRAPHS = {
            "basic": {
                "fields":[
                    "id",
                    "uuid",
                    "name",
                    "short_name",
                    "kind",
                    "created",
                    "thumbnail",
                    "is_active",
                    "timezone"
                ],
                "graphs":{
                    "location":"basic",
                },
            },
            "default": {
                "graphs":{
                    "self":"basic",
                    "parent":"basic"
                },
                "fields": ["metadata"],
            },
            "detailed": {
                "graphs":{
                    "self":"basic",
                    "parent":"basic",
                    "children": "basic"
                },
                "fields": ["metadata"],
            },
            "abstract": {
                "fields":[
                    ('uuid', 'id'),
                    "name",
                    "kind",
                    "timezone"
                ],
                "graphs":{
                    "location":"abstract",
                },
            }
        }

    @property
    def timezone(self):
        return self.getProperty("timezone", "America/Los_Angeles")

    @property
    def timezone_short(self):
        zone = self.getProperty("timezone", "America/Los_Angeles")
        return rest_helpers.getShortTZ(zone)

    @property
    def qbo_account_name(self):
        return self.getProperty("qbo_account_name", self.name)

    @property
    def file_safe_name(self):
        return re.sub("[^0-9a-zA-Z]+", "_", self.name.lower())

    @classmethod
    def on_rest_list_filter(cls, request, qset=None):
        # override on do any pre filters
        child_of = request.DATA.get("child_of")
        if request.group is not None and child_of is None:
            child_of = request.group.id
        parent_id = request.DATA.get(["parent", "parent_id"])
        if parent_id:
            parent = request.member.getGroup(parent_id)
            if not parent:
                raise PermisionDeniedException()
            qset = qset.filter(parent=parent)
        elif child_of:
            parent = Group.objects.filter(pk=child_of).last()
            if parent:
                request.group = None
                return parent.getAllChildren()
        else:
            no_parent = request.DATA.get("no_parent")
            has_parent = request.DATA.get("has_parent")
            if no_parent:
                qset = qset.filter(parent=None)
            elif has_parent:
                qset = qset.exclude(parent=None)
            else:
                is_parent = request.DATA.get("is_parent", False, field_type=bool)
                if is_parent:
                    qset = qset.exclude(groups=None)
        if not request.member.hasPermission("view_all_groups"):
            qset = qset.filter(memberships__member=request.member, memberships__state__gte=-10)
        return qset

    def on_rest_get(self, request):
        if not request.terminal and not request.member.hasPermission("view_all_groups") and not request.member.isMemberOf(self):
            return restPermissionDenied(request)
        graph = request.DATA.get("graph", "default")
        # if not self.checkPermission(request.member, ["manage_settings", "manage_members"]):
        #     graph = "basic"
        return self.restGet(request, graph)

    def onRestCanSave(self, request):
        if request.member is None:
            raise PermisionDeniedException()
        if request.member.hasPermission(["manage_groups", "create_groups"]):
            return True
        if self.checkPermission(request.member, ["manage_settings", "manage_members"]):
            return True
        raise PermisionDeniedException()

    def on_rest_pre_save(self, request, **kwargs):
        pass

    def set_child_of(self, value):
        # this is a helper to add this group to another group
        parent = Group.objects.filter(pk=value).last()
        if parent and parent.pk != self.pk:
            if not parent.children.filter(pk=self.pk).exists() and not self.hasChild(parent) and self.kind != "org":
                parent.children.add(self)

    def set_remove_parent(self, value):
        parent = Group.objects.filter(pk=value).last()
        if parent:
            if parent.children.filter(pk=self.pk).exists():
                parent.children.remove(self)

    def getAllChildren(self, include_me=False):
        if include_me:
            return Group.objects.filter(Q(parent=self)| Q(parents=self)| Q(pk=self.id))
        return Group.objects.filter(Q(parent=self)| Q(parents=self))

    def getAllChildrenIds(self):
        return list(self.getAllChildren().values_list("id", flat=True))

    def hasChild(self, group):
        if not group:
            return False
        if self.children.filter(pk=group.pk).exists():
            return True
        for child in self.children.all():
            if child.hasChild(group):
                return True
        return False

    def getParentOfKind(self, kind):
        if self.parent and self.parent.kind == kind:
            return self.parent
        group = self.parents.filter(kind=kind).first()
        if group:
            return group
        for parent in self.parents.all():
            if parent.kind == kind:
                return parent
            group = parent.getParentOfKind(kind)
            if group:
                return group
        return None

    def hasParent(self, group):
        # this needs to check parents...then check each parent for parent
        if self.parent == group:
            return True
        if self.parents.filter(pk=group.id).count():
            return True
        for parent in self.parents.all():
            if parent == group:
                return True
            if parent.hasParent(group):
                return True
        return False

    def notifyMembers(self, subject, message=None, template=None, context=None, email_only=False, sms_msg=None, perms=None, force=False):
        if perms != None:
            members = self.getMembers(perms=perms, as_member=True)
        else:
            members = Member.objects.filter(is_active=True, memberships__group=self, memberships__state__gte=-10)
        NotificationRecord.notify(members, subject, message, template, context, email_only, sms_msg, force)

    def hasPerm(self, member, perm, staff_override=True, check_member=False):
        return self.checkPermission(member, perm, staff_override, check_member)

    def checkPermission(self, member, perm, staff_override=True, check_member=False):
        if member.is_superuser:
            return True
        if staff_override and member.is_staff:
            return True
        if check_member:
            if member.hasPerm(perm) or member.hasGroupPerm(self, perm):
                return True
        memberships = member.memberships.filter(group=self)
        for ms in memberships:
            if ms.checkPermission(perm, staff_override=staff_override):
                return True
        return False

    def getLocalTime(self, when=None):
        zone = self.getProperty("timezone", "America/Los_Angeles")
        return rest_helpers.convertToLocalTime(zone, when)

    def getUTC(self, when):
        zone = self.getProperty("timezone", "America/Los_Angeles")
        return rest_helpers.convertToUTC(zone, when)

    def getOperatingHours(self, start=None, end=None, kind="day"):
        zone = self.getProperty("timezone", "America/Los_Angeles")
        eod = self.getProperty("eod", 0, field_type=int)
        return rest_helpers.getDateRangeZ(start, end, kind, zone, hour=eod)

    def getTimeZoneOffset(self, when=None, hour=None):
        zone = self.getProperty("timezone", "America/Los_Angeles")
        return rest_helpers.getTimeZoneOffset(zone, when, hour=hour)

    def getEOD(self, eod=None, onday=None, in_local=False):
        if eod is None:
            eod = self.getProperty("eod", 0, field_type=int)
            if in_local:
                return eod
        offset = self.getTimeZoneOffset(onday, hour=eod)
        return offset

    def updateUUID(self):
        self.uuid = Hashids().encrypt(self.id)
        self.save()

    def logo(self):
        lib = self.libraries.first()
        if lib:
            item = lib.items.all().first()
            if item:
                return item.thumbnail_url()
        return None

    def thumbnail(self, name="default"):
        lib = self.libraries.filter(name=name).first()
        if lib:
            item = lib.items.all().first()
            if item:
                return item.thumbnail_url()
        return None

    def getMedia(self, name="default"):
        lib = self.libraries.filter(name=name).first()
        if lib:
            return lib.items.all()
        return None

    def getMediaLibrary(self, name="default"):
        return self.libraries.filter(name=name).first()

    def isMember(self, member):
        return self.memberships.filter(member=member, state__gte=-10).count()

    def hasMember(self, member):
        return self.isMember(member)

    def addMembership(self, member, role):
        if self.memberships.filter(member=member, role=role).count():
            return None
        ms = Membership(group=self, member=member, role=role)
        ms.save()
        return ms

    def getMembers(self, perms=None, role=None, as_member=False):
        if perms:
            if type(perms) in [str, str]:
                perms = [perms]
        if role:
            if type(role) in [str, str]:
                role = [role]

        if as_member:
            res = Member.objects.filter(is_active=True, memberships__group=self, memberships__state__gte=-10)
            if perms:
                res = res.filter(memberships__group=self, memberships__permissions__name__in=perms)
            if role:
                res = res.filter(memberships__group=self, memberships__role__in=role)
            return res.distinct()
        res = self.memberships.filter(state__gte=-10)
        if perms:
            res = res.filter(permissions__name__in=perms)
        if role:
            res = res.filter(role__in=role)
        return res.distinct()

    def getMembership(self, member):
        return self.memberships.filter(member=member).first()

    def set_location(self, values):
        # use this to quicly save an address
        # print "####### HERE"
        if self.location is None:
            # circl ref need to get cls
            AdderClass = self.get_fk_model("location")
            address = AdderClass()
        else:
            address = self.location
        request = get_request()
        address.modified_by = request.user
        for key, value in list(values.items()):
            address.restSaveField(key, value)
        address.save()
        self.location = address
        self.save()

    def getEmails(self, role=None, perms=None, master_perm=None):
        emails = []
        members = self.getMembers(role=role, perms=perms, as_member=True)
        for m in members:
            if "invalid" in m.email:
                continue
            emails.append(m.email)
        if master_perm:
            emails = emails + Member.GetWithPermission(master_perm, email_list=True)
        return emails

    def sendEmail(self, role=None, perms=None, subject="Notification", template="email/base", body="", context={}, master_perm=None):
        c = {
            'settings':settings,
            'subject':subject,
            'from': settings.DEFAULT_FROM_EMAIL,
            "body": body,
            'group': self,
            'sent_to': None,
        }
        sent_to = []
        c.update(context)
        members = self.getMembers(role=role, perms=perms, as_member=True)
        for m in members:
            if "invalid" in m.email:
                continue
            # print m.email
            c["to"] = m.email
            sent_to.append(m.email)
            c["user"] = m
            rest_mail.render_to_mail(template, c)

        if master_perm:
            c["to"] = Member.GetWithPermission(master_perm, email_list=True)
            c["sent_to"] = c["to"]
            if c["to"]:
                rest_mail.render_to_mail(template, c)

    def sendChangeEvent(self, component, component_id, name="group.change", custom=None):
        if not custom:
            custom = {}
        custom["group_id"] = self.id
        RemoteEvents.sendToGroup(self,
            name,
            component=component,
            component_id=component_id,
            custom=custom)

    def getStats(self):
        return {
            "members": self.memberships.count(),
            "active": self.memberships.filter(state__gte=0).count(),
            "pending_invites": self.memberships.filter(state__in=[-10,-9]).count()
        }

    # returns string list of merchants PTIDs for a given kind
    def getPtids(self, kind, processor_name=None):
        if kind == "atm":
            model_class = "ATMProcessor"
            ptid_field = 'terminal_uid'
        elif kind == "cc":
            model_class = "CheckProcessor"
            ptid_field = 'mid1'
        elif kind == "qc":
            model_class = "QCProcessor"
            ptid_field = 'terminal_uid'
        elif kind == "pos":
            model_class = "POSProcessor"
            ptid_field = 'tid' 
        else:
            return []
        model = RestModel.restGetModel("payauth", model_class)
        qset = model.objects.filter(merchant=self)
        if processor_name:
            qset = qset.filter(name=processor_name)
        return qset.values_list(ptid_field, flat=True)

    def logEvent(self, kind, component=None, component_id=None, note=None):
        return GroupFeed.log(self, kind, component, component_id, note)

    def on_rest_saved(self, request):
        if request.member:
            note = "edited group {}:{}\n{}".format(self.name, self.pk, request.DATA.asDict())
            request.member.log("group_edit", note, method="group")
            self.logEvent("group_edit", component="account.Member", component_id=request.member.id, note=note)

    def __unicode__(self):
        return self.name

class GroupMetaData(MetaDataBase):
    parent = models.ForeignKey(Group, related_name="properties", on_delete=models.CASCADE)

class GroupTag(models.Model, RestModel):
    created = models.DateTimeField(auto_now=True)
    group = models.ForeignKey(Group, related_name="tags", on_delete=models.CASCADE)
    tag = models.CharField(max_length=80, db_index=True)


# class GroupLink(models.Model, RestModel):
# 	created = models.DateTimeField(auto_now=True)
# 	parent = models.ForeignKey(Group, related_name="children", on_delete=models.CASCADE)
# 	child = models.ForeignKey(Group, related_name="parents", on_delete=models.CASCADE)
# 	tag = models.CharField(max_length=80, db_index=True)


class Status(models.Model):
    kind = models.IntegerField(default=0)
    text = models.CharField(max_length=200)
    created = models.DateTimeField(auto_now=True)
    who = models.ForeignKey("Membership", related_name="status_history", on_delete=models.CASCADE)
    by = models.ForeignKey("Member", related_name="+", default=None, on_delete=models.CASCADE)

    def __unicode__(self):
        return "{0}: '{1}'".format(self.who.member.username, self.text)

class Membership(models.Model, RestModel):
    class RestMeta:
        CAN_DELETE = True
        SEARCH_FIELDS = ["role", "member__username", "member__first_name", "member__last_name", "member__email"]
        SEARCH_TERMS = [
            ("username", "member__username"),
            ("email", "member__email"),
            ("first_name", "member__first_name"),
            ("last_name", "member__last_name"),
            ("last_activity", "member__last_activity#datetime"),
            ("created", "member__datejoined#datetime"),
            ("perms", "permissions__name"),
            "role"]
        GRAPHS = {
            "base": {
                "fields":[
                    'id',
                    'created',
                    ('member.id','member_id'),
                    ('member.email','email'),
                    'role',
                    'status',
                    'state',
                    'perms'
                ],
                "recurse_into": [("member", "")],
                "graphs":{
                    "member":"basic"
                },
            },
            "basic": {
                "fields":[
                    'id',
                    'created',
                    ('member.id','member_id'),
                    ('member.email','email'),
                    'role',
                    'status',
                    'state',
                    'perms'
                ],
                "recurse_into": [("member", "")],
                "graphs":{
                    "member":"basic",
                    "group":"basic",
                },
            },
            "default": {
                "graphs":{
                    "self":"basic",
                }
            },
            "detailed": {
                "fields":[
                    'id',
                    'created',
                    ('member.id','member_id'),
                    ('member.email','email'),
                    'role',
                    'status',
                    'state',
                    'perms'
                ],
                "recurse_into": [("member", "")],
                "graphs":{
                    "member":"detailed",
                }
            },

            "rauth": {
                "fields":[
                    'id',
                    'created',
                    'role',
                    'status',
                    'state',
                    'perms'
                ],
                "graphs":{
                    "group": "basic"
                }
            },

            "track": {
                "graphs":{
                    "self":"basic"
                },
                "recurse_into": [
                    ("getInvite", "invitation"),
                    ("invitation.invited_by", "by"),
                    ("invitation.track",""),
                ]
            }
        }

    member = models.ForeignKey(Member, related_name="memberships", on_delete=models.CASCADE)
    group = models.ForeignKey(Group, related_name="memberships", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    role = models.CharField(max_length=64, blank=True, null=True, default=None)
    status = models.ForeignKey("Status", blank=True, null=True, default=None, on_delete=models.CASCADE)
    state = models.IntegerField(default=0)

    DEFAULT_ROLE = "guest"

    def set_perms(self, value):
        request = RestModel.getActiveRequest()
        if not request.member.hasPerm(["manage_users", "manage_staff"]):
            # need more permissions, check membership
            ms = self.group.getMembership(request.member)
            if not ms.hasPerm("manage_members"):
                raise PermisionDeniedException()
        if isinstance(value, dict):
            for k, v in list(value.items()):
                if v in [1, "1", True, "true"]:
                    self.addPerm(k)
                elif v in [0, "0", False, "false"]:
                    self.removePerm(k)
        elif isinstance(value, list):
            perms = self.perms
            for k in perms:
                if k not in value:
                    self.removePerm(k)
            for k in value:
                self.addPerm(k)

    def __init__(self, *args, **kwargs):
        super(Membership, self).__init__(*args, **kwargs)

    @property
    def is_enabled(self):
        return self.state >= -10

    def save(self, *args, **kwargs):
        if getattr(self, 'role', None) is None or self.role == "":
            self.role = self.DEFAULT_ROLE
        super(Membership, self).save(*args, **kwargs)

    def getInvite(self):
        return self.group.invited.filter(user=self.member).first()

    def changeStatus(self, text, kind=0, by=None):
        if by is None:
            by = self
        status = Status(kind=kind, text=text, who=self, by=by)
        status.save()
        self.status = status
        self.save()
        return self.status

    def addPerm(self, perm):
        if not self._hasPerm(perm):
            # detailed audits
            request = RestModel.getActiveRequest()
            reason = ""

            if "reason" in request.DATA:
                reason = request.DATA.get("reason").strip()

            if request and request.member:
                self.member.log("add_perm", "{} gave perm {} for {}; {}".format(request.user.username, perm, self.group.name, reason), method="membership_perm")
                request.member.log("gave_perm", "gave perm {} for {} to {}; {}".format(perm, self.group.name, self.member.username, reason), method="membership_perm")
            else:
                self.member.log("add_perm", "system gave perm {} for {}".format(perm, self.group.name), method="membership_perm")
            p = Permission(membership=self, name=perm)
            p.save()
        return True

    def removePerm(self, perm):
        request = RestModel.getActiveRequest()
        reason = ""

        if request and "reason" in request.DATA:
            reason = request.DATA.get("reason").strip()

        if request and request.member:
            self.member.log("remove_perm", "{} removed perm {} for {}; {}".format(request.user.username, perm, self.group.name, reason), method="membership_perm")
            request.member.log("removed_perm", "removed perm {} for {} to {}; {}".format(perm, self.group.name, self.member.username, reason), method="membership_perm")
        else:
            self.member.log("add_perm", "system removed perm {} for {}".format(perm, self.group.name), method="membership_perm")

        if type(perm) is list:
            self.permissions.filter(name__in=perm).delete()
            return
        self.permissions.filter(name=perm).delete()
        return True

    @property
    def perms(self):
        return list(self.permissions.values_list("name", flat=True))

    def _hasPerm(self, perm):
        if type(perm) is list:
            return self.permissions.filter(name__in=perm).count() > 0
        return self.permissions.filter(name=perm).count() > 0

    def checkPermission(self, perm, staff_override=True):
        if staff_override and self.member.is_staff:
            return True

        if not self.is_enabled:
            return False

        if perm == "view":
            return True

        if self._hasPerm(perm):
            return True

        if self.hasRole(perm):
            return True

        return False

    def hasRole(self, role):
        if not self.is_enabled:
            return False

        if type(role) is list:
            return self.role in role
        return self.role == role

    def hasPerm(self, perm):
        if not self.is_enabled:
            return False

        if self.is_admin():
            return True
        if self.hasRole(perm):
            return True
        return self._hasPerm(perm)

    def isAdmin(self):
        if not self.is_enabled:
            return False

        if self._hasPerm(["admin", "owner"]):
            return True
        if self.member.is_staff:
            return True
        return self.role.lower() in ["admin", "owner"]

    def isManager(self):
        if not self.is_enabled:
            return False

        if self._hasPerm(["manager", "admin", "owner", "producer"]):
            return True
        if self.member.is_staff:
            return True
        return self.role in ["manager", "admin", "owner", "producer"]

    def is_admin(self):
        return self.isAdmin()

    def canManageMe(self, member):
        """
        This is a bit flakey, we use the associate role to check for
        a role that we consider a manager in this group
        """
        if member.id == self.member.id:
            return True
        return member.canEdit(self)

    def getSocialStats(self, backend=None):
        """
        backend is None
        returns the total number of friends for all the linked accounts
        """
        return MembershipSocialStats.updateStatsFor(self, True)

    def name(self):
        return self.member.username

    @staticmethod
    def FilterOnline(is_online, qset):
        ids = list(RemoteEvents.smembers("users:online"))
        if is_online:
            qset = qset.filter(member__pk__in=ids)
        else:
            qset = qset.exclude(member__pk__in=ids)
        return qset

    @staticmethod
    def FilterBlocked(is_blocked, qset):
        ids = list(RemoteEvents.hgetall("users:blocked:username"))
        if is_blocked:
            qset = qset.filter(member__username__in=ids)
        else:
            qset = qset.exclude(member__username__in=ids)
        return qset

    def __unicode__(self):
        return "{0}: {1}".format(self.member.username, self.role)

class Permission(models.Model):
    membership = models.ForeignKey(Membership, related_name="permissions", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)

class AuthToken(models.Model, RestModel):
    class RestMeta:
        NO_SHOW_FIELDS = ["token"]
        SEARCH_FIELDS = ["membership__member__username", "membership__member__email", "membership__member__first_name", "membership__member__last_name"]
        GRAPHS = {
            "default":{
                "fields":["created", "ip", "secure_token"],
                "graphs":{
                    "membership":"basic"
                }
            },
            "list":{
                "fields":["created", "ip", "secure_token"],
                "graphs":{
                    "membership":"basic"
                }
            }
        }
    created = models.DateTimeField(auto_now_add=True, editable=False)
    token = models.TextField(db_index=True, unique=True)
    membership = models.ForeignKey(Membership, related_name="auth_tokens", on_delete=models.CASCADE)
    ip = models.CharField(max_length=128, null=True, default=None, blank=True)

    def generateToken(self, commit=True):
        self.token = str(uuid.uuid1())
        if commit:
            self.save()

    @property
    def secure_token(self):
        request = self.getActiveRequest()
        if request:
            if self.membership.member == request.member or request.member.is_superuser:
                return self.token
            if len(self.token) > 6:
                return "{}{}".format("*" * (len(self.token)-4), self.token[-4:])
        return "*" * len(self.token)

    def __unicode__(self):
        return "{o.membership}:{o.ip} <{o.token}>".format(o=self)

class AuthAccount(models.Model, RestModel):
    class RestMeta:
        SEARCH_FIELDS = ["pan", "member__first_name", "member__last_name"]
        NO_SHOW_FIELDS = ["pin"]
        GRAPHS = {
            "default": {
                "graphs": {
                    "member": "basic",
                }
            },
            "list": {
                "graphs": {
                    "self":"default"
                }
            },
            "detailed": {
                "graphs": {
                    "self":"default"
                }
            }
        }

    created = models.DateTimeField(auto_now_add=True, editable=False)
    pan = models.TextField(db_index=True)
    pin = models.CharField(max_length=64, blank=True, null=True, default=None)
    kind = models.CharField(max_length=128, blank=True, null=True, default=None)
    member = models.ForeignKey(Member, related_name="auth_accounts", on_delete=models.CASCADE)
    state = models.IntegerField(default=1, choices=[(0, "disabled"), (1, "enabled")], db_index=True)

    def set_kind(self, kind):
        self.kind = kind
        if kind == "authtoken":
            request = self.getActiveRequest()
            if bool(request):
                pan = request.DATA.get("pan")
                if not pan or len(pan) < 8:
                    # do not let user set pans on auth tokens
                    self.pan = str(uuid.uuid1())
                    # override it in the data to make sure
                    request.DATA.set("pan", self.pan)

    @classmethod
    def queryFromRequest(cls, request, qset):
        if not request.user.is_staff:
            member_id = request.DATA.get(["member", "member_id"])
            if not member_id:
                member_id = request.member.id
            qset = qset.filter(member_id=member_id)
        return super(AuthAccount, cls).queryFromRequest(request, qset)

    @classmethod
    def on_rest_list_filter(cls, request, qset=None):
        if request.group:            
            members = request.group.getMembers(as_member=True)
            qset = qset.filter(member__in=members)
        return qset

    def __unicode__(self):
        return "{o.member} <{o.pan}>".format(o=self)

class MembershipSocialStats(models.Model):
    membership = models.ForeignKey(Membership, related_name="stats", on_delete=models.CASCADE)
    platform = models.CharField(max_length=64, blank=True, null=True, default=None)

    created = models.DateTimeField(auto_now_add=True, editable=True)
    modified = models.DateTimeField(auto_now=True)
    last_aggregation = models.DateTimeField(default=None, blank=True, null=True)

    is_linked = models.BooleanField(blank=True, default=False)

    audience = models.IntegerField(blank=True, default=0)
    views = models.IntegerField(blank=True, default=0)
    shares = models.IntegerField(blank=True, default=0)
    posts = models.IntegerField(blank=True, default=0)

    images = models.IntegerField(blank=True, default=0)
    videos = models.IntegerField(blank=True, default=0)
    links = models.IntegerField(blank=True, default=0)

    @staticmethod
    def updateStatsForPlatform(membership, platform):
        link_name = platform
        if platform == "googleplus":
            link_name = "google"
        link = membership.member.getSocialLink(link_name)
        if platform == "google":
            platform = "googleplus"

        # now lets check out content shares
        stat = MembershipSocialStats.objects.filter(membership=membership, platform=platform).first()
        if not stat:
            stat = MembershipSocialStats(membership=membership, platform=platform)
            stat.save()
        # check if linked
        if not link:
            return stat

        stat.is_linked = True
        q = membership.member.content_shares.filter(content__group=membership.group, shared_to=platform, verified=True)
        stat.posts = q.count()

        if stat.posts:
            val = q.aggregate(total_engagement=Sum('engagement'),total_views=Sum('views'))
            stat.views = val["total_views"]
            stat.shares = val["total_engagement"]
            stat.images = q.filter(content__content_kind='I').count()
            stat.videos = q.filter(content__content_kind='V').count()
            stat.links = q.filter(content__content_kind='E').count()
        # print "audience for: {0}".format(platform)
        audience = membership.member.getProperty("{0}_audience".format(link_name), 0, "social")
        stat.audience = int(audience)
        stat.save()
        return stat

    @staticmethod
    def updateStatsFor(membership, return_dict=False):
        summary = None
        if return_dict:
            summary = {}
        total_videos = 0
        total_images = 0
        total_links = 0
        total_shares = 0
        total_views = 0
        total_posts = 0
        total_audience = 0
        total_received = membership.member.in_flows.count()

        stat_totals = MembershipSocialStats.objects.filter(membership=membership, platform=None).first()
        if not stat_totals:
            stat_totals = MembershipSocialStats(membership=membership, platform=None)
            stat_totals.save()

        next_sync = datetime.now() - timedelta(minutes=5)
        if True or stat_totals.last_aggregation is None or stat_totals.last_aggregation < next_sync:
            stat_totals.last_aggregation = datetime.now()
            stat_totals.save()

            for platform in socialapi.PLATFORMS:
                stat = MembershipSocialStats.updateStatsForPlatform(membership, platform)
                total_shares += stat.shares
                total_views += stat.views
                total_posts += stat.posts
                total_audience += stat.audience
                total_images += stat.images
                total_videos += stat.videos
                total_links += stat.links

                if return_dict:
                    summary[platform] = {
                        "uid": membership.member.getProperty("{0}_uid".format(platform), None, "social"),
                        "username": membership.member.getProperty("{0}_username".format(platform), None, "social"),
                        "email": membership.member.getProperty("{0}_email".format(platform), None, "social"),
                        "avatar": membership.member.getProperty("{0}_avatar".format(platform), None, "social"),
                        "audience": stat.audience,
                        "engagement": stat.shares,
                        "views": stat.views,
                        "posts": stat.posts,
                        "images": stat.images,
                        "videos": stat.videos,
                        "links": stat.links,
                        "is_linked": stat.is_linked,
                    }

            stat_totals.views = total_views
            stat_totals.shares = total_shares
            stat_totals.posts = total_posts
            stat_totals.audience = total_audience
            stat_totals.images = total_images
            stat_totals.videos = total_videos
            stat_totals.links = total_links
            stat_totals.save()

            if return_dict:
                summary["totals"] = {
                    "audience": stat_totals.audience,
                    "engagement": stat_totals.shares,
                    "views": stat_totals.views,
                    "posts": stat_totals.posts,
                    "received": total_received,
                    "notposted": max(total_received-stat_totals.posts, 0),
                    "images": total_images,
                    "videos": total_videos,
                    "links": total_links
                }
                return summary
        elif return_dict:
            for stat in membership.stats.filter(platform__isnull=False):
                summary[stat.platform] = {
                    "uid": membership.member.getProperty("{0}_uid".format(stat.platform), None, "social"),
                    "username": membership.member.getProperty("{0}_username".format(stat.platform), None, "social"),
                    "email": membership.member.getProperty("{0}_email".format(stat.platform), None, "social"),
                    "avatar": membership.member.getProperty("{0}_avatar".format(stat.platform), None, "social"),
                    "is_linked": stat.is_linked,
                    "audience": stat.audience,
                    "engagement": stat.shares,
                    "views": stat.views,
                    "posts": stat.posts,
                    "images": stat.images,
                    "videos": stat.videos,
                    "links": stat.links,
                }
            summary["totals"] = {
                "is_linked": stat.is_linked,
                "audience": stat_totals.audience,
                "engagement": stat_totals.shares,
                "views": stat_totals.views,
                "posts": stat_totals.posts,
                "notposted": max(total_received-stat_totals.posts, 0),
                "received": total_received,
                "images": total_images,
                "videos": total_videos,
                "links": total_links
            }
            return summary
        return stat_totals


class GroupFeed(models.Model, RestModel):
    class RestMeta:
        GRAPHS = {
            "default": {
                "recurse_into":["generic__component"]
            }
        }
    created = models.DateTimeField(auto_now_add=True, editable=True, db_index=True)
    group = models.ForeignKey(Group, related_name="feed", on_delete=models.CASCADE)

    component = models.SlugField(max_length=124, null=True, blank=True, default=None, db_index=True)
    component_id = models.IntegerField(null=True, blank=True, default=None, db_index=True)

    kind = models.SlugField(max_length=32, db_index=True)

    note = models.TextField(null=True, blank=True, default=None)

    @staticmethod
    def log(group, kind, component=None, component_id=None, note=None):
        obj = GroupFeed(group=group, kind=kind, component=component, component_id=component_id, note=note)
        obj.save()
        return obj

# class SecurityGroup(models.Model, RestModel, MetaDataModel):
# 	created = models.DateTimeField(auto_now_add=True, editable=True, db_index=True)
# 	name = models.CharField(max_length=128, db_index=True)
# 	flags = models.CharField(max_length=32, db_index=True)

# class SecurityGroupMember(models.Model, RestModel):
# 	created = models.DateTimeField(auto_now_add=True, editable=True, db_index=True)
# 	sg = models.ForeignKey(SecurityGroup, related_name="memberships", on_delete=models.CASCADE)
# 	member = models.ForeignKey(Member, related_name="security_groups", null=True, blank=True, default=None, on_delete=models.CASCADE)

# class SecurityGroupGroup(models.Model, RestModel):
# 	created = models.DateTimeField(auto_now_add=True, editable=True, db_index=True)
# 	sg = models.ForeignKey(SecurityGroup, related_name="groups", on_delete=models.CASCADE)
# 	group = models.ForeignKey(SecurityGroup, related_name="security_groups", null=True, blank=True, default=None, on_delete=models.CASCADE)


from location.models import GeoLocation, GeoIP
from medialib import youtube


# automatically create the Tasks by Step
@receiver(post_save,sender=Member)
def create_step_tasks(sender,instance, created, **kwargs):
    if created:
        instance.updateUUID()

# automatically create the Tasks by Step
@receiver(post_save,sender=Group)
def create_step_tasks(sender,instance, created, **kwargs):
    if created:
        instance.updateUUID()



# this really should go somewhere else
class SocialAccount(models.Model, RestModel, MetaDataModel):
    modified = models.DateTimeField(auto_now=True)

    state = models.IntegerField(blank=True, default=1)

    platform = models.CharField(db_index=True, max_length=128)
    member = models.ForeignKey("Member", related_name="social_accounts", blank=True, null=True, default=None, on_delete=models.CASCADE)

    url = models.TextField(blank=True, null=True, default=None)
    first_name = models.CharField(max_length=128, blank=True, null=True, default=None)
    last_name = models.CharField(max_length=128, blank=True, null=True, default=None)

    email = models.CharField(max_length=255, blank=True, null=True, default=None)
    username = models.CharField(max_length=255, blank=True, null=True, default=None)
    uid = models.CharField(max_length=255, blank=True, null=True, default=None)
    token = models.TextField()

    audience = models.IntegerField(blank=True, default=0)

    avatar_url = models.TextField(blank=True, null=True, default=None)
    avatar = models.ForeignKey("medialib.MediaItem", default=None, blank=True, null=True, help_text="Profile picture", related_name='+', on_delete=models.CASCADE)

    def setAvatar(self, url):
        """
        This method scrapes the avatar url and caches it locally
        It also creates a rendition called 'source' that keeps the original url
        """
        if not url:
            return None

        self.avatar_url = url
        # now we could check the source, or we could just create a new copy of the image?
        if self.avatar:
            mediarend = self.avatar.get("source")
            if not mediarend or (mediarend and mediarend.url != url):
                self.avatar.updateFromURL(url)
        else:
            MediaItem = RestModel.restGetModel("medialib", "MediaItem")
            avatar = MediaItem.CreateFromURL(url, self.member, kind='I')
            if avatar:
                self.avatar = avatar
                self.avatar.state = 200
                self.avatar.save()
                self.save()
        if not self.member.picture:
            self.member.picture = self.avatar
            self.member.save()

    @staticmethod
    def getByMember(member, platform, uid=None, username=None):
        q = {
            "member":member,
            "platform": platform
        }
        if uid:
            q["uid"] = uid
        if username:
            q["username"] = username
        return SocialAccount.objects.filter(**q).last()

class SocialAccountMetaData(MetaDataBase):
    parent = models.ForeignKey(SocialAccount, related_name="properties", on_delete=models.CASCADE)


class BounceHistory(models.Model, RestModel):
    class RestMeta:
        CAN_SAVE = False
        SEARCH_FIELDS = ["address"]
        SEARCH_TERMS = [("email", "address"), ("to", "address"), "source", "reason", "state", ("user", "user__username")]
        GRAPHS = {
            "default":{
                "graphs":{
                    "user":"basic"
                }
            },
            "list":{
                "graphs":{
                    "user":"basic"
                }
            }
        }
    created = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)
    user = models.ForeignKey(Member, related_name="bounces", null=True, blank=True, default=None, on_delete=models.CASCADE)
    address = models.CharField(max_length=255, db_index=True)
    kind = models.CharField(max_length=32, db_index=True)
    reason = models.TextField(null=True, blank=True, default=None)
    reporter = models.CharField(max_length=255, null=True, blank=True, default=None)
    code = models.CharField(max_length=32, null=True, blank=True, default=None)
    source = models.CharField(max_length=255, null=True, blank=True, default=None)
    source_ip = models.CharField(max_length=64, null=True, blank=True, default=None)

    @staticmethod
    def log(kind, address, reason, reporter=None, code=None, source=None, source_ip=None, user=None):
        obj = BounceHistory(kind=kind, address=address)
        obj.reason = reason
        obj.reporter = reporter
        obj.code = code
        obj.source = source
        obj.source_ip = source_ip
        if user is None:
            user = Member.objects.filter(email=address).last()
            # now lets check our bounced count, if more then 3, we turn off email
            if user:
                user.log("bounced", "{} bounced to {} from {}".format(kind, address, source_ip), method=kind)
                since = datetime.now() - timedelta(days=14)
                bounce_count = BounceHistory.objects.filter(user=user, created__gte=since).count()
                if bounce_count > 2:
                    # TODO notify support an account has been disabled because of bounce
                    user.setProperty("notify_via", "off")
                    user.log("disabled", "notifications disabled because email bounced", method="notify")
        else:
            # TODO notify support of unknown bounce
            pass
        obj.user = user
        obj.save()



class NotificationRecord(models.Model, RestModel):
    class RestMeta:
        CAN_SAVE = CAN_CREATE = False
        DEFAULT_SORT = "-created"
        SEARCH_FIELDS = ["subject"]
        SEARCH_TERMS = ["subject", ("to", "to__to_addr"), "body", "reason", "state", ("from", "from_addr")]
        GRAPHS = {
            "list":{
                "fields": ["id", ("get_state_display", "state_display"), "created", "subject", "from_addr", "to_emails", "reason", "state", "attempts"],
            },
            "default":{
                "extra":["to_emails", ("get_state_display", "state_display")]
            }
        }
    created = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)
    modified = models.DateTimeField(auto_now=True, editable=False)
    method = models.CharField(max_length=128, default="email", db_index=True)

    from_addr = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    body = models.TextField()
    reason = models.TextField()
    # new=0, queued=-5, sent=1
    state = models.IntegerField(default=0, choices=[(0, "new"),(-5, "queued"), (1, "sent"), (-10, "failed")], db_index=True)
    attempts = models.IntegerField(default=0)

    @property
    def to_emails(self):
        return list(self.to.all().values_list("to_addr", flat=True))

    def send(self, member_records=None):
        email_to = []
        save_records = True
        if not member_records:
            member_records = self.to.all()
            save_records = False
        for r in member_records:
            email_to.append(r.to_addr)
            if save_records:
                r.notification = self
                r.save()
        if NotificationRecord.canSend():
            try:
                rest_mail.send(email_to,
                    self.subject,
                    self.body,
                    attachments=self.attachments.all(),
                    do_async=True
                )
                # self.reason = "sent"
                self.state = 1
            except Exception as err:
                self.reason = str(err)
                self.attempts += 1
                if self.attempts >= 3:
                    self.state = -10
                else:
                    self.state = -5
            self.save()
            return True
        if self.state != -5:
            self.state = -5
            self.save()
        return False

    def attach(self, name, mimetype, data):
        atmnt = NotificationAttachment(notification=self, name=name, mimetype=mimetype, data=data)
        atmnt.save()
        return atmnt

    def addAttachments(self, attachments):
        if not attachments:
            return False
        for a in attachments:
            if type(a) in [str, str]:
                # TODO handle file inport
                pass
            else:
                self.attach(a.name, a.mimetype, a.data)

    @classmethod
    def canSend(cls):
        max_emails_per_minute = getattr(settings, "MAX_EMAILS_PER_MINUTE", 30)
        last_email = NotificationRecord.objects.filter(state=1).last()
        now = datetime.now()
        if last_email and (now - last_email.created).total_seconds() < 30:
            # we sent an email less then a minute ago
            # now we can to count the number of message sent in last minute
            when = now - timedelta(seconds=60)
            sent = NotificationRecord.objects.filter(state=1, created__gte=when).count()
            return sent < max_emails_per_minute
        return True

    @classmethod
    def notifyFromEmails(cls, emails, subject, message=None, template=None, context=None, email_only=False, sms_msg=None, force=False, from_email=settings.DEFAULT_FROM_EMAIL, attachments=[]):
        members = Member.objects.filter(email__in=emails)
        cls.notify(members, subject, message, template, context, email_only, sms_msg, force, from_email, attachments)

    @classmethod
    def notify(cls, notify_users, subject, message=None, template=None, context=None, email_only=False, sms_msg=None, force=False, from_email=settings.DEFAULT_FROM_EMAIL, attachments=[]):
        # this will create a record for each email address message is sent to
        from telephony.models import SMS
        email_to = []
        email_list = []
        sms_to = []

        if not message and not template and subject:
            message = subject

        if not sms_msg and subject:
            sms_msg = subject
        if not sms_msg and message:
            sms_msg = message

        if subject and len(subject) > 80:
            epos = subject.find('. ') + 1
            if epos > 10:
                subject = subject[:epos]
            else:
                subject = subject[:80]
                subject = subject[:subject.rfind(' ')] + "..."

        if template:
            # render message now so we can save message
            message = rest_mail.renderBody(message, template, context)
            template = None
            context = None

        email_record = None
        for member in notify_users:
            via = member.getProperty("notify_via", "all")
            phone = member.getProperty("phone")
            email = member.email
            valid_email = email != None and "@" in email and "invalid" not in email
            allow_sms = not email_only and phone and (force or via in ["all", "sms"])
            allow_email = valid_email and (force or via in ["all", "email"])
            if not allow_email and not allow_sms:
                continue
            if allow_email and email not in email_list:
                email_list.append(email)
                nr = NotificationMemberRecord(member=member, to_addr=email)
                email_to.append(nr)
            if not email_only and allow_sms and phone not in sms_to:
                sms_to.append(phone)

        if sms_to:
            for phone in sms_to:
                SMS.send(phone, sms_msg)

        if email_to:
            # lets verify the db is working
            email_record = NotificationRecord(
                method="email",
                subject=subject,
                from_addr=from_email,
                body=message
                )
            try:
                email_record.save()
                email_record.addAttachments(attachments)
                email_record.send(email_to)
            except Exception as err:
                print(("failed to create record: {}".format(str(err))))
                # we need to send emails the old way
                addrs = []
                for to in email_to:
                    addrs.append(to.to_addr)
                rest_mail.send(addrs,
                    subject,
                    message,
                    attachments=attachments,
                    do_async=True
                )


class NotificationAttachment(models.Model, RestModel):
    created = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)
    notification = models.ForeignKey(NotificationRecord, related_name="attachments", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    mimetype = models.CharField(max_length=255)
    data = models.TextField()

class NotificationMemberRecord(models.Model, RestModel):
    created = models.DateTimeField(auto_now_add=True, editable=False, db_index=True)
    member = models.ForeignKey(Member, related_name="notifications", on_delete=models.CASCADE)
    notification = models.ForeignKey(NotificationRecord, related_name="to", on_delete=models.CASCADE)
    to_addr = models.CharField(max_length=255, db_index=True)




