
from account.models import User, Member, Group, Membership, AuthAccount, PasswordHistory

from social_django.models import UserSocialAuth
import social_core.exceptions
from social_django.utils import load_strategy, load_backend

from django.contrib.auth import login as auth_login, logout as auth_logout, authenticate
from django.contrib.auth.forms import PasswordResetForm
import django.middleware.csrf

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import int_to_base36
from django.core.cache import cache

import random
import string
import uuid

from rest.decorators import *
from rest.views import *
from rest import search
from rest import helpers
from medialib.qrcode import generateQRCode


def member_force_login(request, user, kind=None):
    if not user:
        return restStatus(request, False, error="Incorrect login", error_code=422)
    if not user.is_active:
        return restStatus(request, False, error="Account disabled", error_code=410)

    try:
        user.member
    except Member.DoesNotExist:
        member = Member(user_ptr = user)
        for f in user._meta.local_fields: setattr(member, f.name, getattr(user, f.name))
        member.save()

    try:
        user.member.locateByIP(request.ip)
    except:
        pass

    auth_login(request, user)

    user.log("social_login", "{} login".format(kind), request, method="login")
    graph = request.DATA.get("graph", "default")
    #stat = Stat.log(request=request, component="account", action="login", subtype=kind)
    return restGet(request, user.member,  **Member.getGraph(graph))
    #return restStatus(request, True, profile=restGet(request, user.member,  accept_list=['data'], **Member.getGraph("default")))

@urlPOST (r'^login$')
@urlPOST (r'^login/$')
@never_cache
def member_login(request):
    """
    | param: username = username to login with
    | param: password = password used for auth

    | Return: status + error

    | Login
    """

    username = request.DATA.get('username', "").lower()
    password = request.DATA.get('password', None)
    pan = request.DATA.get('pan', None)
    pin = request.DATA.get('pin', None)
    invite_token = request.DATA.get('invite_token', None)

    if pan:
        act = AuthAccount.objects.filter(pan=pan).last()
        if not act:
            return restStatus(request, False, error="Account not found", error_code=404)
        if act.pin and pin != act.pin:
            # requires a pin
            return restStatus(request, False, error="Invalid PIN", error_code=444)

        # TODO MUST CHECK FOR PIN HERE!!!
        user = act.member.user_ptr
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(request, user)
        act.member.log("pan_login", "pan+pin login", request, method="login")
        graph = request.DATA.get("graph", "default")
        return restGet(request, act.member,  **Member.getGraph(graph))
    if invite_token:
        invite_token = invite_token.replace('-', '').replace(' ', '')
        if username:
            if '@' in username:
                member = Member.objects.filter(email=username, invite_token=invite_token).last()
            else:
                member = Member.objects.filter(username=username, invite_token=invite_token).last()
        else:
            member = Member.objects.filter(invite_token=invite_token).last()
        if not member:
            return restStatus(request, False, error="token expried", error_code=422)
        user = member.user_ptr
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(request, user)
        member.log("token_login", "token login", request, method="login")
        graph = request.DATA.get("graph", "me")
        # if a password is included with the invite token
        # we will use that as well
        password = request.DATA.get("password")
        if password:
            member.log("password_change", "token password change", request, method="password")
            member.setPassword(password)
            member.save()
        member.invite_token = None
        member.save()
        return restGet(request, member,  **Member.getGraph(graph))
    if not username:
        return restStatus(request, False, error="Username is required")
    if not password:
        return restStatus(request, False, error="Password is required")

    member = None
    if username.count('@') == 1:
        user = User.objects.filter(email=username).last()
        if user:
            member = user.getMember()

    if not member:
        member = Member.objects.filter(username=username).last()

    if not member:
        return restStatus(request, False, error="Password or Username is incorrect", error_code=422)
    if not member.is_active:
        member.log("login_blocked", "account is not active", request, method="login")
        return restStatus(request, False, error="Account disabled", error_code=410)
    if member.is_blocked:
        member.log("login_blocked", "account is locked out", request, method="login")
        return restStatus(request, False, error="Account locked out", error_code=411)
    if member.hasPasswordExpired():
        member.log("login_blocked", "password has expired", request, method="login")
        return restStatus(request, False, error="password expired", error_code=412)
    if member.requires_topt:
        totp_code = request.DATA.get("totp_code", None)
        if totp_code is None:
            member.log("login_blocked", "requires MFA (TOTP)", request, method="login")
            return restStatus(request, False, error="requires MFA (TOTP)", error_code=455)
        if not member.totp_verify(totp_code):
            member.log("login_blocked", "invalid MFA code", request, method="login")
            return restStatus(request, False, error="invalid MFA code", error_code=456)
    if not member.login(request=request, password=password):
        member.log("login_failed", "incorrect password", request, method="login")
        return restStatus(request, False, error="Password or Username is incorrect", error_code=401)

    graph = request.DATA.get("graph", "me")
    member.log("password_login", "password login", request, method="login")

    #stat = Stat.log(request=request, component="account", action="login", subtype=kind)
    return restGet(request, member,  **Member.getGraph(graph))

    # user = authenticate(username=username, password=password)
    # return member_force_login(request, user, 'password')

@url (r'^login/(?P<backend>[a-zA-Z0-9_.-]+)$')
@never_cache
def member_login_social(request, backend):
    """
    | param: backend = social auth backend (facebook, google, twitter)
    | param: token = this is the token passed from the oauth
    | param: email = this is needed if this is an unknown account
    | param: first_name = this is needed if this is an unknown account
    | param: last_name = this is needed if this is an unknown account
    | param: link_account = this

    | Return: user_graph

    | Login using social token
    """
    strategy = load_strategy(request)
    back = load_backend(strategy, backend, "")

    if not back:
        msg = "invalid social backend '{0}' got {1}".format(backend, back)
        print(msg)
        return restStatus(request, False, error="invalid social backend '{0}'".format(back))
    link_account = request.DATA.get("link_account", False)
    is_authenticated = request.user.is_authenticated
    user = None
    if link_account in ["1", 1, "t", "T", "true", "True", True]:
        if not is_authenticated:
            return restStatus(request, False, error="you can not link an account when you are not logged in!")
        link_account = True
        user = request.user
    else:
        link_account = False

    print('----- SOCIAL LOGIN --------')
    print((request.DATA))

    if 'token' in request.DATA:
        token = request.DATA.get('token')
    elif 'access_token' in request.DATA:
        token = request.DATA.get('access_token')
    else:
        return restStatus(request, False, error="NO TOKEN SENT")

    refresh_token = None
    mobile_token = None
    if 'refresh_token' in request.DATA:
        # TODO: FIXME this is just a hack until mobile sends mobile_token
        mobile_token = request.DATA.get('refresh_token')
        print("RECEIVED refresh_token")

    if 'mobile_token' in request.DATA:
        mobile_token = request.DATA.get('mobile_token')
        print("RECEIVED mobile_token")


    if mobile_token is None and refresh_token is None:
        print("NO REFRESH/MOBILE TOKEN RECEIVED")

    try:
        if refresh_token:
            user = back.do_auth(token, refresh_token=refresh_token, user=user, request=request)
        elif mobile_token:
            user = back.do_auth(token, mobile_token=mobile_token, user=user, request=request)
        else:
            user = back.do_auth(token, request=request, user=user)

        if link_account and user != request.user:
            print("SOCIAL LINK FAILED: ACCOUNT ALREADY EXISTS FOR A DIFFERENT USER!")
            return restStatus(request, True, message="Account already exists, not linking!")

    except social_core.exceptions.AuthTokenError:
        return restStatus(request, False, error="Invalid Token - Possibly expired?")
    except forms.ValidationError as err:
        return restStatus(request, False, error="New User Data Invalid: {0}".format(err))

    if user and user.is_active:
        return member_force_login(request, user, backend)
    if user:
        member.log("login_blocked", "blocked social login, account disabled", request, method="login")
        return restStatus(request, False, error="invalid user - contact admin - uid: {0}".format(user.id))
    return restStatus(request, False, error="auth failed to create user - contact admin")

@urlPOST (r'^unlink/(?P<backend>[a-zA-Z0-9_.-]+)$')
@login_required
def member_unlink_social(request, backend):
    links = UserSocialAuth.objects.filter(user=request.user, provider=backend)
    if links.count():
        request.user.log("unlock_social", "removed social link to {}".format(backend), request, method="unlink")

        links.delete()
        return restStatus(request, True)
    return restStatus(request, False, error="not linked to backend")

@url (r'^loggedin/$')
@never_cache
def is_member_logged_in(request):
    """
    | param: none

    | Return: status + error

    | Check if the current user is logged in
    """
    if request.user:
        return restStatus(request, request.user.is_authenticated, csrf=django.middleware.csrf.get_token(request))
    return restStatus(request, False, csrf=django.middleware.csrf.get_token(request))

@url (r'^logout$')
@url (r'^logout/$')
@never_cache
def member_logout(request):
    """
    | Parameters: none

    | Return: status + error

    | Logout
    """
    if request.user.is_authenticated:
        request.user.log("logout", "user logged out", request, method="logout")
    auth_logout(request)
    return restStatus(request, True)

@urlPOST (r'^updatews/$')
@login_required
def member_update_session(request):
    me = Member.getByUser(request.user)
    request.session['ws4redis:memberof'] = me.getGroupUUIDs()
    return restStatus(request, True)


@urlPOST (r'^forgot$')
@urlPOST (r'^forget/$')
@never_cache
def member_forgot_password(request):
    """
    | param: username = use the username as the lookup
    | param: email = use the email as the lookup

    | Return: status + error

    | Send fgroupet password reset instructions
    """

    username = request.DATA.get('username', "").strip().lower()
    if not username:
        return restStatus(request, False, error="Username is required")

    member = Member.objects.filter(username=username)
    if len(member) == 0:
        member = Member.objects.filter(email=username)
    if len(member) == 0:
        return restStatus(request, False, error="User not found")
    member = member[0]
    if not member.is_active:
        member.log("login_blocked", "account is not active", request, method="forgot")
        return restStatus(request, False, error="Account disabled", error_code=410)

    if request.DATA.get("use_code", False):
        # ok we are going to use a simple invite code
        N = 6
        # code = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(N))
        # verify no one else has this token, this is weak
        code = None
        for i in range(0, 100):
            code = ''.join(random.choice(string.digits) for _ in range(N))
            if Member.objects.filter(invite_token=code).count() == 0:
                break

        member.invite_token = code
        member.save()
        code = "{} {}".format(code[:3], code[3:])
        context = {
            "request": request,
            "user": member,
            "code": code,
        }

        if member.notify(
                context=context,
                email_only=False,
                force=True,
                subject="Login Code",
                template="email/reset_code.html",
                sms_msg="Your login code is:\n{}".format(code)
            ):
            member.log("requested", "user requested password reset code", request, method="login_token")
            return restStatus(request, True)
        member.log("error", "No valid email/phone, check users profile!", request, method="login_token")
        return restStatus(request, False, error="No valid email/phone, check users profile!")

    token = int_to_base36(member.id) + '-' + default_token_generator.make_token(member)
    render_to_mail("registration/password_reset_email", {
        'user': member,
        'uuid': member.uuid,
        'token': token,
        'subject': 'password reset',
        'to': [member.email],
    })
    member.log("forgot", "user requested password reset", request, method="password_reset")
    return restStatus(request, True, msg="Password reset instructions have been sent to your email.")

@urlPOST (r'^password_change$')
@urlPOST (r'^password_change/$')
@never_cache
def member_password_change(request):
    current = request.DATA.get(["current", "current_password", "current_pword"])
    username = request.DATA.get("username", "").lower()
    password = request.DATA.get("password")
    member = None
    if username.count('@') == 1:
        user = User.objects.filter(email=username).last()
        member = user.getMember()

    if not member:
        member = Member.objects.filter(username=username).last()

    if not member:
        return restStatus(request, False, error="Password or Username is incorrect", error_code=404)

    if not member.checkPassword(current):
        member.log("incorrect_password", "password change failed, incorrect current password", request, method="password_change")
        return restStatus(request, False, error="Password or Username is incorrect", error_code=422)

    if not member.setPassword(password):
        return restStatus(request, False, error="password is weak or duplicate");
    return restStatus(request, True)


@urlPOST (r'^linkcard$')
@urlPOST (r'^linkcard/$')
@login_required
def linkcard(request):
    pan = request.DATA.get(["pan", "cardnumber"])
    pin = request.DATA.get("pin")
    if not pan:
        return restStatus(request, False, error="no card data")
    act = AuthAccount.objects.filter(pan=pan).last()
    if act:
        if act.member != request.member:
            return restStatus(request, False, error="Card is already linked a different account.")
        if pin and act.pin != pin:
            act.pin = pin
            act.save()
        return restStatus(request, True)
    act = AuthAccount(member=request.member, pan=pan, pin=pin)
    act.save()
    return restStatus(request, True)

@urlGET (r'^can_access$')
@urlGET (r'^can_access/$')
@login_optional
def can_access(request):
    pan = request.DATA.get(["pan", "cardnumber"])
    pin = request.DATA.get("pin")
    perm = request.DATA.get("perm")
    if not pin and not request.member:
        return restPermissionDenied(request, "permission denied")

    if not perm:
        return restPermissionDenied(request, "requires perm")
    group_id = request.DATA.get("group")
    if not pan:
        return restStatus(request, False, error="no card data")
    act = AuthAccount.objects.filter(pan=pan).last()
    if not act:
        return restPermissionDenied(request, "account not authorized")

    if pin and act.pin != pin:
        act.member.log("can_access", "card *{} can_access, incorrect pin".format(pan[:-4]), request, method="login")
        return restStatus(request, False, error="incorrect pin")

    # now check permissions
    if group_id:
        group = Group.objects.filter(pk=group_id).last()
        if not group or not group.hasPerm(act.member, perm) and not act.member.hasPerm(perm):
            act.member.log("can_access", "card *{} can_access({}), denied group access".format(pan[:-4], perm), request, method="login")
            return restPermissionDenied(request, "card does not have group access")
    if not act.member.hasPerm(perm):
        act.member.log("can_access", "card *{} can_access({}), denied access".format(pan[:-4], perm), request, method="login")
        return restPermissionDenied(request, "card does not have access")
    return restStatus(request, True)

@urlPOST(r'^token/generate$')
@login_required
def auth_token_generate(request):
    msid = request.DATA.get(["membership", "ms"], None)
    if not msid:
        return restPermissionDenied(request, error="requires membership")
    ms = Membership.objects.filter(id=msid).last()
    if request.member != ms.member and not request.member.is_superuser:
        return restPermissionDenied()
    ip = request.DATA.get("ip", None)
    auth_token = AuthToken(token=str(uuid.uuid1()), membership=ms, ip=ip)
    auth_token.save()
    return restStatus(request, True, token=auth_token)

@url(r'^token/$')
@url(r'^token/(?P<pk>\d+)$')
@login_required
def auth_token_handler(request, pk=None):
    if not request.is_staff:
        # we can only edit auth tokens for which we are the owner
        if pk is None:
            qset = AuthToken.objects.filter(membership__member=request.member)
            return AuthToken.on_rest_list(request, qset)
        token = AuthToken.objects.filter(membership__member=request.member, pk=pk).last()
        if not token:
            return restNotFound(request)
    return AuthToken.on_rest_request(request, pk)

@url(r'^token/verify$')
@login_required
def authoken_verify(request):
    return restGet(request, request.member, **Member.getGraph("default"))

"""
Remote Authentication allows remote systems to authenticate users
via a 'remote' server.

step1 client should request a rauth_token from the auth server.
step2 client should attempt to use the rauth_token with a server.
the server will then validate the rauth_token with the auth server.
"""
def generateRauthToken():
    return str(uuid.uuid1())

@urlGET(r'^rauth/generate$')
@login_required
def rauth_token_generate(request):
    #rauth tokens are only good for one hour
    rauth_token = cache.get_or_set('rauth_token_{}'.format(request.member.pk), generateRauthToken, 3600)
    # every time we request it we give it new life
    cache.set(rauth_token, request.member.pk, 3600)
    return restStatus(request, True, rauth_token=rauth_token)

@urlPOST(r'^rauth/auth$')
def rauth_token_auth(request):
    rauth_token = request.DATA.get("rauth_token", None)
    if not rauth_token:
        return restPermissionDenied(request, "token required")
    pk = cache.get(rauth_token, None)
    if not pk:
        return restPermissionDenied(request, "token expired")
    member = Member.objects.filter(pk=pk).last()
    if not member:
        return restPermissionDenied(request, "invalid token")
    return member.restGet(request, graph="rauth")


@urlPOST (r'^password_history$')
@urlPOST (r'^password_history/$')
@staff_required
def clearPasswordHistory(request):
    pk = request.DATA.get(["member", "member_id"])
    if not pk:
        return restStatus(request, False, error="no data")
    member = Member.objects.filter(pk=pk).last()
    if member:
        PasswordHistory.objects.filter(owner=member).delete()
    return restStatus(request, True)


# time based one time passwords
@urlGET(r'^totp/qrcode$')
@login_required
def totp_qrcode(request):
    token = request.member.getProperty("totp_token", category="secrets", default=None)
    reset = request.DATA.get("force_reset", False)
    if token is not None and not reset:
        return restPermissionDenied(request, "token exists")
    params = dict(data=request.member.totp_getURI())
    error = request.DATA.get("error", None)
    if error is not None:
        params["error"] = error
    version = request.DATA.get("version", None)
    if version is not None:
        params["version"] = int(version)
    img_format = request.DATA.get("format", "png")
    if img_format is not None:
        params["img_format"] = img_format
    scale = request.DATA.get("scale", 4)
    if scale is not None:
        params["scale"] = int(scale)
    code = generateQRCode(**params)
    if img_format == "base64":
        return HttpResponse(code, content_type="text/plain")
    elif img_format == "svg":
        return HttpResponse(code, content_type="image/svg+xml")
    return HttpResponse(code, content_type="image/png")


# time based one time passwords
@urlPOST(r'^totp/verify$')
@login_required
def totp_verify(request):
    code = request.DATA.get("code", None)
    if code is None or len(code) != 6:
        return restPermissionDenied(request, "invalid code format")
    if not request.member.totp_verify(code):
        return restPermissionDenied(request, "invalid code")
    return restStatus(request, True)


