from rest import decorators as rd
from rest import crypto
from rest.mail import render_to_mail
from rest.views import restStatus, restPermissionDenied
from account.models import Member
from medialib.qrcode import generateQRCode
from django.http import HttpResponse


@rd.urlPOST(r'^login$')
@rd.urlPOST(r'^login/$')
@rd.never_cache
def member_login(request):
    username = request.DATA.get('username', None)
    auth_code = request.DATA.get(["auth_code", "code"], None)
    if username and auth_code:
        return member_login_uname_code(request, username, auth_code)
    password = request.DATA.get('password', None)
    if username and password:
        return member_login_uname_pword(request, username, password)
    return restStatus(request, False, error="Invalid credentionals", error_code=401)


def getMemberByUsername(username):
    member = None
    username = username.lower()
    if username.count('@') == 1:
        member = Member.objects.filter(email=username).last()
    if not member:
        member = Member.objects.filter(username=username).last()
    return member


def member_login_uname_pword(request, username, password):
    member = getMemberByUsername(username)

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

    member.log("password_login", "password login", request, method="login")
    return member.restGet(request, graph="me")


def member_login_uname_code(request, username, auth_code):
    member = getMemberByUsername(username)
    if not member:
        return restStatus(request, False, error="Password or Username is incorrect", error_code=422)
    if not member.is_active:
        member.log("login_blocked", "account is not active", request, method="login")
        return restStatus(request, False, error="Account disabled", error_code=410)
    if member.is_blocked:
        member.log("login_blocked", "account is locked out", request, method="login")
        return restStatus(request, False, error="Account locked out", error_code=411)
    auth_code = auth_code.replace('-', '').replace(' ', '')
    if member.auth_code != auth_code:
        return restPermissionDenied(request, "token expired", error_code=422)
    password = request.DATA.get('password', None)
    if password:
        member.setPassword(password)
    member.auth_code = None
    member.save()
    member.login(request=request)
    member.log("code_login", "code login", request, method="login")
    return member.restGet(request, graph="me") 


@rd.url(r'^logout$')
@rd.url(r'^logout/$')
@rd.never_cache
def member_logout(request):
    """
    | Parameters: none

    | Return: status + error

    | Logout
    """
    if request.user.is_authenticated:
        request.user.log("logout", "user logged out", request, method="logout")
    request.member.logout(request)
    return restStatus(request, True)


@rd.url(r'^loggedin/$')
@rd.never_cache
def is_member_logged_in(request):
    """
    | param: none

    | Return: status + error

    | Check if the current user is logged in
    """
    if request.user:
        return restStatus(request, request.user.is_authenticated)
    return restStatus(request, False)


@rd.urlPOST (r'^forgot$')
@rd.urlPOST (r'^forget/$')
@rd.never_cache
def member_forgot_password(request):
    """
    | param: username = use the username as the lookup
    | param: email = use the email as the lookup

    | Return: status + error

    | Send fgroupet password reset instructions
    """
    username = request.DATA.get('username', None)
    if not username:
        return restStatus(request, False, error="Username is required")
    member = getMemberByUsername(username)
    if not member:
        return restStatus(request, False, error="Password or Username is incorrect", error_code=422)
    if not member.is_active:
        member.log("login_blocked", "account is not active", request, method="login")
        return restStatus(request, False, error="Account disabled", error_code=410)
    if member.is_blocked:
        member.log("login_blocked", "account is locked out", request, method="login")
        return restStatus(request, False, error="Account locked out", error_code=411)

    if request.DATA.get("use_code", False):
        return member_forgot_password_code(request, member)

    member.auth_code = crypto.get_random_string(16)
    member.save()
    member.log("forgot", "user requested password reset", request, method="password_reset")

    token = "{}-{}".format(crypto.obfuscate_id(member.id), member.auth_code)
    render_to_mail("registration/password_reset_email", {
        'user': member,
        'uuid': member.uuid,
        'token': token,
        'subject': 'password reset',
        'to': [member.email],
    })

    return restStatus(request, True, msg="Password reset instructions have been sent to your email.")


def member_forgot_password_code(request, member):
    member.auth_code = Member.generateAuthCode(6)
    member.save()
    code = "{} {}".format(member.auth_code[:3], member.auth_code[3:])
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
            sms_msg="Your login code is:\n{}".format(code)):
        member.log("requested", "user requested password reset code", request, method="login_token")
        return restStatus(request, True)
    member.log("error", "No valid email/phone, check users profile!", request, method="login_token")
    return restStatus(request, False, error="No valid email/phone, check users profile!")


# time based one time passwords
@rd.urlGET(r'^totp/qrcode$')
@rd.login_required
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
@rd.urlPOST(r'^totp/verify$')
@rd.login_required
def totp_verify(request):
    code = request.DATA.get("code", None)
    if code is None or len(code) != 6:
        return restPermissionDenied(request, "invalid code format")
    if not request.member.totp_verify(code):
        return restPermissionDenied(request, "invalid code")
    return restStatus(request, True)




