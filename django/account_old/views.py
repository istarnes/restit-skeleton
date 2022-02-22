from .models import *
from .forms import *
from .fields import COUNTRIES

from django.views.decorators.cache import never_cache
from account.models import User
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.tokens import default_token_generator
from django.http import Http404, HttpResponseRedirect
from django.utils.http import base36_to_int
from django.shortcuts import get_object_or_404, render, redirect
from django.template import RequestContext
from django.db.models.signals import pre_save

from medialib.models import MediaLibrary
from errorcatcher.exceptions import *
from statistic.models import Stat
from rest.crypto import sign_id

from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.sites.shortcuts import get_current_site
# try:
#     from django.contrib.sites.models import get_current_site
# except ImportError:
#     from django.contrib.sites.shortcuts import get_current_site
from django.template.response import TemplateResponse

import time

@never_cache
def forget(request, uid, token):
    user = get_object_or_404(User, id=base36_to_int(uid))

    if not default_token_generator.check_token(user, token):
        raise Http404

    if request.method == 'POST':
        form = ForgetPasswordForm(data=request.DATA, instance=user)
        if form.is_valid():
            form.save()
            Notification.log(request=request,
                component='account', action='user',
                user=user,
                fields='password')
            user = authenticate(username=user.username, password=request.DATA.get('password'))
            auth_login(request, user)
            return redirect('/profile/' + user.username)
    else:
        form = ForgetPasswordForm(instance=user)

    return render(request, 'account/forget.html', {'u': user, 'form': form})


# def login(request):
# 	if request.user.is_authenticated:
# 		try:
# 			if request.user.member.subscription_kind != 'U':
# 				return redirect('/profile/' + request.user.username)
# 		except Member.DoesNotExist:
# 			pass

# 	payload = {
# 		'next_url': request.GET.get('next', '/profile/')
# 	}

# 	return render(request, 'account/login.html', payload)

def verifyAccount(request, token):
    """
    method checks if the token is valid
        if valid the person is redirected to their account page
        if not valid show not valid token error
    """
    member = Member.checkConfirmation(token)
    if member:
        member.backend = 'django.contrib.auth.backends.ModelBackend'
        auth_login(request, member)
        return redirect(request.DATA.get("next", '/profile/'))
    return render(request, 'error_base.html', {'error': "<h1>Confirm Failed</h1><h3>Invalid Token</h3>"})


def signup_old(request, payload=None):
    # FYI - this page is rendered as part of social auth
    # see account/pipeline.py for details
    if payload is None:
        # assume we are in test mode
        payload = {}
        payload["auth_backend"] = "account-testing"
        payload["email"] = "test@test.com"
        payload["birthday_month"] = 5
        payload["birthday_day"] = 2
        payload["birthday_year"] = 1975
        payload["first_name"] = "Jim"
        payload["last_name"] = "Bob"
    else:
        payload["auth_backend"] = request.session.get("auth_backend")

    email = payload["email"]
    # whitelist = getattr(settings, "SOCIAL_AUTH_DOMAIN_WHITELIST", [])
    # if "@" in email:
    # 	domain = email.split("@")[1]
    # 	if len(whitelist) and domain not in whitelist:
    # 		raise Exception("domain not allowed")
    # elif len(email) < 5:
    # 	raise Exception("not a valid email {0}".format(email))
    if "@" not in email or len(email) < 3:
        raise Exception("not a valid email {0}".format(email))


    return render(request, 'account/verify.html', payload)


def newacct(request, template_name='registration/newacct.html',
    redirect_field_name=REDIRECT_FIELD_NAME,
    create_form=NewUserForm,
    current_app=None, extra_context=None,
    auto_login=True, success_template=None):
    """
    Creates new user
    """

    redirect_to = request.DATA.get(redirect_field_name, '')

    if request.method == "POST":
        form = create_form(data=request.POST)
        if form.is_valid():
            form.save()

            if auto_login:
                auth_login(request, form.get_user())

            if success_template:
                template_name = success_template
            else:
                netloc = urlparse.urlparse(redirect_to)[1]

                # Use default setting if redirect_to is empty
                if not redirect_to:
                    redirect_to = settings.LOGIN_REDIRECT_URL
                elif netloc and netloc != request.get_host():
                    redirect_to = settings.LOGIN_REDIRECT_URL

                return HttpResponseRedirect(redirect_to)
    else:
        form = create_form()

    current_site = get_current_site(request)

    context = {
        'form': form,
        redirect_field_name: redirect_to,
        'site': current_site,
        'site_name': current_site.name,
    }
    if extra_context is not None:
        context.update(extra_context)
    return TemplateResponse(request, template_name, context, current_app=current_app)
