from django.contrib.auth.views import LoginView, LogoutView

from django.conf.urls import url
# from django.contrib.auth.views import password_reset, password_reset_confirm, password_reset_complete, password_reset_done

from django.shortcuts import redirect, render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib.auth import logout, login
from django.shortcuts import get_object_or_404

import os
import binascii

from django.conf import settings

from errorcatcher.decorators import *

from location.models import GeoIPLocation

from . import views
from account.forms import *
from account.models import Member

from flow.models import UserInvite

from rest import helpers

# def getContext(request):
#     me = request.user if request.user.is_authenticated else None
#     if me:
#         me = Member.getByUser(request.user)
#     return {
#         "protocol":helpers.getProtocol(request),
#         "version":settings.VERSION,
#         "SITE_LABEL":settings.SITE_LABEL,
#         "SERVER_NAME":settings.SERVER_NAME,
#         "SHARE_HOST":settings.SHARE_HOST,
#         "TWITTER_HANDLE":settings.TWITTER_HANDLE,
#         "settings":settings,
#         "request": request,
#         "content": None,
#         "me":me
#     }

# def render_test(request, subpage=None):
#     context = getContext(request)
#     context.update(request.DATA.asDict())
#     context["model"] = request.DATA.asDict()
#     return render(request, '{0}.html'.format(subpage), context)

# # force_ssl
# def on_logged_in(request):
#     if request.user.is_authenticated:
#         # print "LOGGED IN !!!!!!!!!!!!!!!!!!!!!!!!"
#         # SET SESSION TO NEVER EXPIRE!!!
#         request.session.set_expiry(0)

#         member = Member.getByUser(request.user)
#         member.locateByIP(request.ip)

#         if "next" in request.DATA:
#             nexturl = request.DATA.get("next", None)
#             if nexturl and len(nexturl):
#                 return redirect(nexturl)
#         if helpers.isMobile(request):
#             return redirect(settings.MOBILE_HOME)

#         # ok lets get the first campaign from a user
#         # groups = Group.objects.filter(memberships__member=member, kind=settings.DEFAULT_GROUP_KIND)
#         # g = groups.first()
#         # if not g:
#         #   return redirect(settings.LOGIN_REDIRECT_URL)

#         # ms = g.getMembership(member)
#         # if ms.isManager():
#         #   return redirect(settings.MANAGER_HOME_URL)
#         return redirect(settings.HOME_URL)

#     return redirect(settings.PUBLIC_URL)


# def on_log_out(request):
#     if request.user.is_authenticated:
#         request.user.log("logout", "user logged out", request, method="logout")
#         logout(request);
#     return redirect(request.DATA.get("next", "/"))

# def render_invite(request, uuid, token):
#     # TODO change this to not uses Member.uuid but UserInvite.uuid
#     from django.utils.http import base36_to_int
#     member = Member.getByUUID(uuid)
#     validlink = member.checkInviteToken(token)
#     group = None

#     if member:
#         ms = member.memberships.last()
#         if ms:
#             group = ms.group
#         if request.user.is_authenticated:
#             if member.id == request.user.id:
#                 return redirect('/login')

#             me = request.user.getMember()
#             # check to make sure this is a new account
#             # is_new =  not member.hasLoggedIn()
#             if validlink:
#                 # check for actions
#                 merge = int(request.DATA.get("merge", 0))
#                 if merge:
#                     me.merge(member)
#                     return redirect('/login')
#                 create = int(request.DATA.get("create", 0))
#                 if not create:
#                     context = getContext(request)
#                     context["group"] = group
#                     context["new_acct"] = member
#                     context["old_acct"] = request.user
#                     return render(request, 'registration/newacct_oldacct.html', context)



#         resend = int(request.DATA.get("resend", 0))
#         if resend and not member.hasLoggedIn():
#             # check if they ever received an invite
#             context = getContext(request)
#             invite = UserInvite.objects.filter(user=member).last()
#             if invite:
#                 invite.resend()
#                 if member:
#                     context["me"] = member
#                 context["message"] = "A new invitation has been sent for your account!"
#                 return render(request, 'registration/newacct_failed.html', context)
#             context["error"] = "Admin has been notified of this failed attempt."
#             return render(request, 'registration/newacct_failed.html', context)

#         if validlink:
#             # now lets login and redirect the user to the social auth link page
#             if not member.is_active:
#                 member.user.activate()
#                 member.save()
#             member.backend = 'django.contrib.auth.backends.ModelBackend'
#             login(request, member)
#             context = getContext(request)
#             context["group"] = group
#             context["me"] = member
#             return render(request, 'registration/newacct.html', context)
#     context = getContext(request)
#     if member:
#         context["me"] = member

#     context["error"] = "Sorry but it looks like your link is no longer valid!  Links can only be used one time and/or expire after a few days.  You may want to generate a new one."
#     context["allow_reinvite"] = 1
#     return render(request, 'registration/newacct_failed.html', context)

# def render_login(request):
#     if request.user.is_authenticated:
#         print(("redirect: {0}".format(settings.LOGIN_REDIRECT_URL)))
#         return redirect(settings.LOGIN_REDIRECT_URL)
#     # return render(request, "registration/login.html", getContext(request))
#     return login_view(request, authentication_form=AuthenticationForm, extra_context=getContext(request))

# @login_required
# def invite_complete(request):
#     if "password" in request.DATA:
#         pwd = request.DATA.get("password", None)
#         if len(pwd) > 5:
#             request.user.set_password(pwd)
#             request.user.save()
#     return redirect("/")

# def render_close(request):
#     return render(request, 'registration/close.html', getContext(request))

# def render_register(request):
#     if request.method == "POST":
#         # request.session['password'] = request.POST.get('password')
#         # backend = request.session['partial_pipeline']['backend']
#         # return redirect('social:complete', backend=backend)
#         return render(request, 'registration/register_done.html', getContext(request))
#     return render(request, 'registration/register.html', getContext(request))


# def render_password_reset(request, uuid=None, token=None):
#     # we need to verify the users account has a usable password
#     if uuid and token:
#         member = Member.getByUUID(uuid)
#         context = getContext(request)
#         if member:
#             validlink = member.checkInviteToken(token)
#             if validlink and member.is_active:
#                 member.backend = 'django.contrib.auth.backends.ModelBackend'
#                 context['me'] = member
#                 context["uuid"] = member.uuid
#                 context['token'] = member.createInviteToken()
#                 return render(request, 'registration/password_reset_confirm.html', context)
#         context["error"] = "Sorry but it looks like your reset password link is no longer valid!  These links can only be used one time and/or expire after a few days."
#         return render(request, 'registration/newacct_failed.html', context)

#     if request.method == "POST" and "token" in request.POST and "uuid" in request.POST:
#         uuid = request.POST.get("uuid")
#         token = request.POST.get("token")
#         member = Member.getByUUID(uuid)
#         if member.checkInviteToken(token) and "new_password1" in request.POST and "new_password2" in request.POST:
#             p1 = request.POST.get("new_password1")
#             p2 = request.POST.get("new_password2")
#             if p1 == p2 and len(p1) > 6:
#                 member.backend = 'django.contrib.auth.backends.ModelBackend'
#                 login(request, member)
#                 member.set_password(p1)
#                 member.save()
#                 context = getContext(request)
#                 context['me'] = member
#                 return render(request, 'registration/password_reset_complete.html', context)

#     if "email" in request.DATA:
#         email = request.DATA.get("email", "").lower()
#         user = Member.objects.filter(email=email).first()
#         if user:
#             user.sendResetPassword()
#             return render(request, 'registration/password_reset_done.html')
#     return render(request, 'registration/password_reset_form.html')


# def render_already_linked(request, linked_to=None, provider=None):
#     context = {"me":request.user, "request":request}
#     context["linked_to"] = linked_to
#     context["platform"] = provider
#     return render(request, "errors/social_already_linked.html", context)

urlpatterns = []
    # url(r'^test/(?P<subpage>.*)$', render_test),
    # url(r'^close$', render_close),
    # url(r'^login/$', render_login),
    # url(r'^logout/$', on_log_out),
    # url(r'^login-canceled/$', render_login),
    # url(r'^logged-in/$', on_logged_in),
    # url(r'^register/$', render_register),
    # url(r'^signup/$', views.newacct, {'auto_login': False, 'success_template': 'registration/newacct_success.html'}),
    # url(r'^forgot/$', render_password_reset),
    # url(r'^forgot/reset$', render_password_reset),
    # url(r'^forgot/(?P<uuid>[a-zA-Z0-9]+)-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})$', render_password_reset),
    # url(r'^invite/(?P<uuid>[a-zA-Z0-9]+)-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})$', render_invite),
    # url(r'^invite/complete$', invite_complete),
# ]
