
from django.conf import settings
from social_core import exceptions as social_exceptions
from social_core.pipeline.partial import partial

from django.http import HttpResponseRedirect, QueryDict
from account.models import User, SocialUser, SocialAccount
from account import socialapi

from django.contrib.auth import logout as auth_logout
from django.shortcuts import redirect, render
from . import views
from .models import Member
from medialib.models import *

from django import forms
from account.forms import NewUserForm
from account.urls import render_already_linked
import urllib.request, urllib.parse, urllib.error

from rest.middleware import get_request
from rest.models import UberDict
import string, random

import sys, traceback

# get custom params from url
# <a href="{% url 'social:begin' 'facebook' %}?key={{ value }}">Login with Facebook</a>
# strategy.session_get('key')

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def _setval(outdict, indict, outkey, inkey):
    if type(inkey) in (str, str):
        inkey = inkey.split('.')
    for k in inkey:
        if k in indict:
            indict = indict[k]
        else:
            return
    if indict != None:
        outdict[outkey] = indict


@partial
def social_user(backend, request, uid, user=None, *args, **kwargs):
    print("= social_user")
    print(("\tlogged in: {0}".format(user != None)))
    is_linking = user != None
    provider = backend.name
    social = backend.strategy.storage.user.get_social_auth(provider, uid)

    if social:
        if user and social.user != user:
            data = backend.strategy.request_data()
            linkto = data.get("linkto")
            if linkto is None:
                request.user = user
                if not hasattr(request, "DATA"):
                   request.DATA = {}
                return render_already_linked(request, social.user, provider)
            if linkto == "me":
                # member = social.user.getMember()
                # member.unlinkSocial(provider, social)
                print("\treassociating account")
                social.user = user
                social.save()
            elif linkto == "cancel":
                print("\tcancel already linked")
                # we are going to cancel the auth
                return redirect("/logged-in")
            else:
                # we are going to login has this user
                print("\tlogin via other account")
                is_linking = False
                drequest = get_request()
                auth_logout(drequest)
                user = social.user

            # raise AuthAlreadyAssociated(backend, msg)
        elif not user:
            user = social.user

    return {'social': social,
            'user': user,
            'is_linking':is_linking,
            'is_new': user is None,
            'new_association': False}


def associate_by_email(backend, details, user=None, *args, **kwargs):
    """
    Associate current auth with a user with the same email address in the DB.
    """
    print("= associate_by_email")
    if user:
        return None

    # only allow facebook and google past this point
    if backend.name not in ["google", "facebook"]:
        return None

    email = details.get('email')
    if email and "@" in email:
        user = User.objects.filter(email=email).first()
        if user is None:
            return None
        return { 'user': user }


def get_username(details, user=None, *args, **kwargs):
    """Return an username for new user. Return current user username
    if user was given.
    """
    if user:
        if "@" in user.username:
            user.username = Member.generateUsername(user.username, user.first_name, user.last_name)
            user.save()
        return {'username': user.username}

    username = details.get("username")
    email = details.get("email")
    
    if username:
        username = str(username)
    elif email:
        username = str(email)
    else:
        username = uuid4().get_hex()
    

    if "@" in username:
        username = Member.generateUsername(username, "", "")
    else:
        username = Member.generateUsername(None, username, "")
    return {'username': username }

@partial
def create_user(strategy, details, user=None, username=None, *args, **kwargs):
    print("= create_user")
    if user:
        print("= create_user -> USER EXISTS")
        return {'is_new': False }
    print("= create_user -> CREATING NEW USER")
    print(('-'*80))
    print("details")
    print(details)
    print(('-'*80))

    if not settings.SOCIAL_AUTH_ALLOW_NEW:
        raise social_exceptions.AuthFailed("This platform requires an invitation!")

    email = details.get("email")
    if email is None or "@" not in email:
        if not settings.SOCIAL_AUTH_ALLOW_NULL_EMAIL:
            # null email
            print("invalid email!!!")
            email = None
            raise social_exceptions.AuthFailed("This platform requires a valid email address to continue!")
        details["email"] = "{0}@invalid.com".format(id_generator()) 
        # if hasattr(settings, "SOCIAL_AUTH_ALLOW_NULL_EMAIL"):
        #     if getattr(settings, "SOCIAL_AUTH_ALLOW_NULL_EMAIL"):
        #         details["email"] = "{0}@invalid.com".format(id_generator())     
        #         print details["email"]
        # if email is None:
        #     raise forms.ValidationError(["email is null, a valid email required!"])
    print("processing form...")
    form_data = details.copy()
    form_data["username"] = username
    frm = NewUserForm(form_data)
    if not frm.is_valid():
        errs = {}
        errs_all = ""
        for f in frm.fields:
            if frm[f].errors:
                errs[f] = []
                for e in frm[f].errors:
                    errs[f].append(e)
        for e in frm.non_field_errors():
            if not errs.get('', None):
                errs[''] = []
            errs[''].append(e)
        for f in errs:
            errs_all += "%s: %s\n" % ( f, ", ".join(errs[f]) )
        print(("form errors: {0}".format(errs_all)))
        raise forms.ValidationError(errs_all)

    user = frm.save(True)
    print(("username: {0}  and then {1}".format(username, user.username)))
    print(("email: {0}  display: {1}".format(user.email, user.display_name)))

    return { "user":user, "is_new":True }

def associate_user(backend, uid, user=None, social=None, *args, **kwargs):
    print("+ associate_user")
    if user and not social:
        try:
            social = backend.strategy.storage.user.create_social_auth(
                user, uid, backend.name
            )
        except Exception as err:
            print(("+ associate_user error: {0}".format(err)))
            if not backend.strategy.storage.is_integrity_error(err):
                raise
            # Protect for possible race condition, those bastard with FTL
            # clicking capabilities, check issue #131:
            #   https://github.com/omab/django-social-auth/issues/131
            return social_user(backend, uid, user, *args, **kwargs)
        else:
            print("\tassociated user")
            return {'social': social,
                    'user': social.user,
                    'new_association': True}
    print("returning nothing??")

def load_extra_data(backend, details, response, uid, user, *args, **kwargs):
    print("+ load_extra_data")
    try:
        social = kwargs.get('social') or \
                 backend.strategy.storage.user.get_social_auth(backend.name, uid)
        if social:
            print(("backend.EXTRA_DATA: '{0}'".format(backend.EXTRA_DATA)))
            print(("setting.EXTRA_DATA: '{0}'".format(backend.setting("EXTRA_DATA"))))
            extra_data = backend.extra_data(user, uid, response, details)
            social.set_extra_data(extra_data)
    except Exception as err:
        print(('-'*60))
        traceback.print_exc(file=sys.stdout)
        print(('-'*60))
        # print "load_extra_data ERROR: {0}".format(err)
    print("done with load_extra_data")


def update_twitter_details(user_data, backend, details, response, member, is_new):
    if "followers_count" in response:
        user_data.audience = response.get("followers_count")
    if "screen_name" in response:
        user_data.screen_name = response.get('screen_name')
    if 'profile_background_image_url_https' in response:
        url = response.get('profile_background_image_url_https')
        if url and len(url):
            user_data.background = url
    if 'user_id' in response:
        user_data.uid = response.get("user_id")

    if "access_token" in response:
        user_data.token = response.get("access_token")

    return user_data

def update_facebook_details(user_data, backend, details, response, member, is_new):
    user_data.timezone = response.get("timezone")
    if "access_token" in response:
        user_data.token = response.get("access_token")
    return user_data

def update_linkedin_details(user_data, backend, details, response, member, is_new):
    user_data.screen_name = response.get("username")
    user_data.uid = response.get('id')
    if "access_token" in response:
        user_data.token = response.get("access_token")
    return user_data

def update_instagram_details(user_data, backend, details, response, member, is_new):
    if "id" in response:
        user_data.uid = response.get("id")
    elif "user" in response:
        u = response.get("user")
        if "id" in u:
            user_data.uid = u["id"]
        if "username" in u:
            user_data.screen_name = u["username"]
    if "access_token" in response:
        user_data.token = response.get("access_token")

    if "counts" in response:
        counts = response.get("counts")
        if counts and "followed_by" in counts:
            user_data.audience = counts.get("followed_by")
    return user_data

def update_google_details(user_data, backend, details, response, member, is_new):
    user_data.gender = response.get("gender")
    # user_data.username = response.get("displayName")
    if "emails" in response:
        for e in response.get("emails"):
            if e.get("type", None) == "account":
                user_data.screen_name = e.get("value", None)
    if "access_token" in response:
        user_data.token = response.get("access_token") 
    if "circledByCount" in response:
        user_data.audience = response.get("circledByCount")
    user_data.uid = response.get("id")
    return user_data  

def update_other_details(user_data, backend, details, response, member, is_new):
    print("+ response: ")
    print(response)
    if "access_token" in response:
      user_data.token = response.get("access_token") 
    return user_data

#SOCIAL_FIELDS = ['link', 'email', 'uid', 'username', 'audience', 'token']
#SOCIAL_FIELDS = ['link', 'email', 'id', 'uid', 'username', 'audience', 'refresh_token', 'mobile_token', 'token']
#META_FIELDS = ["timezone", "gender", "verified_email", "user_birthday", "birthday", "locale"]

CORE_FIELDS = ["first_name", "last_name", "url", "email", "uid", "audience", "token"]

def updateMember(member, name, value, backend_name):
    changed = False
    if value is None:
        return
    if name in SOCIAL_FIELDS:
        member.setProperty("{0}_{1}".format(backend_name, name), value, "social")
    elif name in CORE_FIELDS:
        cur = getattr(member, name, None)
        if cur is None or len(cur) == 0:
            setattr(member, name, value)
            changed = True
    elif name in META_FIELDS:
        member.setProperty(name, value)
    return changed

def updateAccountInfo(act, key, value):
    changed = False
    if value is None:
        return 
    print(("{}: {}".format(key, value)))
    if key in CORE_FIELDS:
        cur = getattr(act, key, None)
        if isinstance(value, str):
            if cur is None or len(cur) == 0:
                setattr(act, key, value)
                changed = True
        elif isinstance(value, int) or isinstance(value, float):
            setattr(act, key, value)
            changed = True
    else:
        act.setProperty(key, value)
    return changed

def updateSocialAccount(member, backend_name, user_data, details, response):
    uid = user_data.uid
    social_act = SocialAccount.objects.filter(member=member, platform=backend_name, uid=uid).last()
    if not social_act:
        social_act = SocialAccount(member=member, platform=backend_name, uid=uid)
        social_act.save()

    for name, value in list(details.items()):
        if updateAccountInfo(social_act, name, value):
            changed = True

    for name, value in list(user_data.items()):
        if updateAccountInfo(social_act, name, value):
            changed = True
    if changed:
        social_act.save()
    setAvatar(social_act, details, response)


def updateMemberData(member, backend_name, user_data, details, response):
    member = Member.getByUser(member)
    if "verified_email" not in list(details.keys()):
        if "verified_email" in response:
            details["verified_email"] = response.get("verified_email")
        elif "verified" in response:
            details["verified_email"] = response.get("verified")

    changed = False
    email = details.get("email")
    if member.email is None or "@" not in member.email and email:
        member.email = email
        changed = True

    if not member.first_name and not member.last_name:
        member.first_name = details.get("first_name", user_data.get("first_name", None))
        member.last_name = details.get("last_name", user_data.get("last_name", None))
        changed = True

    if changed:
        member.save()

    updateSocialAccount(member, backend_name, user_data, details, response)

def updateAudience(member, user_data, backend_name, details, response):
    if not user_data.audience:
        print(("fetching audience for {0}".format(backend_name)))
        user_data.audience = member.fetchAudienceSize(backend_name, response.get("access_token"))

def getMobileToken(response, details, **kwargs):
    if "mobile_token" in response:
        return response.get("mobile_token")
    elif "mobile_token" in details:
        return details.get("mobile_token")
    elif "mobile_token" in kwargs:
        return kwargs.get("mobile_token")
    return None

def getRefreshToken(response, details, **kwargs):
    if "refresh_token" in response:
        return response.get("refresh_token")
    elif "refresh_token" in details:
        return details.get("refresh_token")
    elif "refresh_token" in kwargs:
        return kwargs.get("refresh_token")
    return None

def update_user_details(backend, details, response, user=None, is_new=False,
                        *args, **kwargs):

    member = SocialUser.getByUser(user)
    backend_name = backend.name

    user_data = UberDict()
    user_data.audience = 0
    user_data.username = None
    user_data.uid = None
    user_data.background = None
    user_data.token = None

    if backend_name == "instagram":
        user_data = update_instagram_details(user_data, backend, details, response, member, is_new)
    elif backend_name == "twitter":
        user_data = update_twitter_details(user_data, backend, details, response, member, is_new)
    elif backend_name.startswith("facebook"):
        backend_name = "facebook"
        user_data = update_facebook_details(user_data, backend, details, response, member, is_new)
    elif backend_name.startswith("linkedin"):
        backend_name = "linkedin"
        user_data = update_linkedin_details(user_data, backend, details, response, member, is_new)
    elif "google" in backend_name:
        backend_name = "google"
        user_data = update_google_details(user_data, backend, details, response, member, is_new)
    else:
        user_data = update_other_details(user_data, backend, details, response, member, is_new)

    user_data.mobile_token = getMobileToken(response, details, **kwargs)
    user_data.refresh_token = getRefreshToken(response, details, **kwargs)

    updateAudience(member, user_data, backend_name, details, response)
    print(("+ {0}".format(backend)))
    print("+ member data: ")
    print(user_data)
    print("+ response: ")
    print(response)
    updateMemberData(member, backend_name, user_data, details, response)

    if user_data.audience:
        member.updateAudienceTotal()



    return {'user': user }

def setAvatar(social_act, details, response):
    platform = social_act.platform
    url = None
    if platform == 'facebook' and 'uid' in details:
        url = 'https://graph.facebook.com/%s/picture?type=normal' % response['id']
    elif 'picture' in details:
        url = details['picture']
    elif 'profile_image_url' in details:
        url = details['profile_image_url'] 
    elif 'profile_picture' in details:
        url = details['profile_picture']
    elif platform == 'twitter':
        if 'profile_image_url_https' in response:
            url = response.get('profile_image_url_https')
    elif "linkedin" in platform:
        platform = "linkedin"
        url = socialapi.linkedin.getAvatar(social_act.member, response.get("access_token"))
    if url:
        social_act.setAvatar(url)

def set_profile_pic(backend=None, request=None, auth=None, user=None, details={}, response={}, *args, **kwargs):
    if not user:
        return None


    return None

def save_session(backend, *args, **kwargs):
    """Saves current social-auth status to session."""
    is_linking = False
    if "is_linking" in kwargs:
        is_linking = kwargs["is_linking"]

    if not is_linking:
        print("SAVING SESSION")
        backend.strategy.session_set('auth_backend', backend.name)
        return None

