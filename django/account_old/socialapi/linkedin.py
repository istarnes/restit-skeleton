from django.conf import settings

import requests
import json
import hashlib
import random
import urllib.request, urllib.parse, urllib.error
import contextlib
import math

from datetime import datetime

class LinkedInResult(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self
    def __getattr__(self, item):
            return None

def getAvatar(user, access_token=None):
    if not access_token:
        access_token = user.getAccessTokens("linkedin-oauth2")
    if access_token:
        api = API(access_token)
        return api.getAvatar()
    return None

def getAudienceSize(user, access_token=None):
    access_token = user.getAccessTokens("linkedin-oauth2")
    if access_token:
        api = API(access_token)
        value = api.getNumberOfConnections()
        if type(value) in [str, str] and value.isdigit():
            return int(value)
        elif type(value) is int:
            return value
        else:
            print((type(value)))
            print(("INVALID LINKEDIN AUDIENCE: {0}".format(value)))
    return 0

def getEngagementForURL(url):
    data = getStatsForURL(url)
    if data and "count" in data:
        return data["count"]
    return 0

def getStatsForContentShare(share, get_text=False):
    if not share.is_remote:
        audience = share.getAudience()
        shares = getEngagementForURL(share.remote_url)
        if shares:
            result = LinkedInResult()
            result.engagement = shares
            result.comments = 0
            result.likes = 0
            if audience:
                engagment_rate = result.engagement * 1.0 / audience
                age = (datetime.now() - share.created).total_seconds() * 1.0 / 60 
                result.views = max((1.0 - math.pow(1.0 - engagment_rate, age)) * (audience * ((result.engagement * 2.0/audience))), result.engagement * 3)
        return result
    return None


def updateStatsForContentShare(share, get_text=False):
    if not share.is_remote:
        shares = getEngagementForURL(share.remote_url)
        if shares:
            share.shares = shares
            share.verified = True
            if share.audience and share.shares:
                share.engagment_ratio = share.shares * 1.0 / share.audience 
            share.save()

def getStatsForURL(url):
    r = requests.get("http://www.linkedin.com/countserv/count/share", params={"url":url, "format":"json"})
    return r.json()


def postLink(user, link, text):
    if link not in text:
        text = "{0} {1}".format(text, link)

    access_token = user.getAccessTokens("linkedin-oauth2")
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = API(access_token)
    res = api.postShare(text)
    print("linkedin --- postShare")
    print(res)
    if res:
        if "updateKey" not in res:
            return {"status":False, "error":res}
        return {
            "status":True,
            "remote_id":res["updateKey"],
            "remote_url":res["updateUrl"],
            "text":text
        }
    return {"status":False}

"""
{u'updateKey': u'UPDATE-6321114-6077178864780533760', u'updateUrl': u'https://www.linkedin.com/updates?discuss=&scope=6321114&stype=M&topic=6077178864780533760&type=U&a=UECl'}
"""

def postMedia(user, media, text):
    access_token = user.getAccessTokens("linkedin-oauth2")
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = API(access_token)
    if media.kind != "I":
        res = api.postShare(text, submitted_image_url=media.image_url())
    else:
        res = api.postShare(text)

    if "status" in res and res["status"] == 200:
        return {
            "status":True,
            "remote_id":res["updateKey"],
            "remote_url":res["updateUrl"],
            "text":text
        }
    elif "updateKey" in res:
        return {
            "status":True,
            "remote_id":res["updateKey"],
            "remote_url":res["updateUrl"],
            "text":text
        }
    else:
        print("error from linked in")
        print(res)
    return {"status":False}



class API(object):
    def __init__(self, access_token, api_key=None, api_secret=None):
        self.access_token = access_token
        if api_key is None:
            self.api_key = settings.SOCIAL_AUTH_LINKEDIN_OAUTH2_KEY
            self.api_secret = settings.SOCIAL_AUTH_LINKEDIN_OAUTH2_SECRET

    def getAvatar(self):
        res = self.get_picture_urls()
        if "_total" in res and res["_total"] > 0:
            return res["values"][0]
        return None

    def getNumberOfConnections(self):
        # (network:(networkStats))
        # :(connections)
        #res = self.make_request('GET', 'https://api.linkedin.com/v1/people/~/num-connections')

        res = self.make_request('GET', 'https://api.linkedin.com/v1/people/~/num-connections')
        return res.json()

    def postShare(self, comment=None, title=None, description=None, submitted_url=None, submitted_image_url=None, visibility_code='anyone'):
        """
        submitted_image_url
            A fully qualified URL to a thumbnail image to accompany the shared content.

            The image should be at least 80 x 150px for best results.

        visibility_code
            One of the following values:
            anyone:  Share will be visible to all members.
            connections-only:  Share will only be visible to connections of the member performing the share.
             
            This field is required in all sharing calls.
        """
        post = {
            'visibility': {
                'code': visibility_code,
            },
        }
        if comment is not None:
            post['comment'] = comment
        if title is not None and submitted_url is not None:
            post['content'] = {
                'title': title,
                'submitted-url': submitted_url,
                'description': description,
            }
        if submitted_image_url:
            post['content']['submitted-image-url'] = submitted_image_url

        url = '%s/~/shares' % ENDPOINTS.PEOPLE
        response = self.make_request('POST', url, data=json.dumps(post))
        return response.json()

    def get_picture_urls(self, member_id=None, member_url=None, params=None, headers=None):
        if member_id:
            url = '%s/id=%s/picture-urls::(original)' % (ENDPOINTS.PEOPLE, str(member_id))
        elif member_url:
            url = '%s/url=%s/picture-urls::(original)' % (ENDPOINTS.PEOPLE, urllib.parse.quote_plus(member_url))
        else:
            url = '%s/~/picture-urls::(original)' % ENDPOINTS.PEOPLE

        response = self.make_request('GET', url, params=params, headers=headers)
        return response.json()

    def get_profile(self, member_id=None, member_url=None, selectors=None,
                    params=None, headers=None):
        if member_id:
            if type(member_id) is list:
                # Batch request, ids as CSV.
                url = '%s::(%s)' % (ENDPOINTS.PEOPLE,
                                    ','.join(member_id))
            else:
                url = '%s/id=%s' % (ENDPOINTS.PEOPLE, str(member_id))
        elif member_url:
            url = '%s/url=%s' % (ENDPOINTS.PEOPLE, urllib.parse.quote_plus(member_url))
        else:
            url = '%s/~' % ENDPOINTS.PEOPLE
        if selectors:
            url = '%s:(%s)' % (url, LinkedInSelector.parse(selectors))

        response = self.make_request('GET', url, params=params, headers=headers)
        return response.json()

    def make_request(self, method, url, data=None, params=None, headers=None, timeout=60):
        if headers is None:
            headers = {'x-li-format': 'json', 'Content-Type': 'application/json'}
        else:
            headers.update({'x-li-format': 'json', 'Content-Type': 'application/json'})

        if params is None:
            params = {}
        kw = dict(data=data, params=params,
                  headers=headers, timeout=timeout)

        params.update({'oauth2_access_token': self.access_token})

        return requests.request(method.upper(), url, **kw)

def enum(enum_type='enum', base_classes=None, methods=None, **attrs):
    """
    Generates a enumeration with the given attributes.
    """
    # Enumerations can not be initalized as a new instance
    def __init__(instance, *args, **kwargs):
        raise RuntimeError('%s types can not be initialized.' % enum_type)

    if base_classes is None:
        base_classes = ()

    if methods is None:
        methods = {}

    base_classes = base_classes + (object,)
    for k, v in list(methods.items()):
        methods[k] = classmethod(v)

    attrs['enums'] = attrs.copy()
    methods.update(attrs)
    methods['__init__'] = __init__
    return type(enum_type, base_classes, methods)


class LinkedInSelector(object):
    @classmethod
    def parse(cls, selector):
        with contextlib.closing(StringIO()) as result:
            if type(selector) == dict:
                for k, v in list(selector.items()):
                    result.write('%s:(%s)' % (to_utf8(k), cls.parse(v)))
            elif type(selector) in (list, tuple):
                result.write(','.join(map(cls.parse, selector)))
            else:
                result.write(to_utf8(selector))
            return result.getvalue()



PERMISSIONS = enum('Permission',
                   COMPANY_ADMIN='rw_company_admin',
                   BASIC_PROFILE='r_basicprofile',
                   FULL_PROFILE='r_fullprofile',
                   EMAIL_ADDRESS='r_emailaddress',
                   NETWORK='r_network',
                   CONTACT_INFO='r_contactinfo',
                   NETWORK_UPDATES='rw_nus',
                   GROUPS='rw_groups',
                   MESSAGES='w_messages')

ENDPOINTS = enum('LinkedInURL',
                 PEOPLE='https://api.linkedin.com/v1/people',
                 PEOPLE_SEARCH='https://api.linkedin.com/v1/people-search',
                 GROUPS='https://api.linkedin.com/v1/groups',
                 POSTS='https://api.linkedin.com/v1/posts',
                 COMPANIES='https://api.linkedin.com/v1/companies',
                 COMPANY_SEARCH='https://api.linkedin.com/v1/company-search',
                 JOBS='https://api.linkedin.com/v1/jobs',
                 JOB_SEARCH='https://api.linkedin.com/v1/job-search')

NETWORK_UPDATES = enum('NetworkUpdate',
                       APPLICATION='APPS',
                       COMPANY='CMPY',
                       CONNECTION='CONN',
                       JOB='JOBS',
                       GROUP='JGRP',
                       PICTURE='PICT',
                       EXTENDED_PROFILE='PRFX',
                       CHANGED_PROFILE='PRFU',
                       SHARED='SHAR',
                       VIRAL='VIRL')
