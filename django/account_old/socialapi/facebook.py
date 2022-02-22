#!/usr/bin/env python
#
# Copyright 2010 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Python client library for the Facebook Platform.

This client library is designed to support the Graph API and the
official Facebook JavaScript SDK, which is the canonical way to
implement Facebook authentication. Read more about the Graph API at
http://developers.facebook.com/docs/api. You can download the Facebook
JavaScript SDK at http://github.com/facebook/connect-js/.

If your application is using Google AppEngine's webapp framework, your
usage of this module might look like this:

user = facebook.get_user_from_cookie(self.request.cookies, key, secret)
if user:
    graph = facebook.GraphAPI(user["access_token"])
    profile = graph.get_object("me")
    friends = graph.get_connections("me", "friends")

"""

import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import hashlib
import hmac
import base64
import requests
import json
import re

import time
from datetime import datetime
import math

from django.conf import settings

# Find a query string parser
try:
    from urllib.parse import parse_qs
except ImportError:
    from urllib.parse import parse_qs

__version__ = "2.3"


class FacebookResult(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self
    def __getattr__(self, item):
            return None

def findProfileImage(email=None, username=None):
    # access_token = settings.SOCIAL_AUTH_FACEBOOK_KEY + settings.SOCIAL_AUTH_FACEBOOK_SECRET
    graph = GraphAPI()
    graph.access_token = graph.get_app_access_token(settings.SOCIAL_AUTH_FACEBOOK_KEY, settings.SOCIAL_AUTH_FACEBOOK_SECRET)
    return graph

def getAudienceSize(user, access_token=None):
    if not access_token:
        access_token = user.getAccessToken("facebook")
    if not access_token:
        return 0

    graph = GraphAPI(access_token)
    data = graph.get_friends()
    if "summary" in data:
        return data["summary"]["total_count"]
    return 0

def postLink(user, link, text):
    access_token = user.getAccessToken("facebook")
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = GraphAPI(access_token)
    data = {"link":link}
    #        {"name": "Link name"
    # "link": "http://www.example.com/",
    # "caption": "{*actor*} posted a new review",
    # "description": "This is a longer description of the attachment",
    # "picture": "http://www.example.com/thumbnail.jpg"}
    post = api.put_wall_post(text, data, privacy="SELF")

    result = FacebookResult()
    result.status = False
    if "id" in post:
        result.status = True
        result.id = post["id"]
        result.text = text
        result.remote_id = post["id"]

    if "post_id" in post:
        result.remote_id = post["post_id"]

    return result


def postMedia(user, media, text):
    access_token = user.getAccessToken("facebook")
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = GraphAPI(access_token)

    rendition = media.getImageRendition(width=1024, flat=False)
    fp = rendition.get_file()
    fp.seek(0)

    post = api.put_photo(fp, caption=text)

    result = FacebookResult()
    result.status = False
    if "id" in post:
        result.status = True
        result.id = post["id"]
        result.text = text
        result.remote_id = post["id"]

    if "post_id" in post:
        result.remote_id = post["post_id"]

    return result

ENGAGEMENT_URL = "https://graph.facebook.com/fql?q=SELECT%20like_count,%20total_count,%20share_count,%20click_count,%20comment_count%20FROM%20link_stat%20WHERE%20url%20=%20%22{0}%22"

def getEngagementForURL(url):
    r = requests.get("http://graph.facebook.com", params={"id":url})
    # r = requests.get(ENGAGEMENT_URL.format(url))
    data = r.json()
    # print data
    if data and "shares" in data:
        return data["shares"]
    return 0

def getStatsForContentShare(share, get_text=False):
    audience = share.getAudience()
    # check if we have a remote id
    result = FacebookResult()
    if not share.remote_id:
        r = requests.get(ENGAGEMENT_URL.format(share.remote_url))
        data = r.json()
        # print data
        if data and "share_count" in data:
            result.engagment = data["total_count"]
            result.likes = data["like_count"]
            result.comments = data["comment_count"]
            result.shares = data["share_count"]
            if audience:
                engagment_rate = result.engagement * 1.0 / audience
                age = (datetime.now() - share.created).total_seconds() * 1.0 / 60 
                result.views = max((1.0 - math.pow(1.0 - engagment_rate, age)) * (audience * ((result.engagement * 2.0/audience))), result.engagement * 3)
        return result

    access_token = share.owner.getAccessToken("facebook")
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = GraphAPI(access_token)
    data = api.get_post_metrics(share.remote_id)
    if "comments" in data:
        result.comments = data["comments"]
        result.likes = data["likes"]
        result.shares = data["shares"]
        result.engagment = result.comments + result.likes + result.shares
        if audience:
            engagment_rate = result.engagement * 1.0 / audience
            age = (datetime.now() - share.created).total_seconds() * 1.0 / 60 
            result.views = max((1.0 - math.pow(1.0 - engagment_rate, age)) * (audience * ((result.engagement * 2.0/audience))), result.engagement * 3)
        return result
    return None

def updateStatsForContentShare(share, get_text=False):
    result = getStatsForContentShare(share)
    if result:
        share.engagment = result.engagment
        share.likes = result.likes
        share.comments = result.comments
        share.shares = result.shares
        if result.views:
            share.views = result.views
        share.save()


def getLastPost(user, access_token=None):
    if not access_token:
        access_token = user.getAccessToken("facebook")
    if not access_token:
        return 0

    graph = GraphAPI(access_token)
    data = graph.get_posts()
    print(data)
    if "summary" in data:
        return data["summary"]["total_count"]
    return 0

class GraphAPI(object):
    """A client for the Facebook Graph API.

    See http://developers.facebook.com/docs/api for complete
    documentation for the API.

    The Graph API is made up of the objects in Facebook (e.g., people,
    pages, events, photos) and the connections between them (e.g.,
    friends, photo tags, and event RSVPs). This client provides access
    to those primitive types in a generic way. For example, given an
    OAuth access token, this will fetch the profile of the active user
    and the list of the user's friends:

       graph = facebook.GraphAPI(access_token)
       user = graph.get_object("me")
       friends = graph.get_connections(user["id"], "friends")

    You can see a list of all of the objects and connections supported
    by the API at http://developers.facebook.com/docs/reference/api/.

    You can obtain an access token via OAuth or by using the Facebook
    JavaScript SDK. See
    http://developers.facebook.com/docs/authentication/ for details.

    If you are using the JavaScript SDK, you can use the
    get_user_from_cookie() method below to get the OAuth access token
    for the active user from the cookie saved by the SDK.

    """
    def __init__(self, access_token=None, timeout=None, version="2.3"):
        self.access_token = access_token
        self.timeout = timeout

        valid_API_versions = ["1.0", "2.0", "2.1", "2.2", "2.3"]
        if version:
            version_regex = re.compile("^\d\.\d$")
            match = version_regex.search(str(version))
            if match is not None:
                if str(version) not in valid_API_versions:
                    raise GraphAPIError("Valid API versions are " +
                                        str(valid_API_versions).strip('[]'))
                else:
                    self.version = "v" + str(version)
            else:
                raise GraphAPIError("Version number should be in the"
                                    " following format: #.# (e.g. 1.0).")
        else:
            self.version = ""

    def get_object(self, id, **args):
        """Fetchs the given object from the graph."""
        return self.request(id, args)

    def get_objects(self, ids, **args):
        """Fetchs all of the given object from the graph.

        We return a map from ID to object. If any of the IDs are
        invalid, we raise an exception.
        """
        args["ids"] = ",".join(ids)
        return self.request("", args)

    def get_posts(self, **args):
        """Fetchs the connections for given object."""
        return self.request("me/posts", args)

    def get_friends(self, **args):
        """Fetchs the connections for given object."""
        return self.request("me/friends", args)

    def get_connections(self, id, connection_name, **args):
        """Fetchs the connections for given object."""
        return self.request(id + "/" + connection_name, args)

    def put_object(self, parent_object, connection_name, **data):
        """Writes the given object to the graph, connected to the given parent.

        For example,

            graph.put_object("me", "feed", message="Hello, world")

        writes "Hello, world" to the active user's wall. Likewise, this
        will comment on a the first post of the active user's feed:

            feed = graph.get_connections("me", "feed")
            post = feed["data"][0]
            graph.put_object(post["id"], "comments", message="First!")

        See http://developers.facebook.com/docs/api#publishing for all
        of the supported writeable objects.

        Certain write operations require extended permissions. For
        example, publishing to a user's feed requires the
        "publish_actions" permission. See
        http://developers.facebook.com/docs/publishing/ for details
        about publishing permissions.

        """
        assert self.access_token, "Write operations require an access token"
        return self.request(parent_object + "/" + connection_name,
                            post_args=data,
                            method="POST")

    def put_wall_post(self, message, attachment={}, profile_id="me", privacy="ALL_FRIENDS"):
        """Writes a wall post to the given profile's wall.

        We default to writing to the authenticated user's wall if no
        profile_id is specified.

        attachment adds a structured attachment to the status message
        being posted to the Wall. It should be a dictionary of the form:
        privacy can be = "SELF", "ALL_FRIENDS", "EVERYONE"
        
            {"name": "Link name"
             "link": "http://www.example.com/",
             "caption": "{*actor*} posted a new review",
             "description": "This is a longer description of the attachment",
             "picture": "http://www.example.com/thumbnail.jpg"}

        """
        return self.put_object(profile_id, "feed", message=message,
                               **attachment)

    def put_comment(self, object_id, message):
        """Writes the given comment on the given post."""
        return self.put_object(object_id, "comments", message=message)

    def put_like(self, object_id):
        """Likes the given post."""
        return self.put_object(object_id, "likes")

    def delete_object(self, id):
        """Deletes the object with the given ID from the graph."""
        self.request(id, method="DELETE")

    def delete_request(self, user_id, request_id):
        """Deletes the Request with the given ID for the given user."""
        self.request("%s_%s" % (request_id, user_id), method="DELETE")

    def put_photo(self, image, album_path="/me/photos", **kwargs):
        """
        Upload an image using multipart/form-data.
        image - A file object representing the image to be uploaded.
        album_path - A path representing where the image should be uploaded.
        """
        return self.request(
            album_path,
            post_args=kwargs,
            files={"source": image},
            method="POST")

    def get_insights(self, id, metric="page_posts_impressions"):
        return self.request(id + "/insights/" + metric)

    def get_post_metrics(self, id):
        fields="shares,likes.summary(true),comments.summary(true)"
        res = self.get_object(id, fields=fields)
        data = {
            "status":False,
            "shares":-1
        }

        if "comments" in res and "summary" in res["comments"]:
            data["comments"] = res["comments"]["summary"]["total_count"]

        if "likes" in res and "summary" in res["likes"]:
            data["likes"] = res["likes"]["summary"]["total_count"]

        if "share_count" in res:
            data["shares"] = res["share_count"]
        return data

    def get_version(self):
        """Fetches the current version number of the Graph API being used."""
        args = {"access_token": self.access_token}
        try:
            response = requests.request("GET",
                                        "https://graph.facebook.com/" +
                                        self.version + "/me",
                                        params=args,
                                        timeout=self.timeout)
        except requests.HTTPError as e:
            response = json.loads(e.read())
            raise GraphAPIError(response)

        try:
            headers = response.headers
            version = headers["facebook-api-version"].replace("v", "")
            return float(version)
        except Exception:
            raise GraphAPIError("API version number not available")

    def request(
            self, path, args=None, post_args=None, files=None, method=None):
        """Fetches the given path in the Graph API.

        We translate args to a valid query string. If post_args is
        given, we send a POST request to the given path with the given
        arguments.

        """
        args = args or {}
        if not path.startswith("/"):
            path = "/" + path

        if self.access_token:
            if post_args is not None:
                post_args["access_token"] = self.access_token
            else:
                args["access_token"] = self.access_token

        try:
            response = requests.request(method or "GET",
                                        "https://graph.facebook.com/" +
                                        self.version + path,
                                        timeout=self.timeout,
                                        params=args,
                                        data=post_args,
                                        files=files)
        except requests.HTTPError as e:
            response = json.loads(e.read())
            raise GraphAPIError(response)
        
        headers = response.headers
        if 'json' in headers['content-type']:
            result = response.json()
        elif 'image/' in headers['content-type']:
            mimetype = headers['content-type']
            result = {"data": response.content,
                      "mime-type": mimetype,
                      "url": response.url}
        elif "access_token" in parse_qs(response.text):
            query_str = parse_qs(response.text)
            if "access_token" in query_str:
                result = {"access_token": query_str["access_token"][0]}
                if "expires" in query_str:
                    result["expires"] = query_str["expires"][0]
            else:
                raise GraphAPIError(response.json())
        else:
            raise GraphAPIError('Maintype was not text, image, or querystring')

        if result and isinstance(result, dict) and result.get("error"):
            raise GraphAPIError(result)
        return result

    def fqlDep(self, query):
        """FQL query.

        Example query: "SELECT affiliations FROM user WHERE uid = me()"

        """
        self.request("fql", {"q": query})

    def fql(self, query, args=None, post_args=None):
        """FQL query.
        Two reasons to have this method:
        1. Graph api does not expose some info fields of a user, e.g.
            a user's networks/affiliations, we have to fall back to old api.
        2. FQL is a strong tool.
        Example query: "SELECT affiliations FROM user WHERE uid = me()"

        """
        args = args or {}
        if self.access_token:
            if post_args is not None:
                post_args["access_token"] = self.access_token
            else:
                args["access_token"] = self.access_token
        post_data = None if post_args is None else urllib.parse.urlencode(post_args)
 
        """Check if query is a dict and
           use the multiquery method
           else use single query
        """
        if not isinstance(query, str):
            args["queries"] = query
            fql_method = 'fql.multiquery'
        else:
            args["query"] = query
            fql_method = 'fql.query'
 
        args["format"] = "json"
 
        file = urllib.request.urlopen("https://api.facebook.com/method/" +
                               fql_method + "?" + urllib.parse.urlencode(args),
                               post_data)
        try:
            content = file.read()
            print(content)
            response = _parse_json(content)
            #Return a list if success, return a dictionary if failed
            if type(response) is dict and "error_code" in response:
                raise GraphAPIError(response)
        except Exception as e:
            raise e
        finally:
            file.close()
 
        return response

    def get_app_access_token(self, app_id, app_secret):
        """Get the application's access token as a string."""
        args = {'grant_type': 'client_credentials',
                'client_id': app_id,
                'client_secret': app_secret}

        return self.request("oauth/access_token", args=args)["access_token"]

    def get_access_token_from_code(
            self, code, redirect_uri, app_id, app_secret):
        """Get an access token from the "code" returned from an OAuth dialog.

        Returns a dict containing the user-specific access token and its
        expiration date (if applicable).

        """
        args = {
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": app_id,
            "client_secret": app_secret}

        return self.request("oauth/access_token", args)

    def extend_access_token(self, app_id, app_secret):
        """
        Extends the expiration time of a valid OAuth access token. See
        <https://developers.facebook.com/roadmap/offline-access-removal/
        #extend_token>

        """
        args = {
            "client_id": app_id,
            "client_secret": app_secret,
            "grant_type": "fb_exchange_token",
            "fb_exchange_token": self.access_token,
        }

        return self.request("access_token", args=args)


class GraphAPIError(Exception):
    def __init__(self, result):
        self.result = result
        try:
            self.type = result["error_code"]
        except:
            self.type = ""

        # OAuth 2.0 Draft 10
        try:
            self.message = result["error_description"]
        except:
            # OAuth 2.0 Draft 00
            try:
                self.message = result["error"]["message"]
            except:
                # REST server style
                try:
                    self.message = result["error_msg"]
                except:
                    self.message = result

        Exception.__init__(self, self.message)


def get_user_from_cookie(cookies, app_id, app_secret):
    """Parses the cookie set by the official Facebook JavaScript SDK.

    cookies should be a dictionary-like object mapping cookie names to
    cookie values.

    If the user is logged in via Facebook, we return a dictionary with
    the keys "uid" and "access_token". The former is the user's
    Facebook ID, and the latter can be used to make authenticated
    requests to the Graph API. If the user is not logged in, we
    return None.

    Download the official Facebook JavaScript SDK at
    http://github.com/facebook/connect-js/. Read more about Facebook
    authentication at
    http://developers.facebook.com/docs/authentication/.

    """
    cookie = cookies.get("fbsr_" + app_id, "")
    if not cookie:
        return None
    parsed_request = parse_signed_request(cookie, app_secret)
    if not parsed_request:
        return None
    try:
        result = get_access_token_from_code(parsed_request["code"], "",
                                            app_id, app_secret)
    except GraphAPIError:
        return None
    result["uid"] = parsed_request["user_id"]
    return result


def parse_signed_request(signed_request, app_secret):
    """ Return dictionary with signed request data.

    We return a dictionary containing the information in the
    signed_request. This includes a user_id if the user has authorised
    your application, as well as any information requested.

    If the signed_request is malformed or corrupted, False is returned.

    """
    try:
        encoded_sig, payload = list(map(str, signed_request.split('.', 1)))

        sig = base64.urlsafe_b64decode(encoded_sig + "=" *
                                       ((4 - len(encoded_sig) % 4) % 4))
        data = base64.urlsafe_b64decode(payload + "=" *
                                        ((4 - len(payload) % 4) % 4))
    except IndexError:
        # Signed request was malformed.
        return False
    except TypeError:
        # Signed request had a corrupted payload.
        return False

    data = json.loads(data)
    if data.get('algorithm', '').upper() != 'HMAC-SHA256':
        return False

    # HMAC can only handle ascii (byte) strings
    # http://bugs.python.org/issue5285
    app_secret = app_secret.encode('ascii')
    payload = payload.encode('ascii')

    expected_sig = hmac.new(app_secret,
                            msg=payload,
                            digestmod=hashlib.sha256).digest()
    if sig != expected_sig:
        return False

    return data


def auth_url(app_id, canvas_url, perms=None, **kwargs):
    url = "https://www.facebook.com/dialog/oauth?"
    kvps = {'client_id': app_id, 'redirect_uri': canvas_url}
    if perms:
        kvps['scope'] = ",".join(perms)
    kvps.update(kwargs)
    return url + urllib.parse.urlencode(kvps)


def get_access_token_from_code(code, redirect_uri, app_id, app_secret):
    return GraphAPI().get_access_token_from_code(
        code, redirect_uri, app_id, app_secret)


def get_app_access_token(app_id, app_secret):
    return GraphAPI().get_app_access_token(app_id, app_secret)

API = GraphAPI

