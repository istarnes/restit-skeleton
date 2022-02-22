
import requests
import json

from django.conf import settings

from datetime import datetime

class InstagramResult(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self
    def __getattr__(self, item):
            return None

# look into installing https://github.com/bear/python-twitter
def getAudienceSize(user, access_token=None):
    if not access_token:
        access_token = user.getProperty("instagram_token", None, "social")
    if access_token is None:
        return 0
    api = InstagramAPI(access_token=access_token)
    return api.getFollowersCount("self")

def getEngagementForURL(url):
    return 0

def getStatsForContentShare(share, get_text=False):
    if not share.remote_id or len(share.remote_id) == 0:
        return None
    access_token = share.owner.getProperty("instagram_token", None, "social")
    api = InstagramAPI(access_token=access_token)
    stats = api.getMediaStats(share.remote_id)
    if stats:
        audience = share.getAudience()
        result = InstagramResult()
        result.comments = stats["comments"]["count"]
        result.likes = stats["likes"]["count"]
        result.engagement = result.comments + result.likes
        if share.message is None and "text" in stats["caption"]:
            result.message = stats["caption"]["text"]

        if audience:
            engagment_rate = share.engagement * 1.0 / audience
            age = (datetime.now() - share.created).total_seconds() * 1.0 / 60 
            result.views = max((1.0 - math.pow(1.0 - engagment_rate, age)) * (audience * ((share.engagement * 2.0/audience))), share.engagement * 3)
        return result
    return None

def updateStatsForContentShare(share, get_text=False):
    if not share.remote_id or len(share.remote_id) == 0:
        return
    access_token = share.owner.getProperty("instagram_token", None, "social")
    api = InstagramAPI(access_token=access_token)
    stats = api.getMediaStats(share.remote_id)
    if stats:
        share.comments = stats["comments"]["count"]
        share.likes = stats["likes"]["count"]
        share.engagement = share.comments + share.likes
        caption = stats["caption"]
        if share.message is None and caption and "text" in caption:
            share.message = stats["caption"]["text"]
        share.save()


INSTAGRAM_CLIENT_ID = None
if hasattr(settings, "SOCIAL_AUTH_INSTAGRAM_KEY"):
    INSTAGRAM_CLIENT_ID = getattr(settings, "SOCIAL_AUTH_INSTAGRAM_KEY")

INSTAGRAM_API_URL = "https://api.instagram.com/v1"
INSTAGRAM_MEDIA_URL = "media/{0}/"
INSTAGRAM_LIKES_URL = "media/{0}/likes/"
INSTAGRAM_COMMENTS_URL = "media/{0}/comments/"

INSTAGRAM_USER_URL = "users/{0}/"
INSTAGRAM_FOLLOWERS_URL = "users/{0}/followed-by/"
INSTAGRAM_RECENT_URL = "users/{0}/media/recent/"

class InstagramAPI(object):
    def __init__(self, access_token=None, client_id=None):
        self.api_version = "v1"
        self.access_token = access_token
        self.user_info = None
        self.last_user = None
        if client_id is None:
            self.client_id = settings.SOCIAL_AUTH_INSTAGRAM_KEY
        else:
            self.client_id = client_id

    def GET(self, path, params={}):
        if self.access_token:
            params["access_token"] = self.access_token
        else:
            params["client_id"] = self.client_id
        url = "https://api.instagram.com/{0}/{1}".format(self.api_version, path)
        r = requests.get(url, params=params)
        if r.status_code == 200:
            data = r.json()
            if data and "meta" in data:
                if data["meta"] and data["meta"]["code"] == 200:
                    return data["data"]
        return None

    def getMediaStats(self, media_id):
        """
        data.created
        data.comments.count
        data.likes.count
        """
        res = self.GET(INSTAGRAM_MEDIA_URL.format(media_id))
        if res and res["comments"]:
            return res
        return None

    def getLikes(self, media_id):
        return self.GET(INSTAGRAM_LIKES_URL.format(media_id))

    def getComments(self, media_id):
        return self.GET(INSTAGRAM_COMMENTS_URL.format(media_id))

    def getFollowersCount(self, user_id="self"):
        data = self.getUser(user_id)
        if data and "counts" in data:
            return data["counts"]["followed_by"]
        return 0

    def getPostCount(self, user_id="self"):
        data = self.getUser(user_id)
        if data and "counts" in data:
            return data["counts"]["media"]
        return 0

    def getFollowingCount(self, user_id="self"):
        data = self.getUser(user_id)
        if data and "counts" in data:
            return data["counts"]["follows"]
        return 0

    def getUser(self, user_id="self", force=False):
        """
        "data": {
            "id": "1574083",
            "username": "snoopdogg",
            "full_name": "Snoop Dogg",
            "profile_picture": "http://distillery.s3.amazonaws.com/profiles/profile_1574083_75sq_1295469061.jpg",
            "bio": "This is my bio",
            "website": "http://snoopdogg.com",
            "counts": {
                "media": 1320,
                "follows": 420,
                "followed_by": 3410
            }
        """
        if not force and self.last_user:
            force = user_id != self.last_user
        if force or self.user_info is None:
            self.last_user = user_id
            self.user_info = self.GET(INSTAGRAM_USER_URL.format(user_id))
        return self.user_info

    def getFollowers(self, user_id):
        return self.GET(INSTAGRAM_FOLLOWERS_URL.format(user_id))


    def getRecent(self, user_id, count=1, min_time=None):
        params = {}
        params["count"] = count
        if min_time:
            params["min_timestamp"] = min_time
        return self.GET(INSTAGRAM_LIKES_URL.format(media_id), params=params)

API=InstagramAPI

