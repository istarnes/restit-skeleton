from django.conf import settings
from django.core.cache import cache
import requests
import time
from datetime import datetime
import math

def hitLimits(access_token):
    # now lets check our rate limits for this token
    limits = int(cache.get("tweet_limit_"+access_token, 0))
    if limits > 0:
        delta = time.time() - limits
        if delta < TWITTER_LIMIT_TIMER:
            return True
        # clear limit
        cache.set("tweet_limit_"+access_token, 0)
    return False

def setRateLimit(access_token):
    cache.set("tweet_limit_"+access_token, int(time.time()))

class TwitterResult(dict):
    def __init__(self, **kw):
        dict.__init__(self, kw)
        self.__dict__ = self
    def __getattr__(self, item):
            return None

def getTwitterClient(user):
    access_token, secret_token = getAccessTokens(user)
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = TwitterAPI(access_token, secret_token)
    return api

def getAccessTokens(user, access_token=None):
    secret_token = None
    if not access_token:
        access_token = user.getAccessTokens("twitter")
    # twitter does not expire access_tokens so this is good
    if access_token and "oauth_token_secret" in access_token:
        secret_token = access_token["oauth_token_secret"]
        access_token = access_token["oauth_token"]
    return access_token, secret_token


def postMedia(user, media, text):
    access_token, secret_token = getAccessTokens(user)
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = TwitterAPI(access_token, secret_token)
    if len(text) > 140:
        text = text[:139]
        print("TWITTER POST OVER 140.. truncating")

    # print "TWITTER POSTING: '{0}' at {1} chars".format(text, len(text))
    if media.kind != "I":
        tweet = api.postTweet(text)
        return {
            "status":True,
            "remote_id":tweet.id_str,
            "text":tweet.text
        }

    if media.isAnimated():
        rendition = media.original()
    else:
        rendition = media.getImageRendition(width=1024, flat=False)
    fp = rendition.get_file()
    fp.seek(0)
    
    try:
        tweet = api.postTweetWithMedia(text, fp)
    except TwitterRateLimitError as err:
        print("TWITTER RATE LIMIT HIT")
        return {
            "status":False,
            "error":"rate limit reached"
        }
    except TwitterApiError as err:
        print(("TWITTER API ERROR: {0}".format(err)))
        return {
            "status":False,
            "error":"{0}".format(err)
        }

    return {
        "status":True,
        "remote_id":tweet.id_str,
        "text":tweet.text
    }

def postLink(user, link, text):
    print(user)
    access_token, secret_token = getAccessTokens(user)
    if not access_token:
        return {"status":False, "error":"no access token available"}
    api = TwitterAPI(access_token, secret_token)
    if link not in text:
        text = "{0} {1}".format(text, link)
    if len(text) > 140:
        text = text[:140]

    try:
        tweet = api.postTweet(text)
    except TwitterRateLimitError as err:
        print("TWITTER RATE LIMIT HIT")
        return {
            "status":False,
            "error":"rate limit reached"
        }
    except TwitterApiError as err:
        print(("TWITTER API ERROR: {0}".format(err)))
        return {
            "status":False,
            "error":"{0}".format(err)
        }

    return {
        "status":True,
        "remote_id":tweet.id_str,
        "text":tweet.text
    }

def getAudienceSize(user, access_token=None):
    access_token, secret_token = getAccessTokens(user, access_token)
    if not access_token:
        return None

    if hitLimits(access_token):
        return None

    api = TwitterAPI(access_token, secret_token)
    cnt = api.getFollowersCount()
    if api.limit_remaining != None and api.limit_remaining < 10:
        setRateLimit(access_token)
    return cnt

def getAvatar(user, access_token=None):
    access_token, secret_token = getAccessTokens(user, access_token)
    api = TwitterAPI(access_token, secret_token)
    data = api.getUserInfo()
    if data and "profile_image_url" in data:
        return data["profile_image_url"]
    return None

def getEngagementForURL(url):
    data = getStatsForURL(url)
    if data and "count" in data:
        return data["count"]
    return 0


def getRecentTweetForShare(share):
    # we are trying to get the last post and get the message
    access_token, secret_token = getAccessTokens(share.owner)
    if access_token:
        api = TwitterAPI(access_token, secret_token)
        print("getting last tweet")
        tweet = api.getLastTweet()
        if "entities" in tweet and "urls" in tweet.entities:
            print("-- got tweet")
            match = False
            for u in tweet.entities.urls:
                if "display_url" in u and share.remote_id.endswith(u.display_url):
                    match = True
                    break
        if not match:
            print("-- tweet has no matching urls, checking age")
            # lets look at the timestamp.. if it is close lets assume yes
            age = api.getTweetAge(tweet)
            match = age < 120
            print(("-- tweet age is {0}s".format(age)))

        if match:
            print("-- saving tweet")
            # we have a match lets update
            share.verified = True
            share.remote_id = tweet.id_str
            share.message = tweet.text
            share.likes = tweet.favorite_count
            share.shares = tweet.retweet_count
            share.engagement = tweet.favorite_count + last.retweet_count
            share.save()
        return

def updateStatsForContentShare(share, get_text=False):
    if get_text:
        return getRecentTweetForShare(share)

    result = getStatsForContentShare(share, get_text)
    if result:
        if result.message:
            share.message = result.message
        if result.likes:
            share.likes = result.likes
        if result.shares:
            share.shares = result.shares
        
        share.engagement = result.engagement
        if "views" in result:
            share.views = result.views

        if share.audience and share.engagement:
            share.engagment_ratio = share.engagement * 1.0 / share.audience 
        share.save()


def getStatsForContentShare(share, get_text=False):
    audience = share.getAudience()
    # check if we have a remote id
    result = TwitterResult()

    if share.remote_id:
        access_token, secret_token = getAccessTokens(share.owner)
        if not access_token:
            return None

        if hitLimits(access_token):
            return None
        # no remote id lets try old fashion
        api = TwitterAPI(access_token, secret_token)
        try:
            tweet = api.getTweet(share.remote_id)
            if api.limit_remaining != None and api.limit_remaining < 10:
                setRateLimit(access_token)
        except TwitterRateLimitError as err:
            setRateLimit(access_token)
            print("TWITTER RATE LIMIT HIT")
            return None
        except TwitterApiError as err:
            print(("TWITTER API ERROR: {0}".format(err)))
            return None

        if not result.message:
            result.message = tweet.text
        result.likes = tweet.favorite_count
        result.shares = tweet.retweet_count
        result.engagement = tweet.favorite_count + tweet.retweet_count
        if audience:
            engagment_rate = share.engagement * 1.0 / audience
            age = (datetime.now() - share.created).total_seconds() * 1.0 / 60 
            result.views = max((1.0 - math.pow(1.0 - engagment_rate, age)) * (audience * ((share.engagement * 2.0/audience))), share.engagement * 3)
        return result
    print("no remote id???")
    
    # try old fashion way
    # NO LONGER AVAILABLE
    # shares = getEngagementForURL(share.remote_url)
    # if shares:
    # 	result.engagement = shares
    # 	return result

    return None


def getStatsForURL(url):
    # THIS IS SUPPOSE TO BE DEPRECATED BUT STILL WORKS
    # I CAN NOT FIND AN ALTERNATIVE FOR THIS RIGHT NOW
    r = requests.get("http://urls.api.twitter.com/1/urls/count.json", params={"url":url})
    return r.json()

# https://upload.twitter.com/1.1/media/upload.json

try:
    from birdy.twitter import UserClient, BaseTwitterClient, TwitterAuthError, TwitterRateLimitError, TwitterApiError
except:
    BaseTwitterClient = None

try:
    from twython import Twython
except:
    Twython = None

class TwitterAPI(object):
    def __init__(self, access_token=None, secret_token=None, consumer_key=None, consumer_secret=None):
        self.api_version = "1.1"
        self.access_token = access_token
        self.secret_token = secret_token
        self.limit_ceiling = None
        self.limit_remaining = None
        self.limit_reset = None

        if consumer_key is None:
            self.consumer_key = settings.SOCIAL_AUTH_TWITTER_KEY
            self.consumer_secret = settings.SOCIAL_AUTH_TWITTER_SECRET
        else:
            self.consumer_key = consumer_key
            self.consumer_secret = consumer_secret

        if access_token is None:
            self.access_token = settings.TWITTER_ACCESS_TOKEN
            self.secret_token = settings.TWITTER_ACCESS_TOKEN_SECRET

        for token in ["access_token", "secret_token", "consumer_secret", "consumer_key"]:
            if getattr(self, token) is None:
                raise Exception("{0} required for Twitter API".format(token))

        self.user_info = None
        self.client = UserClient(self.consumer_key, self.consumer_secret, self.access_token, self.secret_token)

    def getTweetAge(self, tweet):
        when = self.convertTwitterTime(tweet.created_at)
        return time.time() - when

    def convertTwitterTime(self, twitter_time):
        try:
            tt = time.strptime(twitter_time,'%a %b %d %H:%M:%S +0000 %Y')
            return time.mktime(tt)
        except:
            pass
        return 0

    def updateLimits(self, response):
        try:
            self.limit_ceiling = response.headers["X-RATE-Limit-Limit"]
            self.limit_remaining = response.headers["X-RATE-Limit-Remaining"]
            self.limit_reset = response.headers["X-RATE-Limit-Reset"]
            print(("TWITTER LIMITS: ceiling: {0} remaining: {1} reset: {2}".format(self.limit_ceiling, self.limit_remaining, self.limit_reset)))
        except:
            pass
        return response

    def search(self, query):
        # count, until=before date, since_id, result_type(mixed, recent, popular)
        response = self.client.api.search.tweets.get(q=query)
        self.updateLimits(response)
        return response.data

    def getUserInfo(self, user_id=None, screen_name=None, force=True):
        if not self.user_info or force:
            response = None
            if user_id:
                response = self.client.api.users.show.get(user_id=user_id)
            elif screen_name:
                response = self.client.api.users.show.get(screen_name=screen_name)
            else:
                response = self.client.api.account.verify_credentials.get()
        self.user_info = response.data
        self.updateLimits(response)
        return self.user_info

    def getFollowersCount(self):
        self.getUserInfo(force=False)
        if self.user_info and "followers_count" in self.user_info:
            return self.user_info["followers_count"]
        return 0

    def getFriendsCount(self):
        self.getUserInfo()
        if self.user_info and "friends_count" in self.user_info:
            return self.user_info["friends_count"]
        return 0

    def getLastTweet(self):

        response = self.client.api.statuses.user_timeline.get(count=1)
        self.updateLimits(response)

        last = response.data
        if last and len(last):
            return last[0]
        return None

    def postTweetWithMedia(self, text, media):
        client = Twython(self.consumer_key, self.consumer_secret, self.access_token, self.secret_token)
        res = client.upload_media(media=media)
        # params = {"status":text, "media[]":media.read()}
        # return client.update_status(status=text, media_ids=res['media_id'])
        response = self.client.api.statuses.update.post(status=text, media_ids=res['media_id'])
        self.updateLimits(response)
        return response.data

    def postTweet(self, text):
        response = self.client.api.statuses.update.post(status=text)
        self.updateLimits(response)
        return response.data

    def getReTweets(self, tweet_id, count=50, trim_user=0):
        response = self.client.api.statuses.retweets.get(id=tweet_id, count=count, trim_user=trim_user)
        self.updateLimits(response)
        return response.data

    def getTweet(self, tweet_id, trim_user=0):
        # include_my_retweet
        response = self.client.api.statuses.show.get(id=tweet_id, trim_user=trim_user)
        self.updateLimits(response)
        return response.data

    def getStatusCount(self):
        self.getUserInfo()
        if self.user_info and "statuses_count" in self.user_info:
            return self.user_info["statuses_count"]
        return 0
    def getStatus(self):
        self.getUserInfo()
        if self.user_info and "status" in self.user_info:
            return self.user_info["status"]
        return 0	
