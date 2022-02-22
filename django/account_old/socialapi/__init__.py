import requests
import threading
from concurrent import futures

from . import facebook
from . import twitter
from . import pinterest
from . import instagram
from . import google
from . import linkedin

"""
Facebook*: https://api.facebook.com/method/links.getStats?urls=%%URL%%&format=json
Twitter: http://urls.api.twitter.com/1/urls/count.json?url=%%URL%%
Reddit:http://buttons.reddit.com/button_info.json?url=%%URL%%
LinkedIn: http://www.linkedin.com/countserv/count/share?url=%%URL%%&format=json 
Digg: http://widgets.digg.com/buttons/count?url=%%URL%% 
Delicious: http://feeds.delicious.com/v2/json/urlinfo/data?url=%%URL%%
StumbleUpon: http://www.stumbleupon.com/services/1.01/badge.getinfo?url=%%URL%%
Pinterest: http://widgets.pinterest.com/v1/urls/count.json?source=6&url=%%URL%%
"""

PLATFORM_MODULES = {
    "facebook":facebook,
    "twitter":twitter,
    "pinterest":pinterest, 
    "instagram":instagram, 
    "linkedin":linkedin,
    "linkedin-oauth2":linkedin,
    "googleplus":google,
    "google":google
}

PLATFORMS = list(PLATFORM_MODULES.keys())
POSTABLE_PLATFORMS = [
    "twitter", "facebook", "linkedin"
]

"""
The below APIs are implemented in each social module

each social platform should implement:
    getAudienceSize(user)
    getEngagementForURL(url)
    updateStatsForContentShare(share)
"""

def postMedia(platform, user, media, text):
    """
    Attempts to post a link the the specified platform.
    It should return a response dictionary
        {
            status:True/False
            error: None
            remote_id: 12313131
        }
    """
    if platform in POSTABLE_PLATFORMS:
        api = PLATFORM_MODULES[platform]
        return api.postMedia(user, media, text)
    return {"status":False, "error":"not supported"}

def postLink(platform, user, link, text):
    """
    Attempts to post a link the the specified platform.
    It should return a response dictionary
        {
            status:True/False
            error: None
            remote_id: 12313131
        }
    """
    if platform in POSTABLE_PLATFORMS:
        api = PLATFORM_MODULES[platform]
        return api.postLink(user, link, text)
    return {"status":False, "error":"not supported"}

def getAudienceSizeFor(platform, user, access_token=None):
    """
    Returns the Audience size for each platform specified
    """
    api = PLATFORM_MODULES[platform]
    return api.getAudienceSize(user, access_token)

def getEngagementForURL(platform, url):
    """
    Returns the engagement around each piece of content 
    """
    api = PLATFORM_MODULES[platform]
    return api.getEngagementForURL(url)

def updateStatsForContentShare(share, get_text=False):
    """
    Returns the engagement around each piece of contentshare
    """
    if share.shared_to in PLATFORM_MODULES:
        api = PLATFORM_MODULES[share.shared_to]
        return api.updateStatsForContentShare(share, get_text)

def getStatsForContentShare(share, get_text=False):
    """
    Returns the engagement around each piece of contentshare
    """
    try:
        if share.shared_to in PLATFORM_MODULES:
            api = PLATFORM_MODULES[share.shared_to]
            return api.getStatsForContentShare(share, get_text)
    except Exception as err:
        print(("{0} ERROR: {1}".format(share.shared_to, err)))
    return None
    
class ContentShareWorker(object):
    """
    This is a simple class to spawn threads that quickly aggregate content stats
    """
    def __init__(self, shares=None, url=None):
        self.shares = shares
        self.url = url
        self.total = 0
        self.results = {}
        self.lock = threading.Lock()

    def fetchEngagementCount(self, platform):
        setattr(self, platform, getEngagementForURL(platform, self.url))

    def updateStats(self, share):
        result = getStatsForContentShare(share)
        if result:
            self.lock.acquire()
            self.results[share.id] = result
            self.lock.release()


    def updateTotal(self):
        self.total = 0
        for p in PLATFORMS:
            if hasattr(self, p):
                self.total += getattr(self, p)
        return self.total

    def syncURL(self):
        with futures.ThreadPoolExecutor(max_workers=3) as e:
            for p in PLATFORMS:
                if hasattr(PLATFORM_MODULES[p], "getEngagementForURL"):
                    e.submit(self.fetchEngagementCount, p)
        self.updateTotal()

    def syncSHARES(self):
        with futures.ThreadPoolExecutor(max_workers=3) as e:
            for share in self.shares:
                e.submit(self.updateStats, share)
        # thread pool is done lets use our safe main thread to update DB
        for share in self.shares:
            if share.id in self.results:
                result = self.results[share.id]
                if result.likes:
                    share.likes = result.likes
                if result.shares:
                    share.shares = result.shares
                if result.comments:
                    share.comments = result.comments
                if result.views:
                    share.views = result.views
                if result.engagement:
                    share.engagement = result.engagement
                share.save()

    def sync(self):
        if self.url:
            self.syncURL()
        elif self.shares:
            self.syncSHARES()

    def toString(self):
        out = ""
        for p in PLATFORMS:
            if hasattr(self, p):
                out += "{0} = {1}, \n".format(p, getattr(self, p))
        return out

    def __str__(self):
        return self.toString()

    def __unicode__(self):
        return self.toString()

def getEngagementTotals(url):
    worker = ContentShareWorker(url=url)
    worker.sync()
    return worker

def updateSharingStats(shares):
    worker = ContentShareWorker(shares=shares)
    worker.sync()
    return worker
