
import requests
import json

# http://widgets.pinterest.com/v1/urls/count.json?source=6&url=%%URL%%

def getAudienceSize(user, access_token=None):
    # tokens = user.getAccessTokens("pinterest")
    # if tokens and tokens.has_key("oauth_token_secret"):
    # 	secret_token = tokens["oauth_token_secret"]
    # 	access_token = tokens["oauth_token"]
    # api = TwitterAPI(access_token, secret_token)
    # return api.getFollowersCount()
    return 0

def getEngagementForURL(url):
    data = getStatsForURL(url)
    if data and "count" in data:
        return data["count"]
    return 0

def updateStatsForContentShare(share, get_text=False):
    if not share.is_remote:
        shares = getEngagementForURL(share.remote_id)
        if shares:
            share.shares = shares
            share.verified = True
            share.save()


def getStatsForURL(url):
    r = requests.get("http://widgets.pinterest.com/v1/urls/count.json", params={"source":6, "url":url})
    a = r.text
    b =a[a.find('{'):a.find('}')+1]
    return json.loads(b)


