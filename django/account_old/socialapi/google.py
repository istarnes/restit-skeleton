import requests
from urllib.parse import urlencode
import json
from django.conf import settings
# https://clients6.google.com/rpc?key=YOUR_API_KEY

def user_data(access_token):
    """Return user data from Google API"""
    data = urlencode({'oauth_token': access_token})

    res = requests.get('https://www.googleapis.com/userinfo/v2/me?' + data, headers={'Authorization': data})
    print((res.text))
    print("----")
    url = "https://www.googleapis.com/plus/v1/people/me/people/collection?"
    res = requests.get(url + data, headers={'Authorization': data})

    api = GoogleAPI(access_token)
    guser =  api.getUser()

    print((res.text))
    # try:
    # 	u_data = json.loads(urlopen(request).read())
    # 	u_data["access_token"] = access_token
    # 	if "mobile_token" in kwargs:
    # 		u_data["mobile_token"] = kwargs["mobile_token"]
    # 	elif "refresh_token" in kwargs:
    # 		u_data["refresh_token"] = kwargs["refresh_token"]
    # 	return u_data
    # except (ValueError, IOError):
    # 	print "ERROR LOADING DATA"
    # return None

def getAudienceSize(user, access_token=None):
    if not access_token:
        access_token = user.getAccessToken("google")
    if not access_token:
        return 0
    api = GoogleAPI(access_token)
    guser =  api.getUser()
    # BECAUSE google followers are not really followers
    # googleplus forced loads to be online this skews the data
    # so for now we just return 0
    if "circledByCount" in guser:
        return guser["circledByCount"]
    return 0
    
def getEngagementForURL(url):
    data = getStatsForURL(url)
    if data and "count" in data:
        return int(data["count"])
    return 0

def updateStatsForContentShare(share, get_text=False):
    shares = getEngagementForURL(share.remote_id)
    if shares and share.shares != shares:
        share.shares = shares
        share.verified = True
        share.save()
    return


def getStatsForURL(url):
    body = json.dumps({
        'method': 'pos.plusones.get', 
        'id': 'p', 
        'key': 'p', 
        'params': { 
            'nolog': True, 
            'id': url, 
            'source': 'widget', 
            },
        'jsonrpc': '2.0', 
        'apiVersion': 'v1'
        })
    r = requests.post('https://clients6.google.com/rpc', data=body)
    data = r.json()
    try:
        return {"count":data['result']['metadata']['globalCounts']['count']}
    except:
        pass
    return {}



class GoogleAPI(object):
    def __init__(self, access_token=None, client_id=None):
        self.api_url = "https://www.googleapis.com/plus"
        self.api_version = "v1"
        self.access_token = access_token
        self.user_info = None
        self.last_user = None
        if client_id is None:
            self.client_id = settings.SOCIAL_AUTH_GOOGLE_KEY
        else:
            self.client_id = client_id

    def GET(self, path, params={}):
        if self.access_token:
            params["access_token"] = self.access_token
        else:
            params["key"] = self.client_id
        url = "{0}/{1}/{2}".format(self.api_url, self.api_version, path)
        # print url
        r = requests.get(url, params=params)
        # print r.text
        if r.status_code == 200:
            return r.json()
        return None

    def getUser(self, user_id="me", force=False):
        path = "people/{0}".format(user_id)
        if not force and self.last_user:
            force = user_id != self.last_user
        if force or self.user_info is None:
            self.last_user = user_id
            self.user_info = self.GET(path)
        return self.user_info
