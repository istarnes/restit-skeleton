import json
import urllib.request, urllib.error, urllib.parse

from account.models import *
from account.forms import *
from medialib.models import *

FAKE_USER_URL = "http://api.randomuser.me/"

def saveImageToLib(owner, url, name="Social Profile Pic", download=False):
    lib = MediaLibrary.objects.filter(owner=owner)[:1]
    if len(lib) == 0:
        lib = MediaLibrary(name="User Media Library", owner=owner)
        lib.save()
    else:
        print("already have media library!")
        lib = lib[0]

    picture = MediaItem(library=lib, owner=owner, name="Social Profile Pic", kind='I', state=0)
    print(url)
    if download:
        picture.downloadurl = url
    else:
        picture.newurl = url
    picture.save()
    owner.picture = picture
    owner.save()

def getFakeUsers(howmany=1):
    url = FAKE_USER_URL
    if howmany > 1:
        url = "{0}?results={1}".format(FAKE_USER_URL, howmany)
    res = json.load(urllib.request.urlopen(url))
    return res["results"]

def createFakeUsers(howmany=10, post_create=None):
    users = getFakeUsers(howmany)
    generated = []
    for item in users:
        data = {}
        user = item["user"]
        data["username"] = user["username"]
        data["first_name"] = user["name"]["first"].title()
        data["last_name"] = user["name"]["last"].title()
        data["phone"] = user["cell"]
        data["email"] = user["email"]
        f = NewUserForm(data)
        if not f.is_valid():
            print("new member")
            print((f.errors))
            return
        member = f.save()
        location = user["location"]
        member.setProperty("street", location["street"], "location")
        member.setProperty("city", location["city"], "location")
        member.setProperty("state", location["state"], "location")
        member.setProperty("country", "USA", "location")
        member.setProperty("zip", location["zip"], "location")

        member.setProperty("birthday", user["dob"])
        member.setProperty("gender", user["gender"])

        saveImageToLib(member, user["picture"]["medium"])
        if post_create:
            post_create(member, user)


