
import urllib, urllib2

from django.conf import settings

import threading

GA_URL = "http://www.google-analytics.com/collect"

def _makeRequest(query_args):
    # This urlencodes your data (that's why we need to import urllib at the top)
    data = urllib.urlencode(query_args)
    # Send HTTP POST request
    request = urllib2.Request(GA_URL, data)
    response = urllib2.urlopen(request)

def trackEvent(clientId, category, action, label=None, value=None, ip=None, user_agent=None):
    """
    v=1             // Version.
    &tid=UA-XXXX-Y  // Tracking ID / Web property / Property ID.
    &cid=555        // Anonymous Client ID.

    &t=event        // Event hit type
    &ec=video       // Event Category. Required.
    &ea=play        // Event Action. Required.
    &el=holiday     // Event label.
    &ev=300         // Event value.
    """

    if not hasattr(settings, "GOOGLE_ANALYTICS"):
        return False

    # Prepare the data
    query_args = {
        'v':'1',
        'tid':getattr(settings, "GOOGLE_ANALYTICS", ""),
        'cid':clientId,
        't':"event",
        'ec':category,
        'ea':action
    }

    if label:
        query_args["el"] = label

    if value:
        query_args["ev"] = value

    if ip:
        query_args["uip"] = ip

    if user_agent:
        query_args["ua"] = user_agent

    _makeRequest(query_args)
    # t = threading.Thread(target=_makeRequest, args=[query_args])
    # t.setDaemon(True)
    # t.start()
    return True
