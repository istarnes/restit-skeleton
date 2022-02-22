from .models import *

from django.shortcuts import get_object_or_404
from django.http import Http404
from django.db.models import Q

from rest.views import *
from rest.decorators import *

from account.models import Member

import json
import datetime

notification_setting_fields = ('kind', 'web', 'email', 'sms')

@urlPOST (r'^device/register$')
@login_required
def registerDevice(request):
    member, group = Member.getMemberGroup(request)

    if "token" not in request.DATA or "service" not in request.DATA :
        return restStatus(request, False, error="requires token and service")
    token = request.DATA.get("token").replace("<", "").replace(">", "").replace(" ", "")
    service = request.DATA.get("service")
    dev = Device.register(member, token, service, 
        platform=request.DATA.get("platform", None),
        hw_version=request.DATA.get("hw_version", None),
        os_version=request.DATA.get("os_version", None))
    return restStatus(request, True)

@urlGET (r'^kinds$')
@login_required
def kindsList(request):
    """
    | Return: all notification kinds
    """
    ret = list(notification_defaults.values())
    return restList(request, ret, fields=(('name', 'kind'), 'web', 'email', 'sms'))

@urlGET (r'^settings$')
@never_cache
@login_required
def getAllSettings(request):
    """
    | Parameter: user=<id|username|'me'> (default=me) (staff only)
    | Parameter: kinds=<kind,kind,...> (default=all)

    | Return: all notifications for user
    """
    if 'user' in request.DATA and request.user.is_staff:
        user = Member.getUser(request.DATA['user'])
    else:
        user = request.user

    if 'kinds' in request.DATA:
        kinds = request.DATA['kinds'].split(',')
    else:
        kinds = None

    ret = []
    for kind in list(notification_defaults.keys()):
        s = NotificationSetting.get(user, kind)
        ret.append(s)

    return restList(request, ret, fields=notification_setting_fields)

@urlGET (r'^settings/(?P<kind>\w.+)$')
@never_cache
@login_required
def getSetting(request, kind):
    """
    | Parameter: user=<id|username|'me'> (default=me) (staff only)

    | Return: get requested notification settings for user
    """
    if 'user' in request.DATA and request.user.is_staff:
        user = Member.getUser(request.DATA['user'])
    else:
        user = request.user

    if kind not in list(notification_defaults.keys()):
        raise Http404

    ret = NotificationSetting.get(user=user, kind=kind)
    return restGet(request, ret, fields=notification_setting_fields)

@urlPOST (r'^settings/(?P<kind>\w.+)$')
@login_required
def setSetting(request, kind):
    """
    | Parameter: user=<id|username|'me'> (default=me) (staff only)
    | Parameter: <kind>.web, <kind>.email, <kind>.sms=<1|true|yes|0|false|no|(unspecified)>: settings

    | Return: change notification settings for user
    """
    if 'user' in request.DATA and request.user.is_staff:
        user = Member.getUser(request.DATA['user'])
    else:
        user = request.user
    
    if kind not in list(notification_defaults.keys()):
        raise Http404
    
    s, _ = NotificationSetting.objects.get_or_create(user=user, kind=kind)
    
    for k in ('web', 'email', 'sms'):
        if k in request.DATA:
            setattr(s, k, request.DATA[k].lower() in ('1', 'true', 'yes'))
    
    s.save()

    return restStatus(request, True)

@urlPOST (r'^settings$')
@login_required
def setSettings(request):
    """
    | Parameter: user=<id|username|'me'> (default=me) (staff only)
    | Parameter: web, email, sms=<1|true|yes|0|false|no|(unspecified)>: settings

    | Return: change notification settings for user
    """
    if 'user' in request.DATA and request.user.is_staff:
        user = Member.getUser(request.DATA['user'])
    else:
        user = request.user
    
    kinds = []
    for v in request.DATA:
        vs = v.split('.')
        if len(vs) == 1:
            continue
        if not vs[-1] in ('web', 'email', 'sms'):
            continue
        kind = '.'.join(vs[0:-1])
        if kind in kinds:
            continue
        if kind not in list(notification_defaults.keys()):
            raise InternalError('Invalid kind %s' % kind)
        kinds.append(kind)
    
    for kind in kinds:
        s, _ = NotificationSetting.objects.get_or_create(user=user, kind=kind)
    
        for k in ('web', 'email', 'sms'):
            if (kind + '.' + k) in request.DATA:
                setattr(s, k, request.DATA[kind + '.' + k].lower() in ('1', 'true', 'yes'))
    
        s.save()

    return restStatus(request, True)

@urlGET (r'^list$')
@urlGET (r'^list/(?P<listtype>\w.+)$')
@vary_on_cookie
@cache_control(private=True, max_age=5)
@login_required
def listNotifications(request, listtype=None):
    """
    | Parameter: user=<id|username|'me'> (default=me) (staff only)
    | Parameter: read=<1|true|yes|0|false|no|-1|both|either|(unspecified)> (default=both): filter by read status
    | Parameter: deleted=<1|true|yes|0|false|no|-1|both|either|(unspecified)> (default=no): filter by deleted status
    | Parameter: kinds=<kind,kind,...> (default=all)

    | Return: list user's notifications
    """
    if 'user' in request.DATA and request.user.is_staff:
        user = Member.getUser(request.DATA['user'])
    else:
        user = request.user

    notifications = Notification.objects.filter(user=user)

    read = request.DATA.get('read', '-1').lower()
    if read in ('1', 'true', 'yes'):
        notifications = notifications.filter(read__isnull = False)
    elif read in ('0', 'false', 'no'):
        notifications = notifications.filter(read__isnull = True)

    deleted = request.DATA.get('deleted', '0').lower()
    if deleted in ('1', 'true', 'yes'):
        notifications = notifications.filter(deleted__isnull = False)
    elif deleted in ('0', 'false', 'no'):
        notifications = notifications.filter(deleted__isnull = True)

    if 'kinds' in request.DATA:
        kinds = request.DATA['kinds'].split(',')
        filt = Q()
        for kind in kinds:
            c, a = kind.split('.', 1)
            filt |= Q(component=c, action=a)
        
        notifications = notifications.filter(filt)
    
    return restList(request, notifications, fields=["*"], todata=lambda x: x.serialize())


@urlGET (r'^unread$')
@vary_on_cookie
@cache_control(private=True, max_age=5)
@login_required
def unreadCount(request):
    count = Notification.objects.filter(user=request.user, read__isnull=True, deleted__isnull=True).count()
    return restStatus(request, True, {'unread': count})


PIXEL_GIF = 'GIF87a\x01\x00\x01\x00\x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00f\x00\x00\x99\x00\x00\xcc\x00\x00\xff\x00\x00\x003\x0033\x00f3\x00\x993\x00\xcc3\x00\xff3\x00\x00f\x003f\x00ff\x00\x99f\x00\xccf\x00\xfff\x00\x00\x99\x003\x99\x00f\x99\x00\x99\x99\x00\xcc\x99\x00\xff\x99\x00\x00\xcc\x003\xcc\x00f\xcc\x00\x99\xcc\x00\xcc\xcc\x00\xff\xcc\x00\x00\xff\x003\xff\x00f\xff\x00\x99\xff\x00\xcc\xff\x00\xff\xff\x00\x00\x0033\x003f\x003\x99\x003\xcc\x003\xff\x003\x0033333f33\x9933\xcc33\xff33\x00f33f3ff3\x99f3\xccf3\xfff3\x00\x9933\x993f\x993\x99\x993\xcc\x993\xff\x993\x00\xcc33\xcc3f\xcc3\x99\xcc3\xcc\xcc3\xff\xcc3\x00\xff33\xff3f\xff3\x99\xff3\xcc\xff3\xff\xff3\x00\x00f3\x00ff\x00f\x99\x00f\xcc\x00f\xff\x00f\x003f33ff3f\x993f\xcc3f\xff3f\x00ff3fffff\x99ff\xccff\xffff\x00\x99f3\x99ff\x99f\x99\x99f\xcc\x99f\xff\x99f\x00\xccf3\xccff\xccf\x99\xccf\xcc\xccf\xff\xccf\x00\xfff3\xffff\xfff\x99\xfff\xcc\xfff\xff\xfff\x00\x00\x993\x00\x99f\x00\x99\x99\x00\x99\xcc\x00\x99\xff\x00\x99\x003\x9933\x99f3\x99\x993\x99\xcc3\x99\xff3\x99\x00f\x993f\x99ff\x99\x99f\x99\xccf\x99\xfff\x99\x00\x99\x993\x99\x99f\x99\x99\x99\x99\x99\xcc\x99\x99\xff\x99\x99\x00\xcc\x993\xcc\x99f\xcc\x99\x99\xcc\x99\xcc\xcc\x99\xff\xcc\x99\x00\xff\x993\xff\x99f\xff\x99\x99\xff\x99\xcc\xff\x99\xff\xff\x99\x00\x00\xcc3\x00\xccf\x00\xcc\x99\x00\xcc\xcc\x00\xcc\xff\x00\xcc\x003\xcc33\xccf3\xcc\x993\xcc\xcc3\xcc\xff3\xcc\x00f\xcc3f\xccff\xcc\x99f\xcc\xccf\xcc\xfff\xcc\x00\x99\xcc3\x99\xccf\x99\xcc\x99\x99\xcc\xcc\x99\xcc\xff\x99\xcc\x00\xcc\xcc3\xcc\xccf\xcc\xcc\x99\xcc\xcc\xcc\xcc\xcc\xff\xcc\xcc\x00\xff\xcc3\xff\xccf\xff\xcc\x99\xff\xcc\xcc\xff\xcc\xff\xff\xcc\x00\x00\xff3\x00\xfff\x00\xff\x99\x00\xff\xcc\x00\xff\xff\x00\xff\x003\xff33\xfff3\xff\x993\xff\xcc3\xff\xff3\xff\x00f\xff3f\xffff\xff\x99f\xff\xccf\xff\xfff\xff\x00\x99\xff3\x99\xfff\x99\xff\x99\x99\xff\xcc\x99\xff\xff\x99\xff\x00\xcc\xff3\xcc\xfff\xcc\xff\x99\xcc\xff\xcc\xcc\xff\xff\xcc\xff\x00\xff\xff3\xff\xfff\xff\xff\x99\xff\xff\xcc\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x08\x05\x00\x01\xb8\x08\x08\x00;'

@urlPOST (r'^(?P<notification_id>[0-9]+)/read.gif')
@login_required
def readMessageTracker(request, notification_id):
    """
    | Return: status
    
    | Marks the specified notification as read
    """
    return HttpResponse(PIXEL_GIF, mimetype="image/gif")
