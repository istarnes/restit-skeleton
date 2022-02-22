from django.db import models
from django.conf import settings

from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from account.models import User, Member, Group, MemberFeed
from location.models import GeoIP, Address

from rest import helpers as rest_helpers
from rest.models import RestModel, MetaDataBase, MetaDataModel
from rest import RemoteEvents

from hashids import Hashids
from rest import mail

from datetime import datetime, timedelta

from telephony.models import SMS
from . import apns


# Create Topics that people can subscribe to
class Topic(models.Model, RestModel):
    class RestMeta:
        GRAPHS = {
            "basic": {
            },
        }	

    created = models.DateTimeField(auto_now_add=True, editable=False)
    owner = models.ForeignKey(Member, related_name="+", null=True, blank=True, default=None, on_delete=models.CASCADE)
    group = models.ForeignKey(Group, related_name="+", null=True, blank=True, default=None, on_delete=models.CASCADE)

    name = models.CharField(max_length=124, db_index=True)




class Device(models.Model, RestModel):
    class RestMeta:
        GRAPHS = {
            "basic": {
            },
        }
    created = models.DateTimeField(auto_now_add=True, editable=False)
    owner = models.ForeignKey(Member, related_name="+", null=True, blank=True, default=None, on_delete=models.CASCADE)
    token = models.CharField(max_length=200, blank=True, null=True, default=None)	
    service = models.CharField(max_length=200, blank=True, null=True, default=None)

    platform = models.CharField(max_length=200, blank=True, null=True, default=None)
    hw_version = models.CharField(max_length=200, blank=True, null=True, default=None)
    os_version = models.CharField(max_length=200, blank=True, null=True, default=None)
    
    rid = models.CharField(max_length=200, blank=True, null=True, default=None)
    
    is_enabled = models.BooleanField(default=True)

    def send(self, msg, badge=1):
        if self.service == "apns":
            apns.send(self.token, msg, cert_file=settings.NOTIFY_APNS_CERT, key_file=settings.NOTIFY_APNS_KEY)

    @staticmethod
    def register(owner, token, service, platform=None, hw_version=None, os_version=None):
        devs = Device.objects.filter(token=token)
        dev = Device.objects.filter(owner=owner, token=token).first()
        if (devs.count() and not dev) or (devs.count() > 1):
            devs.update(is_enabled=False)

        dev = Device.objects.filter(owner=owner, token=token).first()
        if not dev:
            dev = Device(owner=owner, token=token, service=service, platform=platform, hw_version=hw_version, os_version=os_version)
            dev.save()
        elif dev.is_enabled is False:
            dev.is_enabled = True
            dev.save()
        return dev


class NotificationSetting(models.Model, RestModel):
    class RestMeta:
        GRAPHS = {
            "basic": {
            },
        }
    topic = models.ForeignKey(Topic, related_name="+", on_delete=models.CASCADE)
    owner = models.ForeignKey(Member, related_name="notify_settings", on_delete=models.CASCADE)
    action = models.CharField(max_length=64, blank=True, null=True, default=None)
    transport = models.CharField(max_length=124, blank=True, null=True, default=None)

    is_enabled = models.BooleanField(default=True)



class Notification(models.Model, RestModel):
    class RestMeta:
        FILTER_FIELDS=["state", "created", "owner", "group"]
        GRAPHS = {
            "basic": {
            },
        }

    sid = models.CharField(max_length=125, blank=True, null=True, default=None)
    created = models.DateTimeField(auto_now_add=True, editable=False)

class Notify(object):
    @staticmethod
    def sendAPNS(token, alert, sound="default", badge=1):
        pass

    @staticmethod
    def sendToTopic(member, message, topic=None, action=None):
        pass

    @staticmethod
    def sendToGroup(group, message, topic=None, action=None, exclude=None, custom=None):
        members = Member.objects.filter(memberships__group=group).distinct()
        if exclude:
            if type(exclude) is not list:
                exclude = [exclude]
            mids = [m.pk for m in exclude]
            members = members.exclude(pk__in=mids)
        Notify.sendToMembers(members, message, topic, action, custom=custom)

    @staticmethod
    def sendToMembers(members, message, topic=None, action=None, custom=None):
        use_sandbox = settings.NOTIFY_APNS_SANDBOX
        apns_tokens = []
        mids = [m.pk for m in members]
        for device in Device.objects.filter(owner__pk__in=mids, is_enabled=True):
            if device.service == "apns":
                apns_tokens.append(device.token)		
        if len(apns_tokens):
            apns.sendMultiple(apns_tokens, message, cert_file=settings.NOTIFY_APNS_CERT, key_file=settings.NOTIFY_APNS_KEY, use_sandbox=use_sandbox, custom=custom)

    @staticmethod
    def sendToMember(member, message, topic=None, action=None, custom=None):
        use_sandbox = settings.NOTIFY_APNS_SANDBOX
        apns_tokens = []
        for device in Device.objects.filter(owner=member, is_enabled=True):
            if device.service == "apns":
                apns_tokens.append(device.token)
        if len(apns_tokens):
            apns.sendMultiple(apns_tokens, message, cert_file=settings.NOTIFY_APNS_CERT, key_file=settings.NOTIFY_APNS_KEY, use_sandbox=use_sandbox, custom=custom)

        # phone = member.getProperty("phone", None)
        # if phone:
        # 	SMS.send(phone, message, to=member)
