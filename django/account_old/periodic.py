
from account.models import Member, Group, NotificationRecord
from datetime import datetime, timedelta
from django.conf import settings

from django.db.models import Avg, Max, Min, Count, Sum, Q

import time

from rest.decorators import periodic
from rest import helpers

from auditlog.models import PersistentLog

from telephony.models import SMS
from django.core.mail import send_mail
from sessionlog.models import SessionLog

# run once an hour to clean up tokens
@periodic(minute=15)
def run_cleanup_tokens(force=False, verbose=False, now=None):
    # we want to nuke invite tokens every 5 minutes
    # we do not want to do this if using invite
    stale = datetime.now() - timedelta(minutes=5)
    qset = Member.objects.filter(invite_token__isnull=False).filter(modified__lte=stale)
    qset.update(invite_token=None)

# run once an hour to clean up tokens
@periodic(hour=[9, 10, 11, 12, 13])
def run_account_cleanup(force=False, verbose=False, now=None):
    # we want to nuke invite tokens every 5 minutes
    # we do not want to do this if using invite
    # lets prune old non active sessions
    SessionLog.Clean(limit=10000)

    admin = Member.objects.filter(username="admin").first()

    # lets log out anyone logged in for 30 days or more
    # SessionLog.LogOutExpired(30)
    # Logout Activity
    # days = getattr(settings, "LOGOUT_AFTER_DAYS", 0)
    # if days:
    #     stale = datetime.now() - timedelta(days=days)
    #     qset = Member.objects.filter(last_activity__lte=stale, is_active=True)
    #     for member in qset:
    #         member.logout()

    # disable for no activity
    # days = getattr(settings, "DISABLE_AFTER_DAYS", 90)
    # if days:
    #     stale = datetime.now() - timedelta(days=days)
    #     qset = Member.objects.filter(is_active=True, is_staff=False).filter(Q(last_activity__lte=stale, last_login__lte=stale)|Q(last_activity__isnull=True, last_login__isnull=True, date_joined__lte=stale))
    #     disabled = []
    #     for member in qset:
    #         member.disable(admin, "no activity", False)
    #         disabled.append("{}:{}<br>\n".format(member.username, member.full_name))
    #     if len(disabled):
    #         subject = "Users disabled for no activity (90 days)"
    #         body = "The following users have been disabled for no activity<br>\n{}".format("<br>\n".join(disabled))
    #         Member.notifyWithPermission("user_audit", subject, message=body, email_only=True)

def run_email_queue(force=False, verbose=False, now=None):
    outbox = NotificationRecord.objects.filter(state=-5, attempts__lte=3).order_by("-id")
    for msg in outbox:
        if not msg.send():
            print("unable to send")
            break



