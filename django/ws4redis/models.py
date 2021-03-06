# -*- coding: utf-8 -*-
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver


@receiver(user_logged_in)
def store_groups_in_session(sender, user, request, **kwargs):
    """
    When a user logs in, fetch its groups and store them in the users session.
    This is required by ws4redis, since fetching groups accesses the database, which is a blocking
    operation and thus not allowed from within the websocket loop.
    """
    request.session['ws4redis:memberof'] = user.getGroupUUIDs()
