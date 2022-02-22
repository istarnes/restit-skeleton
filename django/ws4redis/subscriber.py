# -*- coding: utf-8 -*-
from django.conf import settings
from ws4redis.redis_store import RedisStore, SELF

from rest.log import getLogger
logger = getLogger("async", filename="async.log")


class RedisSubscriber(RedisStore):
    """
    Subscriber class, used by the websocket code to listen for subscribed channels
    """
    subscription_channels = ['subscribe-session', 'subscribe-group', 'subscribe-user', 'subscribe-broadcast']
    publish_channels = ['publish-session', 'publish-group', 'publish-user', 'publish-broadcast']

    def __init__(self, connection):
        self._subscription = None
        self.user_id = None
        super(RedisSubscriber, self).__init__(connection)

    def parse_response(self):
        """
        Parse a message response sent by the Redis datastore on a subscribed channel.
        """
        return self._subscription.parse_response()

    def set_pubsub_channels(self, request, channels):
        """
        Initialize the channels used for publishing and subscribing messages through the message queue.
        """
        facility = request.path_info.replace(settings.WEBSOCKET_URL, '', 1)

        # initialize publishers
        audience = {
            'users': 'publish-user' in channels and [SELF] or [],
            'groups': 'publish-group' in channels and [SELF] or [],
            'sessions': 'publish-session' in channels and [SELF] or [],
            'broadcast': 'publish-broadcast' in channels,
        }
        self._publishers = set()
        for key in self._get_message_channels(request=request, facility=facility, **audience):
            self._publishers.add(key)

        groups = SELF

        # initialize subscribers
        audience = {
            'users': 'subscribe-user' in channels and [SELF] or [],
            'groups': 'subscribe-group' in channels and [groups] or [],
            'sessions': 'subscribe-session' in channels and [SELF] or [],
            'broadcast': 'subscribe-broadcast' in channels,
        }
        # print "audience"
        # print audience
        self._subscription = self._connection.pubsub()
        for key in self._get_message_channels(request=request, facility=facility, **audience):
            self._subscription.subscribe(key)
        # print "subscribtions"
        # print self._subscription

        if request.user and request.user.is_authenticated:
            self.user_id = request.user.id
            count = self._connection.hincrby("users:online:connections", self.user_id, 1)
            if count == 1:
                self._connection.sadd("users:online", self.user_id)
        elif not request.user:
            logger.info("NO USER OBJECT")


    def send_persited_messages(self, websocket):
        """
        This method is called immediately after a websocket is openend by the client, so that
        persisted messages can be sent back to the client upon connection.
        """
        # in the future we should return priority messages???
        # but for now we do not want to return any events, we assumethe client
        # is going to get in sync at its start
        # for channel in self._subscription.channels:
        #     message = self._connection.get(channel)
        #     if message:
        #         websocket.send(message)
        return

    def get_file_descriptor(self):
        """
        Returns the file descriptor used for passing to the select call when listening
        on the message queue.
        """
        return self._subscription.connection and self._subscription.connection._sock.fileno()


    def release(self):
        """
        New implementation to free up Redis subscriptions when websockets close. This prevents
        memory sap when Redis Output Buffer and Output Lists build when websockets are abandoned.
        """
        if self.user_id:
            count = self._connection.hincrby("users:online:connections", self.user_id, -1)
            if count == 0:
                self._connection.srem("users:online", self.user_id)

        if self._subscription and self._subscription.subscribed:
            self._subscription.unsubscribe()
            self._subscription.reset()
