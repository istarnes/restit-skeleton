# -*- coding: utf-8 -*-
import sys
import six
from six.moves import http_client
from redis import StrictRedis
import django
if django.VERSION[:2] >= (1, 7):
    django.setup()
from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
import logging
from rest import UberDict
# logger = logging.getLogger('django.request')
from rest.log import getLogger
logger = getLogger("async", filename="async.log")

from http.client import  responses
from django.core.exceptions import PermissionDenied
from django import http
from django.utils.encoding import force_str
from importlib import import_module
from django.utils.functional import SimpleLazyObject
from ws4redis import settings as private_settings
from ws4redis.redis_store import RedisMessage
from ws4redis.exceptions import WebSocketError, HandshakeError, UpgradeRequiredError, SSLRequiredError
import time

class WebsocketWSGIServer(object):
    def __init__(self, redis_connection=None):
        """
        redis_connection can be overriden by a mock object.
        """
        comps = str(private_settings.WS4REDIS_SUBSCRIBER).split('.')
        module = import_module('.'.join(comps[:-1]))
        Subscriber = getattr(module, comps[-1])
        self.possible_channels = Subscriber.subscription_channels + Subscriber.publish_channels
        self._redis_connection = redis_connection and redis_connection or StrictRedis(**private_settings.WS4REDIS_CONNECTION)
        self.Subscriber = Subscriber
        self._redis_connection.delete("users:online:connections")
        self._redis_connection.delete("users:online")
        self._websockets = set()  # a list of currently active websockets

    def assure_protocol_requirements(self, environ):
        if environ.get('REQUEST_METHOD') != 'GET':
            raise HandshakeError('HTTP method must be a GET')

        if environ.get('SERVER_PROTOCOL') != 'HTTP/1.1':
            raise HandshakeError('HTTP server protocol must be 1.1')

        if environ.get('HTTP_UPGRADE', '').lower() != 'websocket':
            raise HandshakeError('Client does not wish to upgrade to a websocket')

    def process_request(self, request):
        request.session = None
        request.user = None

        has_sessions = False
        for mware in settings.MIDDLEWARE:
            if "SessionMiddleware" in mware:
                has_sessions = True
                break

        if has_sessions:
            engine = import_module(settings.SESSION_ENGINE)
            session_key = request.DATA.get('session_key', None)
            # logger.info("session key request: {}".format(session_key))
            if not session_key:
                session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME, None)
                # logger.info("session key cookie: {}".format(session_key))

            if session_key:
                request.session = engine.SessionStore(session_key)
                if 'django.contrib.auth.middleware.AuthenticationMiddleware' in settings.MIDDLEWARE:
                    from django.contrib.auth import get_user
                    request.user = SimpleLazyObject(lambda: get_user(request))
                    # logger.info("getting user: {}".format(request.user != None))
                else:
                    logger.info("websocket no auth middleware")

    def process_subscriptions(self, request):
        agreed_channels = []
        echo_message = False
        for qp in request.GET:
            param = qp.strip().lower()
            if param in self.possible_channels:
                agreed_channels.append(param)
            elif param == 'echo':
                echo_message = True
        return agreed_channels, echo_message

    @property
    def websockets(self):
        return self._websockets

    def __call__(self, environ, start_response):
        """ Hijack the main loop from the original thread and listen on events on Redis and Websockets"""
        websocket = None
        subscriber = self.Subscriber(self._redis_connection)
        try:
            self.assure_protocol_requirements(environ)
            request = WSGIRequest(environ)
            self.process_request(request)
            channels, echo_message = self.process_subscriptions(request)
            if callable(private_settings.WS4REDIS_ALLOWED_CHANNELS):
                channels = list(private_settings.WS4REDIS_ALLOWED_CHANNELS(request, channels))
            websocket = self.upgrade_websocket(environ, start_response)
            # logger.info('Subscribed to channels: {0}'.format(', '.join(channels)))
            subscriber.set_pubsub_channels(request, channels)
            websocket_fd = websocket.get_file_descriptor()
            listening_fds = [websocket_fd]
            redis_fd = subscriber.get_file_descriptor()
            if redis_fd:
                # logger.info("ws listening for redis")
                listening_fds.append(redis_fd)
            subscriber.send_persited_messages(websocket)
            recvmsg = None
            last_beat = time.time()
            while websocket and not websocket.closed:
                ready = self.select(listening_fds, [], [], 4.0)[0]
                if not ready:
                    # flush empty socket
                    websocket.flush()
                for fd in ready:
                    if fd == redis_fd:
                        # logger.info("redis incoming")
                        sub_resp = subscriber.parse_response()
                        # logger.info(sub_resp)
                        sendmsg = RedisMessage(sub_resp)
                        if sendmsg and (echo_message or sendmsg != recvmsg):
                            # logger.info("pushing to websocket", sendmsg)
                            websocket.send(sendmsg)
                        # else:
                        #     logger.info("ignoring redis event")
                    elif fd == websocket_fd:
                        # logger.info("websocket incoming")
                        try:
                            recvmsg = websocket.receive()
                        except:
                            logger.info("unable to recv on ws... flushing")
                            websocket.flush()
                        if bool(recvmsg):
                            # logger.info("received msg: {}".format(recvmsg))
                            try:
                                dmsg = UberDict.fromJSON(recvmsg)
                            except Exception as err:
                                logger.exception(err)
                            recvmsg = RedisMessage(recvmsg)
                            if bool(recvmsg):
                                # logger.info("pushing to subscribers")
                                subscriber.publish_message()
                    else:
                        logger.error('Invalid file descriptor: {0}'.format(fd))
                # Check again that the websocket is not closed before sending the heartbeat,
                # because the websocket can closed previously in the loop.
                beat_delta = time.time() - last_beat
                if beat_delta > 30.0:
                    last_beat = time.time()
                    if private_settings.WS4REDIS_HEARTBEAT and not websocket.closed:
                        # logger.info("send heartbeat")
                        websocket.send(private_settings.WS4REDIS_HEARTBEAT)
        except WebSocketError as excpt:
            logger.warning('WebSocketError: {}'.format(excpt), exc_info=sys.exc_info())
            response = http.HttpResponse(status=1001, content='Websocket Closed')
        except UpgradeRequiredError as excpt:
            logger.info('Websocket upgrade required')
            response = http.HttpResponseBadRequest(status=426, content=excpt)
        except HandshakeError as excpt:
            logger.warning('HandshakeError: {}'.format(excpt), exc_info=sys.exc_info())
            response = http.HttpResponseBadRequest(content=excpt)
        except PermissionDenied as excpt:
            logger.warning('PermissionDenied')
            logger.warning('PermissionDenied: {}'.format(excpt), exc_info=sys.exc_info())
            response = http.HttpResponseForbidden(content=excpt)
        except SSLRequiredError as excpt:
            logger.warning('SSLRequiredError')
            response = http.HttpResponseServerError(content=excpt)
        except Exception as excpt:
            logger.error('Other Exception: {}'.format(excpt), exc_info=sys.exc_info())
            response = http.HttpResponseServerError(content=excpt)
        else:
            response = http.HttpResponse()
        finally:
            subscriber.release()
            if websocket:
                websocket.close(code=1001, message='Websocket Closed')
            else:
                logger.warning('Starting late response on websocket')
                status_text = http_client.responses.get(response.status_code, 'UNKNOWN STATUS CODE')
                status = '{0} {1}'.format(response.status_code, status_text)
                headers = list(response._headers.values())
                # if six.PY3:
                #     headers = list(headers)
                start_response(force_str(status), headers)
                logger.info('Finish non-websocket response with status code: {}'.format(response.status_code))
        return response

