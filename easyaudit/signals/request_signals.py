from io import BytesIO

from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.core.signals import request_started
from django.http.cookie import SimpleCookie
from django.utils import timezone
from django.conf import settings
from django.utils.module_loading import import_string

# try and get the user from the request; commented for now, may have a bug in this flow.
# from easyaudit.middleware.easyaudit import get_current_user
from easyaudit.settings import REMOTE_ADDR_HEADER, UNREGISTERED_URLS, REGISTERED_URLS, WATCH_REQUEST_EVENTS, \
    LOGGING_BACKEND

import re

audit_logger = import_string(LOGGING_BACKEND)()
LIMIT_TO = 1 * 1024 * 1024  # limit to 1Mb of post data in log


def should_log_url(url):
    # check if current url is blacklisted
    for unregistered_url in UNREGISTERED_URLS:
        pattern = re.compile(unregistered_url)
        if pattern.match(url):
            return False

    # only audit URLs listed in REGISTERED_URLS (if it's set)
    if len(REGISTERED_URLS) > 0:
        for registered_url in REGISTERED_URLS:
            pattern = re.compile(registered_url)
            if pattern.match(url):
                return True
        return False

    # all good    
    return True


def request_started_handler(sender, environ, **kwargs):
    if not should_log_url(environ['PATH_INFO']):
        return

    # try and get the user from the request; commented for now, may have a bug in this flow.
    # user = get_current_user()
    user = None
    # get the user from cookies
    if not user and environ.get('HTTP_COOKIE'):
        cookie = SimpleCookie() # python3 compatibility
        cookie.load(environ['HTTP_COOKIE'])

        session_cookie_name = settings.SESSION_COOKIE_NAME
        if session_cookie_name in cookie:
            session_id = cookie[session_cookie_name].value

            try:
                session = Session.objects.get(session_key=session_id)
            except Session.DoesNotExist:
                session = None

            if session:
                user_id = session.get_decoded().get('_auth_user_id')
                try:
                    user = get_user_model().objects.get(id=user_id)
                except:
                    user = None

    if environ.get("wsgi.input"):
        data = environ.get("wsgi.input").read()
        environ["wsgi.input"] = BytesIO(data)

        data = str(data)
        if len(data) > LIMIT_TO:
            data = data[:LIMIT_TO] + ' ...'
        # To not save passwords in plain in the database/log
        if '&password' in data and '&username=' in data:
            data = 'Not saved for privacy protection'
        if '&old_password=' in data and '&new_password1=' in data:
            data = 'Not saved for privacy protection'

    audit_logger.request({
        'url': environ['PATH_INFO'],
        'method': environ['REQUEST_METHOD'],
        'query_string': f"{environ['QUERY_STRING']} POST DATA: {data}",
        'user_id': getattr(user, 'id', None),
        'remote_ip': environ[REMOTE_ADDR_HEADER],
        'datetime': timezone.now()
    })


if WATCH_REQUEST_EVENTS:
    request_started.connect(request_started_handler, dispatch_uid='easy_audit_signals_request_started')
