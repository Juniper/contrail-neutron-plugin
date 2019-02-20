import logging

from eventlet import corolocal
from eventlet.greenthread import getcurrent

"""
This middleware is used to forward user token to Contrail API server.
Middleware is inserted at head of Neutron pipeline via api-paste.ini file
so that user token can be preserved in local storage of Neutron thread.
This is needed because neutron will later remove the user token before control
finally reaches Contrail plugin. Contrail plugin will retreive the user token
from thread's local storage and pass it to API server via X-AUTH-TOKEN header.
"""


class UserToken(object):
    def __init__(self, app, conf):
        self._logger = logging.getLogger(__name__)
        self._app = app
        self._conf = conf

    def __call__(self, env, start_response):
        # preserve user token for later forwarding to contrail API server
        cur_greenlet = getcurrent()
        cur_greenlet.contrail_vars = corolocal.local()
        cur_greenlet.contrail_vars.token = env.get('HTTP_X_AUTH_TOKEN')
        return self._app(env, start_response)


def token_factory(global_conf, **local_conf):
    """Paste factory."""

    conf = global_conf.copy()
    conf.update(local_conf)

    def _factory(app):
        return UserToken(app, conf)
    return _factory
