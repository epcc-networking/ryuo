import os

from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.base import app_manager
from webob.static import DirectoryApp

from ryuo.controller.central import Ryuo


class GUIServerApp(Ryuo):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(GUIServerApp, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(GUIServerController)


class GUIServerController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(GUIServerController, self).__init__(req, link, data, **config)
        path = '%s/html/' % os.path.dirname(__file__)
        self.static_app = DirectoryApp(path)

    @route('topology', '/html/{filename:.*}')
    def static_handler(self, req, **kwargs):
        if kwargs['filename']:
            req.path_info = kwargs['filename']
        return self.static_app(req)


app_manager.require_app('ryuo.topology.rest_topology')
app_manager.require_app('ryuo.topology.ws_topology')