from ryu.app.wsgi import WSGIApplication, ControllerBase
from ryu.app.wsgi import route as rest_route

from ryuo.constants import ROUTER_ID_PATTERN, PORTNO_PATTERN
from ryuo.controller.central import Ryuo
from ryuo.topology.api import get_all_link
from ryuo.utils import json_response, error_response


APP_CONTEXT_KEY = 'app'
WSGI_CONTEXT_KEY = 'wsgi'


class KFRoutingApp(Ryuo):
    _CONTEXTS = {WSGI_CONTEXT_KEY: WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(KFRoutingApp, self).__init__(*args, **kwargs)
        wsgi = kwargs[WSGI_CONTEXT_KEY]
        wsgi.register(_RestController, {APP_CONTEXT_KEY: self})

    def get_all_links(self):
        return get_all_link(self)

    def set_port_address(self, address, router_id, port_no):
        pass

    def routing(self):
        pass


class _RestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(_RestController, self).__init__(req, link, data, **config)
        self.app = data[APP_CONTEXT_KEY]

    @rest_route('topo', '/topo/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        links = self.app.get_all_links()
        return json_response([link.to_dict() for link in links])

    @rest_route('router', '/router/{router_id}/{port_no}/address',
                methods=['POST'],
                requirements={'router_id': ROUTER_ID_PATTERN,
                              'port_no': PORTNO_PATTERN})
    def set_port_address(self, req, router_id, port_no, **kwargs):
        address = eval(req.body).get('address')
        if address is None:
            return error_response(400, 'Empty address')
        return json_response(self.app.set_port_address(address,
                                                       int(router_id),
                                                       int(port_no)))

    @rest_route('router', '/router/routing', methods=['POST'])
    def routing(self, req, **kwargs):
        return json_response(self.app.routing())
