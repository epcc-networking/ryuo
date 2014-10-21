import json

from ryu.app.wsgi import ControllerBase
from webob import Response
from ryu.app.wsgi import route as rest_route

from constants import ROUTER_ID_PATTERN, PORTNO_PATTERN


class RestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RestController, self).__init__(req, link, data, **config)
        self.router_app = data['router_app']

    @rest_route('topo', '/topo/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        links = self.router_app.get_all_links()
        return json_response([link.to_dict() for link in links])

    @rest_route('topo', '/topo/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        switches = self.router_app.get_all_switches()
        return json_response([switch.to_dict() for switch in switches])

    @rest_route('route', '/router/{router_id}', methods=['GET'],
                requirements={'router_id': ROUTER_ID_PATTERN})
    def get_router(self, req, **kwargs):
        router = self.router_app.get_router(int(kwargs['router_id']))
        if router is None:
            return error_response(404, 'Router not found')
        return json_response(router)

    @rest_route('router', '/router/{router_id}/{port_no}', methods=['GET'],
                requirements={'router_id': ROUTER_ID_PATTERN,
                              'port_no': PORTNO_PATTERN})
    def get_port(self, req, **kwargs):
        return json_response(self.router_app.get_port(int(kwargs['router_id']),
                                                      int(kwargs['port_no'])))

    @rest_route('router', '/router/{router_id}/{port_no}/address',
                methods=['POST'],
                requirements={'router_id': ROUTER_ID_PATTERN,
                              'port_no': PORTNO_PATTERN})
    def set_port_address(self, req, router_id, port_no, **kwargs):
        address = eval(req.body).get('address')
        self.router_app.logger.info("%s %s %s", router_id, port_no, address)
        if address is None:
            return error_response(400, 'Empty address.')
        return json_response(self.router_app.set_port_address(address,
                                                              int(router_id),
                                                              int(port_no)))

    @rest_route('router', '/router/{router_id}/{port_no}/address',
                methods=['DELETE'],
                requirements={'router_id': ROUTER_ID_PATTERN,
                              'port_no': PORTNO_PATTERN})
    def delete_port_address(self, req, **kwargs):
        return json_response(
            self.router_app.delete_port_address(
                int(kwargs['router_id']),
                int(kwargs['port_no'])))

    @rest_route('router', '/router/routing', methods=['POST'])
    def routing(self, req, **kwargs):
        return json_response(self.router_app.routing())


def json_response(obj, status=200):
    return Response(status=status, content_type='application/json',
                    body=json.dumps(obj))


def error_response(status, msg):
    return json_response(msg, status=status)
