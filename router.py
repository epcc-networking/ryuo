import logging
import json

from webob import Response

from ryu.base import app_manager

from ryu.app.wsgi import route
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication

from ryu.controller import dpset 
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER

from ryu.lib import dpid as dpid_lib
from ryu.lib import mac  as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3

from ryu.topology.api import get_all_switch
from ryu.topology.api import get_all_link

class RouterRestController(ControllerBase):
    _PORTNO_PATTERN = r'[0-9]{1,8}|all'
    _ROUTER_ID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

    def __init__(self, req, link, data, **config):
        super(RouterRestController, self).__init__(req, link, data, **config)
        self.router_app = data['router_app']

    @route('topo', '/topo/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        links = router_app.get_all_links()
        return JsonResponse([link.to_dict() for link in links])

    @route('topo', '/topo/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        switches = router_app.get_all_switches()
        return JsonResponse([switch.to_dict() for switch in switches])

    @route('route', '/router/{router_id}', methods=['GET'],
           requirements={'router_id': self._ROUTER_ID_PATTERN})
    def get_router(self, req, **kwargs):
        router = router_app.get_router(int(kwargs['router_id']))
        if router is None:
            return ErrorResponse(404, 'Router not found')
        return JsonResponse(router)

    @route('router', '/router/{router_id}/{port_no}', methods=['GET'],
           requirements={'router_id': self._ROUTER_ID_PATTERN,
                         'port_no': self._PORTNO_PATTERN})
    def get_port(self, req, **kwargs):
        return JsonResponse(router_app.get_port(int(kwargs['router_id']),
                                                int(kwargs['port_no']))) 

    @route('router', '/router/{router_id}/{port_no}/address',
           methods=['POST'],
           requirements={'router_id': self._ROUTER_ID_PATTERN,
                         'port_no': self._PORTNO_PATTERN})
    def set_port_address(self, req, **kwargs):
        address = kwargs.get('address') 
        if address is None:
            return ErrorResponse(400, 'Empty address.')
        return JsonResponse(address,
                            router_app.set_port(int(kwargs['router_id']),
                                                int(kwargs['port_no'])))

    @route('router', '/router/{router_id}/{port_no}/address',
           methods=['DELETE'],
           requirements={'router_id': self._ROUTER_ID_PATTERN,
                         'port_no': self._PORTNO_PATTERN})
    def delete_port_address(self, req, **kwargs):
        return JsonResponse(
            router_app.delete_port_address(
                int(kwargs['router_id']),
                int(kwargs['port_no'])))

    @route('router', '/router/routing', methods=['POST'])
    def routing(self, req, **kwargs):
        return JsonResponse(router_app.routing()) 

class RouterApp(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi':  WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RouterApp, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RouterRestController, {'router_app': self})

    def get_all_links(self):
        return get_all_link(self)

    def get_all_switches(self):
        return get_all_switch(self)

    def get_router(self, router_id):
        return None

    def get_port(self, router_id, port_no):
        return None

    def set_port_address(self, address, router_id, port_no):
        return None

    def del_port_address(self, router_id, port_no):
        return None 

    def routing(self):
        return None


def JsonResponse(obj, status=200):
    return Response(status=status, content_type='application/json',
                    body=json.dumps(obj))

def ErrorResponse(status, msg):
    return JsonResponse(msg, status=status) 
