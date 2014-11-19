from ryu.app.wsgi import WSGIApplication, ControllerBase
from ryu.app.wsgi import route as rest_route
from ryu.controller.handler import set_ev_cls

from ryuo.constants import ROUTER_ID_PATTERN, PORTNO_PATTERN
from ryuo.controller.central import Ryuo
from ryuo.topology.api import get_all_link
from ryuo.topology.event import EventSwitchEnter, EventSwitchLeave, \
    EventPortAdd, EventPortModify, EventPortDelete
from ryuo.utils import json_response, error_response, nw_addr_aton, \
    ipv4_apply_mask


APP_CONTEXT_KEY = 'app'
WSGI_CONTEXT_KEY = 'wsgi'


class KFRoutingApp(Ryuo):
    _CONTEXTS = {WSGI_CONTEXT_KEY: WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(KFRoutingApp, self).__init__(*args, **kwargs)
        wsgi = kwargs[WSGI_CONTEXT_KEY]
        wsgi.register(_RestController, {APP_CONTEXT_KEY: self})
        self.ports = {}  # dpid -> port_no -> port

    def get_all_links(self):
        return get_all_link(self)

    def set_port_address(self, address, router_id, port_no):
        nw, mask, ip = nw_addr_aton(address)
        # Check address overlap
        for port in self.ports[router_id].values():
            if port.ip is None:
                continue
            if (port.nw == ipv4_apply_mask(ip, port.netmask)
                or nw == ipv4_apply_mask(port.ip, mask)):
                self._logger.error('IP %s overlaps with %s/%d of %d.%d.',
                                   address,
                                   port.ip,
                                   port.netmask,
                                   port.port.dpid,
                                   port.port.port_no)
                return None
        self.ports[router_id][port_no].set_ip(ip, mask, nw)
        self.local_apps[router_id].set_port_address(port_no, ip, mask, nw)
        return {'dpid': router_id, 'port_no': port_no, 'ip': address}

    def routing(self):
        pass

    @set_ev_cls(EventSwitchEnter)
    def _switch_entered(self, event):
        switch = event.switch
        self._logger.info('Router %d up.', switch.dpid)
        self.ports[switch.dpid] = {port.port_no: _Port(port) for port in
                                   switch.ports.values()}

    @set_ev_cls(EventSwitchLeave)
    def _switch_left(self, event):
        self._logger.info('Router %d down.', event.switch.dpid)
        del self.ports[event.switch.dpid]

    @set_ev_cls(EventPortAdd)
    def _port_added(self, event):
        self._logger.info('Port %d.%d up.',
                          event.port.dpid,
                          event.port.port_no)
        self.ports[event.port.dpid][event.port.port_no] = _Port(event.port)

    @set_ev_cls(EventPortModify)
    def _port_modified(self, event):
        self._logger.info('Port %d.%d modified.',
                          event.port.dpid,
                          event.port.port_no)
        self.ports[event.port.dpid][event.port.port_no].update(event.port)

    @set_ev_cls(EventPortDelete)
    def _port_deleted(self, event):
        self._logger.info('Port %d.%d deleted.',
                          event.port.dpid,
                          event.port.port_no)
        del self.ports[event.port.dpid][event.port.port_no]


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


class _Port(object):
    def __init__(self, port):
        super(_Port, self).__init__()
        self.ip = None
        self.netmask = None
        self.nw = None
        self.port = port

    def set_ip(self, ip, netmask, nw):
        self.ip = ip
        self.netmask = netmask
        self.nw = nw

    def update(self, port):
        self.port = port
