import logging

_logger = logging.getLogger(__name__)


class Routing(object):
    def __init__(self):
        super(Routing, self).__init__()
        self._logger = type(self).__name__

    def routing(self, links, switches, routers):
        raise NotImplementedError()

    def register_router(self, router):
        raise NotImplementedError()

    def get_routing_data_by_dst_ip(self, dpid, dst_ip):
        raise NotImplementedError()

    def get_routing_data_by_gateway_mac(self, dpid, gateway_mac):
        raise NotImplementedError()

    def get_gateways(self, dpid):
        raise NotImplementedError()

    def update_mac(self, router, msg, headers):
        raise NotImplementedError()


class BaseRoute(object):
    def __init__(self, route_id, dst_ip, netmask, gateway_ip, src_mac,
                 gateway_mac, out_port):
        super(BaseRoute, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.src_mac = src_mac
        self.gateway_mac = gateway_mac
        self.out_port = out_port
