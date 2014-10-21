import logging

_logger = logging.getLogger(__name__)


class Routing(object):
    def __init__(self):
        super(Routing, self).__init__()

    def routing(self, links, switches, routers):
        raise NotImplementedError()

    def update_routing_table(self, links, switches, routers):
        raise NotImplementedError()


class BaseRoute(object):
    def __init__(self, route_id, dst_ip, net_mask, gateway_ip, src_mac,
                 gateway_mac, out_port):
        super(BaseRoute, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.net_mask = net_mask
        self.gateway_ip = gateway_ip
        self.src_mac = src_mac
        self.gateway_mac = gateway_mac
        self.out_port = out_port
