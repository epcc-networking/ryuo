import logging

from utils import ipv4_apply_mask, nw_addr_aton, ip_addr_aton, ip_addr_ntoa, \
    config_logger


class Routing(object):
    def __init__(self):
        super(Routing, self).__init__()
        self._logger = logging.getLogger(type(self).__name__)
        config_logger(self._logger)

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
                 gateway_mac, out_port, in_port=None):
        super(BaseRoute, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.src_mac = src_mac
        self.gateway_mac = gateway_mac
        self.out_port = out_port
        self.in_port = in_port


class BaseRoutingTable(dict):
    def __init__(self, logger):
        super(BaseRoutingTable, self).__init__()
        self.logger = logger
        self.route_id = 1

    def add(self, router, dst_ip, gateway_ip, src_mac, gateway_mac, out_port):
        dst, netmask, dummy = nw_addr_aton(dst_ip)
        gateway_ip = ip_addr_aton(gateway_ip)

        overlap_route = None
        if dst_ip in self:
            overlap_route = self[dst_ip].route_id

        if overlap_route is not None:
            self.logger.info('Destination overlaps route id: %d',
                             overlap_route)
            return

        routing_data = BaseRoute(self.route_id, dst, netmask, gateway_ip,
                                 src_mac, gateway_mac, out_port)
        ip_str = ip_addr_ntoa(dst)
        key = '%s/%d' % (ip_str, netmask)
        self[key] = routing_data
        self.route_id += 1

        router.install_routing_entry(routing_data)
        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]

    def get_gateways(self):
        return [routing_data.gateway_ip for routing_data in self.values()]

    def get_data_by_dst_ip(self, dst_ip):
        get_route = None
        mask = 0
        for route in self.values():
            if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                if mask < route.netmask:
                    get_route = route
                    mask = route.netmask
        return get_route

    def get_data_by_gateway_mac(self, gateway_mac):
        for route in self.values():
            if gateway_mac == route.gateway_mac:
                return route
        return None