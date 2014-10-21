import logging

from routing import Routing, BaseRoute
from utils import nw_addr_aton, ip_addr_aton, ip_addr_ntoa, ipv4_apply_mask


class ShortestPathRouting(Routing):
    def __init__(self):
        super(ShortestPathRouting, self).__init__()
        self._logger = logging.getLogger(__name__)
        self._routing_tables = {}

    def routing(self, links, switches, routers):
        dpids = [switch.ports[0].dpid for switch in switches]
        self._logger.info('Connected routers: %s', str(dpids))
        for router_id, router in routers.items():
            self._logger.info('Router %d', router_id)
            self._logger.info('Ports %s', str(router.ports.keys()))
            for port in router.ports.values():
                if port.ip is None:
                    continue
                self._logger.info("ip %s, nw %s, mask %d", port.ip, port.nw,
                                  port.netmask)
        self._routing_tables = {dpid: _RoutingTable(self._logger) for dpid in
                                dpids}
        graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                 for src_dpid in dpids}
        via = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
               for src_dpid in dpids}
        tmp_graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                     for src_dpid in dpids}
        for link in links:
            dst_dpid = link.dst.dpid
            src_dpid = link.src.dpid
            graph[src_dpid][dst_dpid] = link
            via[src_dpid][dst_dpid] = link
            tmp_graph[src_dpid][dst_dpid] = 1

        # Shortest path for each node
        for k in dpids:
            for src in dpids:
                for dst in dpids:
                    if src == dst:
                        continue
                    src_k = tmp_graph[src][k]
                    k_dst = tmp_graph[k][src]
                    src_dst = tmp_graph[src][dst]
                    if (src_k is not None and k_dst is not None and
                            (src_dst is None or src_dst > src_k + k_dst)):
                        tmp_graph[src][dst] = src_k + k_dst
                        if graph[src][k] is not None:
                            via[src][dst] = graph[src][k]
                        else:
                            via[src][dst] = via[src][k]

        # Routing entries
        for src in dpids:
            router = routers[src]
            for dst in dpids:
                if src == dst:
                    continue
                ports = routers[dst].ports
                out_link = via[src][dst]
                if out_link is None:
                    continue
                self._logger.info(out_link)
                for port in ports.values():
                    if port.ip is None:
                        continue
                    gateway_ip = (routers[out_link.dst.dpid]
                                  .ports[out_link.dst.port_no]
                                  .ip)
                    dst_str = '%s/%d' % (port.ip, port.netmask)
                    self._logger.info("%s via %s", port.ip, gateway_ip)
                    self._routing_tables[src].add(router,
                                                  dst_str,
                                                  out_link.src.hw_addr,
                                                  out_link.dst.hw_addr,
                                                  gateway_ip,
                                                  out_link.src.port_no,
                                                  router)


class _RoutingTable(dict):
    def __init__(self, logger):
        super(_RoutingTable, self).__init__()
        self.logger = logger
        self.route_id = 1

    def add(self, router, dst_ip, gateway_ip, src_mac, gateway_mac, out_port):
        dst, net_mask, dummy = nw_addr_aton(dst_ip)
        gateway_ip = ip_addr_aton(gateway_ip)

        overlap_route = None
        if dst_ip in self:
            overlap_route = self[dst_ip].route_id

        if overlap_route is not None:
            self.logger.info('Destination overlaps route id: %d',
                             overlap_route)
            return

        routing_data = BaseRoute(self.route_id, dst, net_mask, gateway_ip,
                                 src_mac, gateway_mac, out_port)
        ip_str = ip_addr_ntoa(dst)
        key = '%s/%d' % (ip_str, net_mask)
        self[key] = routing_data
        self.route_id += 1

        router.install_routing_entry(routing_data, src_mac, gateway_mac,
                                     out_port, in_port=None)
        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]

    def get_gateways(self):
        return [routing_data.gateway_ip for routing_data in self.values()]

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None
        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                    if mask < route.netmask:
                        get_route = route
                        mask = route.netmask
            return get_route

