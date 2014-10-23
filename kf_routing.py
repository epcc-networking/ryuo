from Queue import Queue

from routing import Routing, BaseRoutingTable, BaseRoute
from utils import nw_addr_aton, ip_addr_aton, ip_addr_ntoa


class KFRouting(Routing):
    def __init__(self):
        super(KFRouting, self).__init__()
        self._routing_tables = {}

    def register_router(self, router):
        self._routing_tables[router.dp.id] = _RoutingTable(self._logger)

    def unregister_router(self, dpid):
        del self._routing_tables[dpid]

    def routing(self, links, switches, routers):
        dpids = [switch.ports[0].dpid for switch in switches]
        graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                 for src_dpid in dpids}
        degree = {src: 0 for src in dpids}
        for link in links:
            dst = link.dst.dpid
            src = link.src.dpid
            graph[src][dst] = link
            degree[src] += 1

        for dst in dpids:
            level = {dpid: None for dpid in dpids}
            bfs_q = Queue()
            bfs_q.put(dst)
            level[dst] = 0
            dst_ips = ['%s/%d' % (port.ip, port.netmask) for port in
                       routers.get(dst).ports.values() if port.ip is not None]
            visited = {src: False for src in dpids}
            # build PSNs for each destination
            while not bfs_q.empty():
                node = bfs_q.get()
                visited[node] = True
                for link in links:
                    if link.dst.dpid == node \
                            and visited[link.src.dpid] is False:
                        level[link.src.dpid] = level[node] + 1
                        bfs_q.put(link.src.dpid)
            self._logger.info('Level for dst=%d: %s', dst, str(level))
            # Get routing table
            for src in dpids:
                if src == dst:
                    continue
                self._logger.info('On router %d: ', src)
                router = routers.get(src)
                ports = [port.port_no for port in
                         routers.get(src).ports.values() if
                         port.ip is not None]
                candidates = [link for link in links if link.src.dpid == src]
                for in_port in ports:
                    sorted_candidates = sorted(candidates,
                                               cmp=lambda x, y:
                                               KFRouting._compare_link(x, y,
                                                                       level,
                                                                       degree,
                                                                       in_port)
                    )
                    sorted_ports = [link.src.port_no for link in
                                    sorted_candidates]
                    src_macs = [link.src.hw_addr for link in sorted_candidates]
                    dst_macs = [link.dst.hw_addr for link in sorted_candidates]
                    group_id = router.set_group(sorted_ports, src_macs,
                                                dst_macs)
                    for dst_str in dst_ips:
                        self._logger.info(
                            '%s from port %d to ports %s group_id %d',
                            dst_str, in_port, str(sorted_ports), group_id
                        )
                        self._routing_tables[src].add(router,
                                                      dst_str,
                                                      None,
                                                      None,
                                                      None,
                                                      None,
                                                      in_port,
                                                      group_id)
        return ''

    @staticmethod
    def _compare_link(l1, l2, level, degree, in_port):
        if l1.src.port_no == in_port:
            return 1
        if l2.src.port_no == in_port:
            return -1
        level_diff = level[l1.dst.dpid] - level[l2.dst.dpid]
        if level_diff != 0:
            return level_diff
        return degree[l2.dst.dpid] - degree[l1.dst.dpid]

    def get_routing_data_by_dst_ip(self, dpid, dst_ip):
        return None

    def get_routing_data_by_gateway_mac(self, dpid, gateway_mac):
        return None

    def get_gateways(self, dpid):
        return []

    def update_mac(self, router, msg, headers):
        return False


class _RoutingTable(BaseRoutingTable):
    def __init__(self, logger):
        super(_RoutingTable, self).__init__(logger)

    def add(self, router, dst_ip, gateway_ip, src_mac, gateway_mac, out_port,
            in_port=None, out_group=None):
        assert in_port is not None
        dst, netmask, dummy = nw_addr_aton(dst_ip)
        if gateway_ip is not None:
            gateway_ip = ip_addr_aton(gateway_ip)
        ip_str = ip_addr_ntoa(dst)
        key = _RoutingTable._get_route_key(ip_str, netmask, in_port)
        overlap_route = None
        if key in self:
            overlap_route = self[key].route_id

        if overlap_route is not None:
            self._logger.info('Destination overlaps route id: %d',
                              overlap_route)
            return

        routing_data = BaseRoute(self.route_id, dst, netmask, gateway_ip,
                                 src_mac, gateway_mac, out_port,
                                 in_port=in_port, out_group=out_group)
        self[key] = routing_data
        self.route_id += 1

        router.install_routing_entry(routing_data)

    @staticmethod
    def _get_route_key(ip_str, netmask, in_port):
        return '%s/%d@%d' % (ip_str, netmask, in_port)

    def get_gateways(self):
        return set([routing_data.gateway_ip for routing_data in self.values()])







