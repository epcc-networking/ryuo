from ryuo.constants import ARP
from resilient_app import LINK_UP

from routing import Routing, BaseRoutingTable


class ShortestPathRouting(Routing):
    def __init__(self, app):
        super(ShortestPathRouting, self).__init__(app)
        self._routing_tables = {}
        self._switches = []
        self._links = []
        self._link_status = []

    def register_router(self, router):
        self._routing_tables[router.dp.id] = BaseRoutingTable(self._logger)

    def unregister_router(self, dpid):
        del self._routing_tables[dpid]
        # TODO: recalculate routing table

    def routing(self, links, switches, routers):
        for routing_table in self._routing_tables.values():
            routing_table.clear()
        dpids = [switch.ports[0].dpid for switch in switches]
        self._logger.info('Connected routers: %s', str(dpids))
        for switch in switches:
            dpid = switch.ports[0].dpid
            self._logger.info('Router %d', switch.ports[0].dpid)
            self._logger.info('Ports %s',
                              str([port.to_dict() for port in switch.ports]))
            for port in switch.ports:
                port_no = port.port_no
                router_port = routers[dpid].ports[port_no]
                if router_port.ip is None:
                    continue
                self._logger.info("ip %s, nw %s, mask %d", router_port.ip,
                                  router_port.nw, router_port.netmask)
        graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                 for src_dpid in dpids}
        via = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
               for src_dpid in dpids}
        tmp_graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                     for src_dpid in dpids}
        for dpid in dpids:
            tmp_graph[dpid][dpid] = 0
        for link in links:
            dst_dpid = link.dst.dpid
            src_dpid = link.src.dpid
            graph[src_dpid][dst_dpid] = link
            via[src_dpid][dst_dpid] = link
            tmp_graph[src_dpid][dst_dpid] = 1
        self._logger.info(str(graph))

        # Shortest path for each node
        for k in dpids:
            for src in dpids:
                for dst in dpids:
                    if src == dst:
                        continue
                    src_k = tmp_graph[src][k]
                    k_dst = tmp_graph[k][dst]
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
                                                  gateway_ip,
                                                  out_link.src.hw_addr,
                                                  out_link.dst.hw_addr,
                                                  out_link.src.port_no)
        return {src_dpid: {dst_dpid: via[src_dpid][dst_dpid].to_dict()
                           for dst_dpid in dpids
                           if via[src_dpid][dst_dpid] is not None}
                for src_dpid in dpids}

    def get_routing_data_by_dst_ip(self, dpid, dst_ip):
        return self._routing_tables[dpid].get_data_by_dst_ip(dst_ip)

    def get_routing_data_by_gateway_mac(self, dpid, gateway_mac):
        return self._routing_tables[dpid].get_data_by_gateway_mac(gateway_mac)

    def get_gateways(self, dpid):
        return [route.gateway_ip for route in
                self._routing_tables[dpid].values()]

    def update_mac(self, router, msg, headers):
        # Set flow: routing to gateway.
        out_port = router.ofctl.get_packetin_inport(msg)
        src_mac = headers[ARP].src_mac
        dst_mac = router.ports[out_port].mac
        src_ip = headers[ARP].src_ip

        gateway_flg = False
        for key, value in self._routing_tables[router.dp.id].items():
            if value.gateway_ip == src_ip:
                gateway_flg = True
                if value.gateway_mac == src_mac:
                    continue
                self._routing_tables[router.dp.id][key].gateway_mac = src_mac

                # cookie = self._id_to_cookie(REST_ROUTEID, value.route_id)
                # priority, log_msg = self._get_priority(PRIORITY_TYPE_ROUTE,
                # route=value)
                # self.ofctl.set_routing_flow(cookie, priority, out_port,
                # dl_vlan=self.vlan_id,
                # src_mac=dst_mac,
                # dst_mac=src_mac,
                # nw_dst=value.dst_ip,
                # dst_mask=value.netmask,
                # dec_ttl=True)
                # self.logger.info('Set %s flow [cookie=0x%x]', log_msg,
                # cookie,
                # extra=self.sw_id)
        return gateway_flg

    def on_port_status_change(self, msg, links, link_status, switches,
                              routers):
        new_links = []
        for idx, link in enumerate(links):
            if link_status[idx] == LINK_UP:
                new_links.append(link)
        self._logger.info('Rerouting...')
        self._logger.info(self.routing(new_links, switches, routers))
