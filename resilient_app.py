from ryu.base import app_manager
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch
from ryu.topology.api import get_all_link

from rest_controller import RestController
from router import Router


class ResilientApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ResilientApp, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, {'router_app': self})

        self.routers = {}

    def get_all_links(self):
        return get_all_link(self)

    def get_all_switches(self):
        return get_all_switch(self)

    def get_router(self, router_id):
        return self.routers[router_id]

    def get_port(self, router_id, port_no):
        return None

    def set_port_address(self, address, router_id, port_no):
        router = self.get_router(router_id)
        return router.set_port_address(address, port_no)

    def del_port_address(self, router_id, port_no):
        return None

    def routing(self):
        links = self.get_all_links()
        switches = self.get_all_switches()

        if links is None or switches is None:
            return
        dpids = [switch.ports[0].dpid for switch in switches]
        self.logger.info(str(dpids))
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

        self.logger.info(str(graph))
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
        for router_id, router in self.routers.items():
            self.logger.info('Router %d', router_id)
            self.logger.info('Ports %s', str(router.ports.keys()))
            for port in router.ports.values():
                if port.ip is None:
                    continue
                self.logger.info("ip %s, nw %s, mask %d", port.ip, port.nw,
                                 port.netmask)
        # Routing entries
        for src in dpids:
            router = self.get_router(src)
            for dst in dpids:
                if src == dst:
                    continue
                ports = self.get_router(dst).ports
                out_link = via[src][dst]
                if out_link is None:
                    continue
                self.logger.info(out_link)
                for port in ports.values():
                    if port.ip is None:
                        continue
                    addr = port.nw
                    gateway_ip = (self.get_router(out_link.dst.dpid)
                                  .ports[out_link.dst.port_no]
                                  .ip)
                    dst_str = '%s/%d' % (port.ip, port.netmask)
                    self.logger.info("%s via %s", port.ip, gateway_ip)
                    router.set_routing_data(dst_str,
                                            out_link.src.hw_addr,
                                            out_link.dst.hw_addr,
                                            gateway_ip,
                                            out_link.src.port_no)
        return {src_dpid: {dst_dpid: via[src_dpid][dst_dpid].to_dict()
                           for dst_dpid in dpids
                           if via[src_dpid][dst_dpid] is not None}
                for src_dpid in dpids}

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            self._register_router(ev.dp)
        else:
            self._unregister_router(ev.dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        dpid = ev.msg.datapath.id
        if dpid in self.routers:
            self.routers[dpid].packet_in(ev.msg)

    def _register_router(self, dp):
        router = Router(dp, self.logger)
        self.routers[dp.id] = router
        self.logger.info('Router %d comes up.', dp.id)

    def _unregister_router(self, dp):
        if dp.id in self.routers:
            self.routers[dp.id].delete()
            del self.routers[dp.id]
            self.logger.info('Router %d leaves.', dp.id)
