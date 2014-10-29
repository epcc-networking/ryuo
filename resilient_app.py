import logging

from ryu.base import app_manager
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch
from ryu.topology.api import get_all_link

from constants import LINK_UP, LINK_DOWN, PORT_UP
from kf_routing import KFRouting
from rest_controller import RestController
from router import Router
from utils import config_logger


class ResilientApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(ResilientApp, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(__name__)
        config_logger(self._logger)
        wsgi = kwargs['wsgi']
        wsgi.register(RestController, {'router_app': self})
        self._links = []
        self._switches = []
        self._link_status = []
        self._routing = KFRouting(self)

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
        self._links = self.get_all_links().keys()
        self._switches = self.get_all_switches()
        self._link_status = [LINK_UP] * len(self._links)

        # update links in ports
        for link in self._links:
            router = self.routers[link.src.dpid]
            router.ports[link.src.port_no].add_link(link)

        if self._links is None or self._switches is None:
            return
        return self._routing.routing(self._links, self._switches, self.routers)

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

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_change(self, ev):
        msg = ev.msg
        dp = msg.datapath
        self.routers[dp.id].on_port_status_change(msg)
        self._logger.info('Total links: %d', len(self._links))
        # In case the topo discovery module not update yet
        for idx, link in enumerate(self._links):
            src_port = self.routers[link.src.dpid].ports[link.src.port_no]
            dst_port = self.routers[link.dst.dpid].ports[link.dst.port_no]
            if src_port.status == PORT_UP and dst_port.status == PORT_UP:
                self._link_status[idx] = LINK_UP
            else:
                self._link_status[idx] = LINK_DOWN
        self._logger.info('Link status: %s.', self._link_status)
        self._routing.on_port_status_change(msg, self._links,
                                            self._link_status, self._switches,
                                            self.routers)

    def _register_router(self, dp):
        router = Router(dp, self._routing)
        self._routing.register_router(router)
        self.routers[dp.id] = router
        self._logger.info('Router %d comes up.', dp.id)

    def _unregister_router(self, dp):
        if dp.id in self.routers:
            self.routers[dp.id].delete()
            del self.routers[dp.id]
            self._routing.unregister_router(dp.id)
            self._logger.info('Router %d leaves.', dp.id)
