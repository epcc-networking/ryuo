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

from rest_controller import RestController
from router import Router
from shortest_path_routing import ShortestPathRouting
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
        self._routing = ShortestPathRouting()

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
        return self._routing.routing(links, switches, self.routers)

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
        router = Router(dp, self._routing)
        self._routing.register_router(router)
        self.routers[dp.id] = router
        self._logger.info('Router %d comes up.', dp.id)

    def _unregister_router(self, dp):
        if dp.id in self.routers:
            self.routers[dp.id].delete()
            del self.routers[dp.id]
            self._logger.info('Router %d leaves.', dp.id)
