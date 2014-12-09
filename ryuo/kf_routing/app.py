from Queue import Queue

from ryu.app.wsgi import WSGIApplication, ControllerBase
from ryu.app.wsgi import route as rest_route
from ryu.controller.handler import set_ev_cls

from ryuo.constants import ROUTER_ID_PATTERN, PORTNO_PATTERN
from ryuo.controller.central import Ryuo
from ryuo.kf_routing.event import EventAddressRemove, Address
from ryuo.kf_routing.event import EventAddressAdd
from ryuo.topology.api import get_all_link
from ryuo.topology.event import EventSwitchEnter, EventSwitchLeave, \
    EventPortAdd, EventPortModify, EventPortDelete
from ryuo.utils import json_response, error_response, nw_addr_aton, \
    ipv4_apply_mask


APP_CONTEXT_KEY = 'app'
WSGI_CONTEXT_KEY = 'wsgi'


class KFRoutingApp(Ryuo):
    _CONTEXTS = {WSGI_CONTEXT_KEY: WSGIApplication}

    _EVENTS = {EventAddressAdd, EventAddressRemove}

    def __init__(self, *args, **kwargs):
        super(KFRoutingApp, self).__init__(*args, **kwargs)
        wsgi = kwargs[WSGI_CONTEXT_KEY]
        wsgi.register(_RestController, {APP_CONTEXT_KEY: self})
        self.ports = {}  # dpid -> port_no -> port
        self.address_cache = {}  # dpid -> port_no -> ip

    def get_all_links(self):
        return get_all_link(self)

    def get_router(self, router_id):
        return {port_no: self.ports[router_id][port_no].to_dict() for port_no
                in
                self.ports[router_id]}

    def set_port_address_lazy(self, address, router_id, port_no):
        if router_id not in self.address_cache:
            self.address_cache[router_id] = {}
        if port_no not in self.address_cache[router_id]:
            self.address_cache[router_id][port_no] = {}
        self.address_cache[router_id][port_no] = address

    def flush_address_cache(self):
        for router_id in self.address_cache:
            ips = {}
            for port_no in self.address_cache[router_id]:
                nw, mask, ip = self.do_set_port_address(
                    self.address_cache[router_id][port_no],
                    router_id,
                    port_no)
                ips[port_no] = [nw, mask, ip]
            self.local_apps[router_id].batch_set_port_address(ips)
            for port_no in ips:
                self.send_event_to_observers(EventAddressAdd(Address(
                    router_id, port_no, ips[port_no][2], ips[port_no][1])))
        self.address_cache = {}

    def do_set_port_address(self, address, router_id, port_no):
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

        self._logger.info('Setting address of %d.%d', router_id, port_no)
        self.ports[router_id][port_no].set_ip(ip, mask, nw)
        return nw, mask, ip

    def routing(self):
        if len(self.address_cache) != 0:
            self.flush_address_cache()
        links = self.get_all_links()
        self._logger.debug([link.to_dict() for link in links])
        dpids = self.ports.keys()
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
                       self.ports[dst].values() if port.ip is not None]
            # build PSNs for each destination
            while not bfs_q.empty():
                node = bfs_q.get()
                for link in links:
                    if link.dst.dpid == node \
                            and level[link.src.dpid] is None:
                        level[link.src.dpid] = level[node] + 1
                        bfs_q.put(link.src.dpid)
            self._logger.debug('Level for dst=%d: %s', dst, str(level))
            # Get routing table
            for src in dpids:
                if src == dst:
                    continue
                self._logger.debug('On router %d: ', src)
                router = self.local_apps[src]
                ports = [port.port_no for port in
                         self.ports[src].values() if
                         port.ip is not None]
                candidates = [link for link in links if link.src.dpid == src]
                candidate_true_sinks = {
                    candidate: self._find_true_sink(candidate, graph, degree,
                                                    dst) for candidate in
                    candidates}
                for in_port in ports:
                    in_port_link = [link for link in candidates if
                                    link.src.port_no == in_port]
                    if len(in_port_link) == 0:
                        in_port_true_sink = src
                    else:
                        in_port_link = in_port_link[0]
                        in_port_true_sink = self._find_true_sink(in_port_link,
                                                                 graph, degree,
                                                                 dst)
                    sorted_candidates = sorted(candidates,
                                               cmp=lambda x, y:
                                               self.compare_link(
                                                   x, y,
                                                   level,
                                                   degree,
                                                   in_port,
                                                   candidate_true_sinks,
                                                   in_port_true_sink))
                    # remove ports with the same true sink as the in_port.
                    self._logger.debug('For in port %s, candidates: %s',
                                       in_port,
                                       str([link.to_dict() for link in
                                            sorted_candidates]))

                    sorted_ports = [link.src.port_no for link in
                                    sorted_candidates]
                    output_ports = list(sorted_ports)
                    group_id = router.add_group(in_port, output_ports)
                    router.add_routes(dst_ips, group_id)
                    self._logger.info('%s from port %d to ports %s',
                                      dst_ips, in_port, group_id)
        return {router: self.get_router(router) for router in self.ports}

    @set_ev_cls(EventSwitchEnter)
    def _switch_entered(self, event):
        switch = event.switch
        self._logger.info('Router %d up.', switch.dpid)
        self.ports[switch.dpid] = {port.port_no: _Port(port) for port in
                                   switch.ports.values()}

    @set_ev_cls(EventSwitchLeave)
    def _switch_left(self, event):
        self._logger.info('Router %d down.', event.switch.dpid)
        self.address_cache = {}
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

    # Find the true sink of each out link
    def _find_true_sink(self, link, graph, degree, ultimate_dst):
        dst_dpid = link.dst.dpid
        src_dpid = link.src.dpid
        while degree[dst_dpid] <= 2 and dst_dpid != ultimate_dst:
            self._logger.debug('src: %d, dst: %d, degree: %d, udst: %d',
                               src_dpid,
                               dst_dpid, degree[dst_dpid], ultimate_dst)
            updated = False
            for olink in graph[dst_dpid].values():
                if olink is not None and olink.dst.dpid != src_dpid:
                    src_dpid = dst_dpid
                    dst_dpid = olink.dst.dpid
                    updated = True
                    break
            if not updated:
                break
        self._logger.debug('True sink: %d', dst_dpid)
        return dst_dpid

    @staticmethod
    def get_level(link, level):
        return level[link.src.dpid] - level[link.dst.dpid]

    @staticmethod
    def compare_link(l1, l2, level, degree, in_port, candidate_sinks,
                     in_port_sink):
        if l1.src.port_no == in_port:
            return 1
        if l2.src.port_no == in_port:
            return -1
        level_diff = level[l1.dst.dpid] - level[l2.dst.dpid]
        if level_diff != 0:
            return level_diff
        if candidate_sinks[l2] == in_port_sink:
            return -1
        if candidate_sinks[l1] == in_port_sink:
            return 1
        return degree[l2.dst.dpid] - degree[l1.dst.dpid]


class _RestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(_RestController, self).__init__(req, link, data, **config)
        self.app = data[APP_CONTEXT_KEY]

    @rest_route('router', '/router/{router_id}/{port_no}/address',
                methods=['POST'],
                requirements={'router_id': ROUTER_ID_PATTERN,
                              'port_no': PORTNO_PATTERN})
    def set_port_address(self, req, router_id, port_no, **kwargs):
        address = eval(req.body).get('address')
        if address is None:
            return error_response(400, 'Empty address')
        self.app.set_port_address_lazy(address, int(router_id, 16),
                                       int(port_no))
        return json_response({'success': True})

    @rest_route('router', '/router/{router_id}',
                methods=['GET'],
                requirements={'router_id': ROUTER_ID_PATTERN})
    def get_router(self, req, router_id, **kwargs):
        return json_response(self.app.get_router(int(router_id, 16)))

    @rest_route('router', '/router/routing', methods=['POST'])
    def routing(self, req, **kwargs):
        return json_response(self.app.routing())


class _Port(object):
    def __init__(self, port):
        super(_Port, self).__init__()
        self.ip = None
        self.netmask = None
        self.nw = None
        self.port = None
        self.port_no = None
        self.update(port)

    def set_ip(self, ip, netmask, nw):
        self.ip = ip
        self.netmask = netmask
        self.nw = nw

    def update(self, port):
        self.port = port
        self.port_no = port.port_no

    def to_dict(self):
        return {'ip': self.ip,
                'netmask': self.netmask,
                'nw': self.nw,
                'port_no': self.port_no}
