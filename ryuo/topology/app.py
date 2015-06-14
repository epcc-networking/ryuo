from threading import Lock
from ryu.controller.handler import set_ev_cls
from ryu.topology.switches import Link

from ryuo.controller.central import Ryuo
from ryuo.local.topology import EventSwitchEnter, EventSwitchLeave, \
    EventPortAdd, EventPortDelete, EventPortModify, EventSwitchRequest, \
    EventSwitchReply, EventLinkAdd, EventLinkDelete, EventLinkRequest, \
    EventLinkReply
from ryuo.topology.common import Switch
from ryuo.utils import expose


class TopologyApp(Ryuo):
    _EVENTS = {EventLinkAdd,
               EventLinkDelete,
               EventPortAdd,
               EventPortDelete,
               EventPortModify,
               EventSwitchEnter,
               EventSwitchLeave}
    _NAME = 'Topology'

    def __init__(self, *args, **kwargs):
        super(TopologyApp, self).__init__(*args, **kwargs)
        self.switches = {}  # dpid -> switch
        self._switches_lock = Lock()
        self.links = {}  # src_dpid -> dst_dpid -> link
        self._links_lock = Lock()

    @expose
    def switch_enter(self, dpid, ports_data):
        switch = Switch(dpid)
        for port_data in ports_data:
            switch.add_port(port_data)
        with self._switches_lock:
            self.switches[dpid] = switch
        self.send_event_to_observers(EventSwitchEnter(switch))

    @expose
    def ryuo_switch_leave(self, dpid, uri):
        super(TopologyApp, self).ryuo_switch_leave(dpid, uri)
        with self._switches_lock:
            switch = self.switches[dpid]
        self.send_event_to_observers(EventSwitchLeave(switch))
        with self._switches_lock:
            if dpid in self.switches:
                del self.switches[dpid]
        with self._links_lock:
            if dpid in self.links:
                del self.links[dpid]

    @set_ev_cls(EventLinkRequest)
    def link_request_handler(self, req):
        self._logger.debug('Link request.')
        dpid = req.dpid
        if dpid is None:
            with self._links_lock:
                links = [link for src_dpid in self.links.keys() for link in
                         self.links[src_dpid].values()]
        else:
            with self._links_lock:
                links = self.links[dpid].values()
        rep = EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @set_ev_cls(EventSwitchRequest)
    def switch_request_handler(self, req):
        self._logger.debug('Switch request')
        dpid = req.dpid
        if dpid is None:
            with self._switches_lock:
                switches = self.switches.values()
        else:
            with self._switches_lock:
                switches = [self.switches[dpid]]
        rep = EventSwitchReply(req.src, switches)
        self.reply_to_request(req, rep)

    @expose
    def port_added(self, port_data):
        self._logger.info('Port %d.%d comes up', port_data.dpid,
                          port_data.port_no)
        with self._switches_lock:
            port = self.switches[port_data.dpid].add_port(port_data)
        self.send_event_to_observers(EventPortAdd(port))

    @expose
    def port_deleted(self, port_data):
        self._logger.info('Port %d.%d deleted.', port_data.dpid,
                          port_data.port_no)
        with self._switches_lock:
            port = self.switches[port_data.dpid].del_port(port_data)
        self.send_event_to_observers(EventPortDelete(port))

    @expose
    def port_modified(self, port_data):
        self._logger.info('Port %d.%d modified.', port_data.dpid,
                          port_data.port_no)
        with self._switches_lock:
            port = self.switches[port_data.dpid].update_port(port_data)
        self.send_event_to_observers(EventPortModify(port))

    @expose
    def link_deleted(self, src_port_data, dst_port_data):
        try:
            with self._switches_lock:
                src_port = self.switches[src_port_data.dpid].update_port(
                    src_port_data)
                dst_port = self.switches[dst_port_data.dpid].update_port(
                    dst_port_data)
            with self._links_lock:
                del self.links[src_port.dpid][dst_port.dpid]
            self._logger.info('Link %d.%d -> %d.%d down',
                              src_port_data.dpid,
                              src_port_data.port_no,
                              dst_port_data.dpid,
                              dst_port_data.port_no)
            self.send_event_to_observers(
                EventLinkDelete(Link(src_port, dst_port)))
        except KeyError:
            self._logger.error('Cannot find link %d.%d -> %d.%d',
                               src_port_data.dpid,
                               src_port_data.port_no,
                               dst_port_data.dpid,
                               dst_port_data.port_no)

    @expose
    def link_added(self, src_port_data, dst_port_data):
        try:
            with self._switches_lock:
                src_port = self.switches[src_port_data.dpid].update_port(
                    src_port_data)
                dst_port = self.switches[dst_port_data.dpid].update_port(
                    dst_port_data)
            link = Link(src_port, dst_port)
            with self._links_lock:
                if src_port.dpid not in self.links.keys():
                    self.links[src_port.dpid] = {}
                self.links[src_port.dpid][dst_port.dpid] = link
            self._logger.info('Link %d.%d -> %d.%d up',
                              src_port_data.dpid,
                              src_port_data.port_no,
                              dst_port_data.dpid,
                              dst_port_data.port_no)
            self.send_event_to_observers(EventLinkAdd(link))
        except KeyError:
            self._logger.error('Cannot find dst port %d.%d',
                               dst_port_data.dpid,
                               dst_port_data.port_no)
