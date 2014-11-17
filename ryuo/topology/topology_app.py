#!/usr/bin/env python2
import Pyro4
from ryu.controller.handler import set_ev_cls
from ryu.topology import event
from ryu.topology.switches import Link

from ryuo.common.central import Ryuo
from ryuo.topology.common import Switch, Port


class TopologyApp(Ryuo):
    _EVENTS = {event.EventLinkAdd,
               event.EventLinkDelete,
               event.EventPortAdd,
               event.EventPortDelete,
               event.EventPortModify,
               event.EventSwitchEnter,
               event.EventSwitchLeave}

    def __init__(self, *args, **kwargs):
        super(TopologyApp, self).__init__(args, kwargs)
        self.switches = {}  # dpid -> switch
        self.links = {}

    @Pyro4.expose
    def switch_enter(self, dpid, ports_data):
        switch = Switch(dpid)
        for port_data in ports_data:
            switch.add_port(port_data)
        self.switches[dpid] = switch
        self.send_event_to_observers(event.EventSwitchEnter(switch))

    @Pyro4.expose
    def ryuo_switch_leave(self, dpid, uri):
        super(TopologyApp, self).ryuo_switch_leave(dpid, uri)
        switch = self.switches[dpid]
        self.send_event_to_observers(event.EventSwitchLeave(switch))
        if dpid in self.switches:
            del self.switches[dpid]
        if dpid in self.links:
            del self.links[dpid]

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        dpid = req.dpid
        if dpid is None:
            links = [link for link in self.links[dpid].values() for dpid in
                     self.links.keys()]
        else:
            links = self.links[dpid].values()
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @Pyro4.expose
    def port_added(self, port_data):
        self._logger.info('Port %d.%d comes up', port_data.dpid,
                          port_data.port_no)
        self.send_event_to_observers(event.EventPortAdd(Port(port_data)))

    @Pyro4.expose
    def port_deleted(self, port_data):
        self._logger.info('Port %d.%d deleted.', port_data.dpid,
                          port_data.port_no)
        self.send_event_to_observers(event.EventPortDelete(Port(port_data)))

    @Pyro4.expose
    def port_modified(self, port_data):
        self._logger.info('Port %d.%d modified.', port_data.dpid,
                          port_data.port_no)
        self.send_event_to_observers(event.EventPortModify(Port(port_data)))

    @Pyro4.expose
    def link_deleted(self, src_port_data, dst_port_data):
        src_port = Port(src_port_data)
        try:
            dst_port = self.switches[dst_port_data.dpid].ports[
                dst_port_data.port_no]
            del self.links[src_port.dpid][dst_port.dpid]
            self._logger.info('Link %d.%d -> %d.%d down',
                              src_port_data.dpid,
                              src_port_data.port_no,
                              dst_port_data.dpid,
                              dst_port_data.port_no)
            self.send_event_to_observers(
                event.EventLinkDelete(Link(src_port, dst_port)))
        except KeyError:
            self._logger.error('Cannot find link %d.%d -> %d.%d',
                               src_port_data.dpid,
                               src_port_data.port_no,
                               dst_port_data.dpid,
                               dst_port_data.port_no)

    @Pyro4.expose
    def link_added(self, src_port_data, dst_port_data):
        src_port = Port(src_port_data)
        try:
            dst_port = self.switches[dst_port_data.dpid].ports[
                dst_port_data.port_no]
            link = Link(src_port, dst_port)
            if src_port.dpid not in self.links.keys():
                self.links[src_port.dpid] = {}
            self.links[src_port.dpid][dst_port.dpid] = link
            self._logger.info('Link %d.%d -> %d.%d up',
                              src_port_data.dpid,
                              src_port_data.port_no,
                              dst_port_data.dpid,
                              dst_port_data.port_no)
            self.send_event_to_observers(event.EventLinkAdd(link))
        except KeyError:
            self._logger.error('Cannot find dst port %d.%d',
                               dst_port_data.dpid,
                               dst_port_data.port_no)
