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

    def _switch_leave(self, dpid):
        switch = self.switches[dpid]
        self.send_event_to_observers(event.EventSwitchLeave(switch))
        del self.switches[dpid]

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        dpid = req.dpid
        if dpid is None:
            links = [link for link in self.links[dpid] for dpid in
                     self.links.keys()]
        else:
            links = self.links[dpid]
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @Pyro4.expose
    def report_links(self, dpid, links):
        self.links[dpid] = links
        self._logger.info('Link report from %d', dpid)

    @Pyro4.expose
    def unregister(self, dpid, name, uri):
        super(TopologyApp, self).unregister(dpid, name, uri)
        self._switch_leave(dpid)
        del self.links[dpid]

    @Pyro4.expose
    def port_added(self, port_data):
        self.send_event_to_observers(event.EventPortAdd(Port(port_data)))

    @Pyro4.expose
    def port_deleted(self, port_data):
        self.send_event_to_observers(event.EventPortDelete(Port(port_data)))

    @Pyro4.expose
    def port_modified(self, port_data):
        self.send_event_to_observers(event.EventPortModify(Port(port_data)))

    @Pyro4.expose
    def link_deleted(self, src_port_data, dst_port_data):
        src_port = Port(src_port_data)
        try:
            dst_port = self.switches[dst_port_data.dpid][dst_port_data.port_no]
            self.send_event_to_observers(
                event.EventLinkDelete(Link(src_port, dst_port)))
        except KeyError:
            self._logger.error('Cannot find dst port %s', str(dst_port_data))

    @Pyro4.expose
    def link_added(self, src_port_data, dst_port_data):
        src_port = Port(src_port_data)
        try:
            dst_port = self.switches[dst_port_data.dpid][dst_port_data.port_no]
            self.send_event_to_observers(
                event.EventLinkAdd(Link(src_port, dst_port)))
        except KeyError:
            self._logger.error('Cannot find dst port %s', str(dst_port_data))


