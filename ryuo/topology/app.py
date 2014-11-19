import Pyro4
from ryu.controller.handler import set_ev_cls
from ryu.topology.switches import Link

from ryuo.controller.central import Ryuo
from ryuo.topology import event
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
        super(TopologyApp, self).__init__(*args, **kwargs)
        self.switches = {}  # dpid -> switch
        self.links = {}  # src_dpid -> dst_dpid -> link

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
        self._logger.debug('Link request.')
        dpid = req.dpid
        if dpid is None:
            links = [link for src_dpid in self.links.keys() for link in
                     self.links[src_dpid].values()]
        else:
            links = self.links[dpid].values()
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @Pyro4.expose
    def port_added(self, port_data):
        self._logger.info('Port %d.%d comes up', port_data.dpid,
                          port_data.port_no)
        self.switches[port_data.dpid].add_port(port_data)
        self.send_event_to_observers(event.EventPortAdd(Port(port_data)))

    @Pyro4.expose
    def port_deleted(self, port_data):
        self._logger.info('Port %d.%d deleted.', port_data.dpid,
                          port_data.port_no)
        self.switches[port_data.dpid].del_port(port_data)
        self.send_event_to_observers(event.EventPortDelete(Port(port_data)))

    @Pyro4.expose
    def port_modified(self, port_data):
        self._logger.info('Port %d.%d modified.', port_data.dpid,
                          port_data.port_no)
        self.switches[port_data.dpid].update_port(port_data)
        self.send_event_to_observers(event.EventPortModify(Port(port_data)))

    @Pyro4.expose
    def link_deleted(self, src_port_data, dst_port_data):
        try:
            src_port = self.switches[src_port_data.dpid].update_port(
                src_port_data)
            dst_port = self.switches[dst_port_data.dpid].update_port(
                src_port_data)
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
        try:
            src_port = self.switches[src_port_data.dpid].update_port(
                src_port_data)
            dst_port = self.switches[dst_port_data.dpid].update_port(
                dst_port_data)
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
