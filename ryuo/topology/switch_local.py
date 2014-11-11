import logging
import time

from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib.mac import DONTCARE_STR
from ryu.ofproto import ofproto_v1_2
from ryu.topology import event
from ryu.topology.switches import LinkState, Link, PortDataState, PortState, \
    LLDPPacket, Port

from ryuo.common.local_controller import LocalController


class SwitchLocal(LocalController):
    """
    Ryu topology module ported to Local Controller
    """
    _EVENTS = {event.EventLinkAdd,
               event.EventLinkDelete,
               event.EventPortAdd,
               event.EventPortDelete,
               event.EventPortModify}

    DEFAULT_TTL = 64
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0))
    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    def __init__(self, *args, **kwargs):
        super(SwitchLocal, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(self.__class__.__name__)
        self.is_active = True
        self.explicit_drop = True
        self.ports = PortDataState()
        self.port_state = PortState()
        self.links = LinkState()
        self.lldp_event = hub.Event()
        self.link_event = hub.Event()
        self.threads.append(hub.spawn(self.lldp_loop))
        self.threads.append(hub.spawn(self.link_loop))

    def _register(self, dp):
        super(SwitchLocal, self)._register(dp)
        for port in dp.ports.values():
            self.port_state.add(port.port_no, port)

    def _unregister(self):
        super(SwitchLocal, self)._unregister()
        self.port_state.clear()

    def _get_port(self, port_no):
        pass

    def _port_added(self, port):
        lldp_data = LLDPPacket.lldp_packet(port.dpid,
                                           port.port_no,
                                           port.hw_addr,
                                           self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)

    def _link_down(self, port):
        try:
            dst, rev_link_dst = self.links.port_deleted(port)
        except KeyError:
            return
        link = Link(port, dst)
        self.send_event_to_observers(event.EventLinkDelete(link))
        if rev_link_dst:
            rev_link = Link(dst, rev_link_dst)
            self.send_event_to_observers(event.EventLinkDelete(rev_link))
            # self.ports.move_front(dst)

    @set_ev_cls(ofp_event.EventOFPPortsStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofp_port = msg.desc

        if reason == dp.ofproto.OFPPR_ADD:
            self.port_state.add(ofp_port.port_no, ofp_port)
            self.send_event_to_observers(
                event.EventPortAdd(Port(dp.id, dp.ofproto, ofp_port)))

            port = self._get_port(ofp_port.port_no)
            if port and not port.is_reserved():
                self._port_added(port)
                self.lldp_event.set()
        elif reason == dp.ofproto.OFPPR_DELETE:
            self.port_state.remove(ofp_port.port_no)
            self.send_event_to_observers(
                event.EventPortDelete(Port(dp.id, dp.ofproto, ofp_port)))
            port = self._get_port(ofp_port.port_no)
            if port and not port.is_reserved():
                self.ports.del_port(port)
                self._link_down(port)
                self.lldp_event.set()
        else:
            self.port_state.modify(ofp_port.port_no, ofp_port)
            self.send_event_to_observers(
                event.EventPortModify(Port(dp.id, dp.ofproto, ofp_port)))
            port = self._get_port(ofp_port.port_no)
            if port and not port.is_reserved():
                if self.ports.set_down(port):
                    self._link_down(port)
                self.lldp_event.set()

    @set_ev_cls(ofp_event.EventOFPPakcetIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except LLDPPacket.LLDPUnknownFormat as e:
            self._logger.warning('Unknown LLDP format.')
        dst_dpid = msg.datapath.id
        if msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dst_port_no = msg.match['in_port']
        else:
            self._logger.error('Unsupported LLDP version. %x',
                               msg.datapath.ofproto.OFP_VERSION)
        src = self._get_port(src_dpid, src_port_no)
        if not src or src.dpid == dst_dpid:
            return
        try:
            self.ports.lldp_received(src)
        except KeyError:
            pass
        dst = self._get_port(dst_dpid, dst_port_no)
        if not dst:
            return
        old_peer = self.links.get_peer(src)
        if old_peer and old_peer != dst:
            old_link = Link(src, old_peer)
            self.send_event_to_observers(event.EventLinkDelete(old_link))
        link = Link(src, dst)
        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))
        if not self.links.update_link(src, dst):
            self.ports.move_front(dst)
            self.lldp_event.set()
        if self.explicit_drop:
            self._drop_packet(msg)

    def send_lldp_packet(self, port):
        try:
            port_data = self.ports.lldp_sent(port)
        except KeyError as e:
            return
        if port_data.is_down:
            return
        dp = self.dp
        if dp is None:
            return
        ofp = dp.ofproto
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            out = dp.ofproto_parser.OFPPacketOut(datapath=dp,
                                                 in_port=ofp.OFPP_CONTROLLER,
                                                 buffer_id=ofp.OFP_NO_BUFFER,
                                                 actions=actions,
                                                 data=port_data.lldp_data)
            dp.send_msg(out)
        else:
            self._logger.error('Cannot send LLDP packet, unsupported version.')

    def lldp_loop(self):
        while self.is_active:
            self.lldp_event.clear()
            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            for (key, data) in self.ports.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue
                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue
                timeout = expire - now
            for port in ports_now:
                self.send_lldp_packet(port)
            for port in ports:
                self.send_lldp_packet(port)
                hub.sleep(self.LLDP_SEND_GUARD)

            if timeout is not None and ports:
                timeout = 0
            self.lldp_event.wait(timeout=timeout)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()
            now = time.time()
            deleted = []
            for (link, timestamp) in self.links.items():
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    if src in self.ports:
                        port_data = self.ports.get_port(src)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)
            for link in deleted:
                self.links.link_down(link)
                self.send_event_to_observers(event.EventLinkDelete(link))
                dst = link.dst
                rev_link = Link(dst, link.src)
                if rev_link not in deleted:
                    expire = now - self.LINK_TIMEOUT
                    self.links.rev_link_set_timestamp(rev_link, expire)
                    if dst in self.ports:
                        self.ports.move_front(dst)
                        self.lldp_event.set()
            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        # LOG.debug(req)
        dpid = req.dpid

        if dpid is None:
            links = self.links
        else:
            links = [link for link in self.links if link.src.dpid == dpid]
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    def close(self):
        self.is_active = False
        self.lldp_event.set()
        self.link_event.set()
        hub.joinall(self.threads)