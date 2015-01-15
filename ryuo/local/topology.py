import time
import logging

from ryu.controller import ofp_event, event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib.mac import DONTCARE_STR
from ryu.lib.packet import lldp, packet
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.topology.switches import LLDPPacket, PortDataState, Link, LinkState

from ryuo.constants import ETHERNET
from ryuo.local.local_service import LocalService
from ryuo.topology.common import PortData, Port

LOG = logging.getLogger(__name__)


class EventLinkBase(event.EventBase):
    def __init__(self, link):
        super(EventLinkBase, self).__init__()
        self.link = link

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.link)


class EventSwitchBase(event.EventBase):
    def __init__(self, switch):
        super(EventSwitchBase, self).__init__()
        self.switch = switch

    def __str__(self):
        return '%s<dpid=%s, %s ports>' % \
               (self.__class__.__name__,
                self.switch.dp.id, len(self.switch.ports))


class EventSwitchEnter(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchEnter, self).__init__(switch)


class EventSwitchLeave(EventSwitchBase):
    def __init__(self, switch):
        super(EventSwitchLeave, self).__init__(switch)


class EventPortBase(event.EventBase):
    def __init__(self, port):
        super(EventPortBase, self).__init__()
        self.port = port

    def __str__(self):
        return '%s<%s>' % (self.__class__.__name__, self.port)


class EventPortAdd(EventPortBase):
    def __init__(self, port):
        super(EventPortAdd, self).__init__(port)


class EventPortDelete(EventPortBase):
    def __init__(self, port):
        super(EventPortDelete, self).__init__(port)


class EventPortModify(EventPortBase):
    def __init__(self, port):
        super(EventPortModify, self).__init__(port)


class EventSwitchRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventSwitchRequest, self).__init__()
        self.dst = 'Topology'
        self.dpid = dpid

    def __str__(self):
        return 'EventSwitchRequest<src=%s, dpid=%s>' % \
               (self.src, self.dpid)


class EventSwitchReply(event.EventReplyBase):
    def __init__(self, dst, switches):
        super(EventSwitchReply, self).__init__(dst)
        self.switches = switches

    def __str__(self):
        return 'EventSwitchReply<dst=%s, %s>' % \
               (self.dst, self.switches)


class EventLinkAdd(EventLinkBase):
    def __init__(self, link):
        super(EventLinkAdd, self).__init__(link)


class EventLinkDelete(EventLinkBase):
    def __init__(self, link):
        super(EventLinkDelete, self).__init__(link)


class EventLinkRequest(event.EventRequestBase):
    # If dpid is None, reply all list
    def __init__(self, dpid=None):
        super(EventLinkRequest, self).__init__()
        self.dst = 'Topology'
        self.dpid = dpid

    def __str__(self):
        return 'EventLinkRequest<src=%s, dpid=%s>' % \
               (self.src, self.dpid)


class EventLinkReply(event.EventReplyBase):
    def __init__(self, dst, dpid, links):
        super(EventLinkReply, self).__init__(dst)
        self.dpid = dpid
        self.links = links

    def __str__(self):
        return 'EventLinkReply<dst=%s, dpid=%s, links=%s>' % \
               (self.dst, self.dpid, len(self.links))


class Topology(LocalService):
    _EVENTS = {EventPortAdd,
               EventPortDelete,
               EventPortModify,
               EventLinkAdd,
               EventLinkDelete}
    """
    Ryu topology module ported to Local Controller
    """
    DEFAULT_TTL = 64
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0))
    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5
    LLDP_PRIORITY = 0xFFFF

    def __init__(self, *args, **kwargs):
        super(Topology, self).__init__(*args, **kwargs)
        self.is_active = True
        self.explicit_drop = True
        self.ports = PortDataState()
        self.links = _LinkState()
        self.lldp_event = hub.Event()
        self.link_event = hub.Event()
        self.threads.append(hub.spawn(self.lldp_loop))
        self.threads.append(hub.spawn(self.link_loop))

    def _port_added(self, port):
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)

    def _switch_enter(self, dp):
        super(Topology, self)._switch_enter(dp)
        self._init_flows()
        ports = [Port(PortData(dp.id, port, dp.ofproto)) for port in
                 dp.ports.values()]
        for port in ports:
            if not port.is_reserved():
                self._port_added(port)
        self.ryuo.switch_enter(dp.id,
                               [port.port_data for port in self.ports.keys()])
        self.lldp_event.set()

    def _init_flows(self):
        self._logger.info('Init flow table.')
        self.ofctl.set_packet_in_flow(cookie=0, priority=self.LLDP_PRIORITY,
                                      eth_type=ETH_TYPE_LLDP,
                                      eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)

    def _switch_leave(self):
        super(Topology, self)._switch_leave()
        self.links.clear()
        self.ports.clear()

    def _get_port(self, port_no):
        for port in self.ports.keys():
            if port.port_no == port_no:
                return port

    def _report_port_added(self, port):
        self.send_event_to_observers(EventPortAdd(port))
        self.ryuo.port_added(port.port_data)

    def _report_port_deleted(self, port):
        self.send_event_to_observers(EventPortDelete(port))
        self.ryuo.port_deleted(port.port_data)

    def _report_port_modified(self, port):
        self.send_event_to_observers(EventPortModify(port))
        self.ryuo.port_modified(port.port_data)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_change(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofpport = msg.desc
        ofp = dp.ofproto

        if reason == ofp.OFPPR_ADD:
            self._logger.info('Port %d added.', ofpport.port_no)
            port = Port(PortData(self.dp.id, ofpport, ofp))
            if not port.is_reserved():
                self._port_added(port)
                self._report_port_added(port)
                self.lldp_event.set()
        elif reason == ofp.OFPPR_DELETE:
            self._logger.info('Port %d deleted.', ofpport.port_no)
            port = self._get_port(ofpport.port_no)
            if port and not port.is_reserved():
                del self.ports[Port(PortData(self.dp.id, ofpport))]
                self._report_port_deleted(port)
                self._link_down(port)
                self.lldp_event.set()
        else:
            self._logger.info('Port %d modified.', ofpport.port_no)
            port = self._get_port(ofpport.port_no)
            port.lldp_reply = False
            if port and not port.is_reserved():
                port.modify(ofpport)
                self._report_port_modified(port)
                if self.ports.set_down(port):
                    self._link_down(port)
                self.lldp_event.set()

    def send_lldp_packet(self, port):
        try:
            port_data = self.ports.lldp_sent(port)
        except KeyError as e:
            # ports can be modified during our sleep in self.lldp_loop()
            self._logger.warning('Missing port %d, %s.', port.port_no, e)
            return
        if port_data.is_down:
            return

        dp = self.dp
        if dp is None:
            # datapath was already deleted
            self._logger.warning('Switch left.')
            return

        self.ofctl.send_packet_out(in_port=dp.ofproto.OFPP_CONTROLLER,
                                   output=port.port_no,
                                   data=port_data.lldp_data)

    def lldp_loop(self):
        while self.is_active:
            self._logger.debug('LLDP loop')
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

                if timeout is None or timeout > expire - now:
                    timeout = expire - now
                    # break

            for port in ports_now:
                self.send_lldp_packet(port)
                self._logger.debug('Sending LLDP to %d.%d',
                                   port.dpid,
                                   port.port_no)
            for port in ports:
                self.send_lldp_packet(port)
                self._logger.debug('Sending LLDP to %d.%d',
                                   port.dpid,
                                   port.port_no)
                hub.sleep(self.LLDP_SEND_GUARD)  # don't burst

            if timeout is not None and ports:
                timeout = 0  # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.lldp_event.wait(timeout=timeout)

    def _report_link_deleted(self, link):
        self.send_event_to_observers(EventLinkDelete(link))
        self.ryuo.link_deleted(link.src.port_data, link.dst.port_data)

    def _report_link_added(self, link):
        self.send_event_to_observers(EventLinkAdd(link))
        self.ryuo.link_added(link.src.port_data, link.dst.port_data)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self._logger.debug('Packet in')
        msg = ev.msg
        ofp = msg.datapath.ofproto
        pkt = packet.Packet(msg.data)
        headers = dict((p.protocol_name, p)
                       for p in pkt.protocols if type(p) != str)
        src_mac = headers[ETHERNET].src
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except LLDPPacket.LLDPUnknownFormat as e:
            self._logger.debug('LLDPUnknownFormat %s', e)
            return
        dst_port_no = self.ofctl.get_packet_in_inport(msg)
        dst = self._get_port(dst_port_no)
        self._logger.debug('LLDP from %d.%d -> %d',
                           src_dpid,
                           src_port_no,
                           dst_port_no)
        if not dst:
            self._logger.warning('Dst not found.')
            return
        self.ports.lldp_received(dst)
        src = Port(PortData(src_dpid, port_no=src_port_no, hw_addr=src_mac))
        old_peer = self.links.get_peer(dst)
        need_update = False
        if old_peer and old_peer != src:
            self._logger.info('Peer changed.')
            self._report_link_deleted(Link(old_peer, dst))
            need_update = True
        link = Link(src, dst)
        if link not in self.links:
            need_update = True
            self._report_link_added(Link(src, dst))
            self.lldp_event.set()

        # Always return false, since we don't have the reverse link information
        if need_update:
            self.links.update_link(src, dst)
            self._logger.info('Update link %d.%d -> %d.%d',
                              src.dpid,
                              src.port_no,
                              dst.dpid,
                              dst.port_no)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()

            now = time.time()
            deleted = []
            for (link, timestamp) in self.links.items():
                # LOG.debug('%s timestamp %d (now %d)', link, timestamp, now)
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    if src in self.ports:
                        port_data = self.ports.get_port(src)
                        # LOG.debug('port_data %s', port_data)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)

            for link in deleted:
                self.links.link_down(link)
                # LOG.debug('delete %s', link)
                self._report_link_deleted(link)

            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    def _link_down(self, port):
        try:
            src, rev_link_dst = self.links.dst_port_deleted(port)
            self._logger.info('Link down: %d.%d -> %d.%d',
                              src.dpid,
                              src.port_no,
                              port.dpid,
                              port.port_no)
        except KeyError:
            self._logger.info('Cannot find peer of %d.%d',
                              port.dpid,
                              port.port_no)
            return
        self._report_link_deleted(Link(src, port))

    def close(self):
        self.is_active = False
        self.lldp_event.set()
        self.link_event.set()
        super(Topology, self).close()


class _LinkState(LinkState):
    def __init__(self):
        super(_LinkState, self).__init__()
        self._rmap = {}

    def get_peer(self, port):
        peer = self._map.get(port, None)
        if peer is None:
            return self._rmap.get(port, None)
        return peer

    def update_link(self, src, dst):
        self._rmap[dst] = src
        return super(_LinkState, self).update_link(src, dst)

    def link_down(self, link):
        del self._rmap[link.dst]
        super(_LinkState, self).link_down(link)

    def port_deleted(self, src):
        dst, rev_link_dst = super(_LinkState, self).port_deleted(src)
        del self._rmap[dst]
        return dst, rev_link_dst

    def dst_port_deleted(self, dst):
        src = self.get_peer(dst)
        if src is None:
            raise KeyError()

        link = Link(src, dst)
        rev_link = Link(dst, src)
        del self[link]
        del self._map[src]
        del self._rmap[dst]
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        return src, rev_link_dst


