import time

from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib.mac import DONTCARE_STR
from ryu.lib.packet import lldp, packet
from ryu.ofproto import ofproto_v1_2, ofproto_v1_3, ofproto_v1_4
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.topology.switches import LLDPPacket, PortDataState, Link, LinkState

from ryuo.constants import ETHERNET
from ryuo.topology import event
from ryuo.local.local_controller import LocalController
from ryuo.topology.common import PortData, Port
from ryuo.topology.app import TopologyApp


class TopologyLocal(LocalController):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION,
                    ofproto_v1_4.OFP_VERSION]

    _EVENTS = {event.EventPortAdd,
               event.EventPortDelete,
               event.EventPortModify,
               event.EventLinkAdd,
               event.EventLinkDelete}
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

    def __init__(self, *args, **kwargs):
        kwargs['ryuo_name'] = TopologyApp.__name__
        super(TopologyLocal, self).__init__(*args, **kwargs)
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
        super(TopologyLocal, self)._switch_enter(dp)
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
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            match = ofp_parser.OFPMatch(
                eth_type=ETH_TYPE_LLDP,
                eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE
            )
            actions = [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                  ofp.OFPCML_NO_BUFFER)]
            inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                     actions)]
            mod = ofp_parser.OFPFlowMod(datapath=self.dp,
                                        match=match,
                                        idle_timeout=0,
                                        hard_timeout=0,
                                        instructions=inst,
                                        priority=0xFFFF)
            self.dp.send_msg(mod)
        else:
            self._logger.error(
                'Cannot install flow, unsupported OF version %x',
                ofp.OFP_VERSION)

    def _switch_leave(self):
        super(TopologyLocal, self)._switch_leave()
        self.links.clear()
        self.ports.clear()

    def _get_port(self, port_no):
        for port in self.ports.keys():
            if port.port_no == port_no:
                return port

    def _report_port_added(self, port):
        self.send_event_to_observers(event.EventPortAdd(port))
        self.ryuo.port_added(port.port_data)

    def _report_port_deleted(self, port):
        self.send_event_to_observers(event.EventPortDelete(port))
        self.ryuo.port_deleted(port.port_data)

    def _report_port_modified(self, port):
        self.send_event_to_observers(event.EventPortModify(port))
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

        # LOG.debug('lldp sent dpid=%s, port_no=%d', dp.id, port.port_no)
        # TODO:XXX
        if dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
                buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
                data=port_data.lldp_data)
            dp.send_msg(out)
        else:
            self._logger.error(
                'cannot send lldp packet. unsupported version. %x',
                dp.ofproto.OFP_VERSION)

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
        self.send_event_to_observers(event.EventLinkDelete(link))
        self.ryuo.link_deleted(link.src.port_data, link.dst.port_data)

    def _report_link_added(self, link):
        self.send_event_to_observers(event.EventLinkAdd(link))
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
        dst_port_no = None
        if ofp.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dst_port_no = msg.match['in_port']
        else:
            self._logger.error(
                'Cannot accept LLDP, unsupported OF version %x.',
                ofp.OFP_VERSION)
        dst = self._get_port(dst_port_no)
        self._logger.info('LLDP from %d.%d -> %d',
                          src_dpid,
                          src_port_no,
                          dst_port_no)
        if not dst:
            self._logger.warning('Dst not found.')
            return
        self.ports.lldp_received(dst)
        src = Port(PortData(src_dpid, port_no=src_port_no, hw_addr=src_mac))
        old_peer = self.links.get_peer(dst)
        if old_peer and old_peer != src:
            self._logger.info('Peer changed.')
            self._report_link_deleted(Link(old_peer, dst))
        link = Link(src, dst)
        if link not in self.links:
            self._report_link_added(Link(src, dst))
            self.lldp_event.set()

        # Always return false, since we don't have the reverse link information
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
        super(TopologyLocal, self).close()


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