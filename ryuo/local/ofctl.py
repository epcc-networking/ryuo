from ryu.exception import OFPUnknownVersion
from ryu.lib.mac import haddr_to_bin
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_0, ofproto_v1_2, ofproto_v1_3, ofproto_v1_4
from ryu.ofproto import ofproto_v1_3_parser
import threading

from ryuo.utils import *
from ryuo.constants import *


class OfCtl(object):
    _OF_VERSIONS = {}
    lock = threading.Lock()
    switch_inited = False

    def __init__(self, dp, logger):
        super(OfCtl, self).__init__()
        self.dp = dp
        self.logger = logger
        self.ofp = dp.ofproto
        self.ofp_parser = dp.ofproto_parser

    @staticmethod
    def register_of_version(version):
        def _register_of_version(cls):
            OfCtl._OF_VERSIONS.setdefault(version, cls)
            return cls

        return _register_of_version

    @staticmethod
    def factory(dp, logger):
        of_version = dp.ofproto.OFP_VERSION
        if of_version in OfCtl._OF_VERSIONS:
            ofctl = OfCtl._OF_VERSIONS[of_version](dp, logger)
            return ofctl
        else:
            raise OFPUnknownVersion(version=of_version)

    def async_config_to_str(self, msg):
        self.logger.warning('Async Config not supported by OFP: %d',
                            self.ofp.OFP_VERSION)

    def send_packet_out(self, in_port, output, data, data_str=None):
        actions = [self.dp.ofproto_parser.OFPActionOutput(output)]
        self.dp.send_packet_out(in_port=in_port, actions=actions, data=data)
        # TODO: Packet library convert to string
        # if data_str is None:
        # data_str = str(packet.Packet(data))
        # self.logger.debug('Packet out = %s', data_str, extra=self.sw_id)

    def set_normal_flow(self, cookie, priority):
        # out_port = self.dp.ofproto.OFPP_NORMAL
        # actions = [self.dp.ofproto_parser.OFPActionOutput(out_port, 0)]
        actions = []
        self.set_flow(cookie, priority, actions=actions)

    def get_packet_in_inport(self, msg):
        pass

    def update_routing_flow(self, cookie, priority, out_port, dl_vlan=None,
                            nw_src=None, src_mask=32, nw_dst=None, dst_mask=32,
                            src_mac=None, dst_mac=None, idle_timeout=0,
                            dec_ttl=False, eth_type=ether.ETH_TYPE_IP,
                            in_port=None, out_group=None):
        self._mod_routing_flow(self.ofp.OFPFC_MODIFY, cookie, priority,
                               out_port, dl_vlan, nw_src, src_mask, nw_dst,
                               dst_mask, src_mac, dst_mac, idle_timeout,
                               dec_ttl, eth_type, in_port, out_group)

    def set_routing_flow(self, cookie, priority, out_port, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False,
                         eth_type=ether.ETH_TYPE_IP, in_port=None,
                         out_group=None):
        self._mod_routing_flow(self.ofp.OFPFC_ADD, cookie, priority, out_port,
                               dl_vlan, nw_src, src_mask, nw_dst, dst_mask,
                               src_mac, dst_mac, idle_timeout, dec_ttl,
                               eth_type, in_port, out_group)

    def _mod_routing_flow(self, command, cookie, priority, out_port, dl_vlan=0,
                          nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                          src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False,
                          eth_type=ether.ETH_TYPE_IP, in_port=None,
                          out_group=None):
        pass

    def set_routing_flow_v6(self, cookie, priority, outport, dl_vlan=None,
                            nw_src=None, src_mask=128, nw_dst=None,
                            dst_mask=128, src_mac=None, dst_mac=None,
                            idle_timeout=0, dec_ttl=False):
        self.set_routing_flow(cookie, priority, outport, dl_vlan=dl_vlan,
                              nw_src=nw_src, src_mask=src_mask, nw_dst=nw_dst,
                              dst_mask=dst_mask, src_mac=src_mac,
                              dst_mac=dst_mac, idle_timeout=idle_timeout,
                              dec_ttl=dec_ttl, eth_type=ether.ETH_TYPE_IPV6)

    def set_async_config(self, packet_in_mask=None, port_status_mask=None,
                         flow_removed_mask=None):
        self.logger.warning('Set Async is not supported by OFP: %d',
                            self.ofp.OFP_VERSION)

    def set_flow(self, cookie, priority, eth_type=None, eth_dst=None,
                 dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                 dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                 in_port=None):
        self._mod_flow(self.ofp.OFPFC_ADD, cookie, priority, eth_type, eth_dst,
                       dl_vlan, nw_src, src_mask, nw_dst, dst_mask, nw_proto,
                       idle_timeout, actions, in_port)

    def update_flow(self, cookie, priority, eth_type=None, eth_dst=None,
                    dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                    dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                    in_port=None):
        self._mod_flow(self.ofp.OFPFC_MODIFY, cookie, priority, eth_type,
                       eth_dst,
                       dl_vlan, nw_src, src_mask, nw_dst, dst_mask, nw_proto,
                       idle_timeout, actions, in_port)

    def _mod_flow(self, command, cookie, priority, eth_type=None, eth_dst=None,
                  dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                  dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                  in_port=None):
        pass

    def set_packet_in_flow(self, cookie, priority, eth_type=0, eth_dst=0,
                           dl_vlan=0, dst_ip=0, dst_mask=32, nw_proto=0,
                           idle_timeout=0, in_port=None):
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER)]
        self.set_flow(cookie, priority, eth_type=eth_type, eth_dst=eth_dst,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,
                      nw_proto=nw_proto, actions=actions,
                      idle_timeout=idle_timeout, in_port=in_port)

    def set_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                           dst_macs, command):
        self.logger.warning('FF Group not supported by OFP: %d',
                            self.ofp.OFP_VERSION)

    def modify_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                              dst_macs):
        self.logger.warning('FF Group not supported by OFP: %d',
                            self.ofp.OFP_VERSION)

    def add_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                           dst_macs):
        self.logger.warning('FF Group not supported by OFP: %d',
                            self.ofp.OFP_VERSION)

    def send_icmp(self, in_port, eth_src, eth_dst, icmp_type, icmp_code,
                  ip_dst, icmp_data=None, msg_data=None, src_ip=None,
                  ip_header_length=5, ip_version=4, ip_tos=0, identification=0,
                  flags=0, ip_offset=0):
        # Generate ICMP reply packet
        csum = 0
        offset = ethernet.ethernet._MIN_LEN

        ether_proto = ether.ETH_TYPE_IP

        e = ethernet.ethernet(eth_dst, eth_src, ether_proto)

        if icmp_data is None and msg_data is not None:
            ip_datagram = msg_data[offset:]
            if icmp_type == icmp.ICMP_DEST_UNREACH:
                icmp_data = icmp.dest_unreach(data_len=len(ip_datagram),
                                              data=ip_datagram)
            elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
                icmp_data = icmp.TimeExceeded(data_len=len(ip_datagram),
                                              data=ip_datagram)

        ic = icmp.icmp(icmp_type, icmp_code, csum, data=icmp_data)

        ip_total_length = ip_header_length * 4 + ic._MIN_LEN
        if ic.data is not None:
            ip_total_length += ic.data._MIN_LEN
            if ic.data.data is not None:
                ip_total_length += + len(ic.data.data)
        i = ipv4.ipv4(ip_version, ip_header_length, ip_tos,
                      ip_total_length, identification, flags,
                      ip_offset, DEFAULT_TTL, inet.IPPROTO_ICMP, csum,
                      src_ip, ip_dst)
        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(i)
        pkt.add_protocol(ic)
        pkt.serialize()

        # Send packet out
        self.send_packet_out(in_port, self.dp.ofproto.OFPP_IN_PORT,
                             pkt.data, data_str=str(pkt))

    def reply_icmp(self, in_port, protocol_list, icmp_type, icmp_code,
                   icmp_data=None, msg_data=None, src_ip=None):

        eth = protocol_list[ETHERNET]
        ip = protocol_list[IPV4]
        self.send_icmp(in_port=in_port,
                       eth_src=eth.dst,
                       eth_dst=eth.src,
                       icmp_type=icmp_type,
                       icmp_code=icmp_code,
                       icmp_data=icmp_data,
                       msg_data=msg_data,
                       src_ip=src_ip,
                       ip_version=ip.version,
                       ip_header_length=ip.header_length,
                       ip_tos=ip.tos,
                       identification=ip.identification,
                       flags=ip.flags,
                       ip_offset=ip.offset,
                       ip_dst=ip.src)

    def send_arp(self, arp_opcode, src_mac, dst_mac,
                 src_ip, dst_ip, arp_target_mac, in_port, output):
        # Generate ARP packet

        ether_proto = ether.ETH_TYPE_ARP
        hwtype = 1
        arp_proto = ether.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ether_proto)
        a = arp.arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        # Send packet out
        self.send_packet_out(in_port, output, pkt.data, data_str=str(pkt))
        self.logger.debug('Sending ARP from %s to %s', src_ip, dst_ip)

    def get_async_config_request(self):
        self.logger.warning(
            'Get Async Config Request not supported by OFP: %d',
            self.ofp.OFP_VERSION)


@OfCtl.register_of_version(ofproto_v1_0.OFP_VERSION)
class OfCtl_v1_0(OfCtl):
    def __init__(self, dp, logger):
        super(OfCtl_v1_0, self).__init__(dp, logger)

    def _mod_routing_flow(self, command, cookie, priority, out_port, dl_vlan=0,
                          nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                          src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False,
                          eth_type=ether.ETH_TYPE_IP, in_port=None,
                          out_group=None):
        ofp_parser = self.dp.ofproto_parser

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.NXActionDecTtl())
        if src_mac:
            if type(src_mac) == str:
                src_mac = haddr_to_bin(src_mac)
            actions.append(ofp_parser.OFPActionSetDlSrc(src_mac))
        if dst_mac:
            if type(dst_mac) == str:
                dst_mac = haddr_to_bin(dst_mac)
            actions.append(ofp_parser.OFPActionSetDlDst(dst_mac))
        if out_port is not None:
            actions.append(ofp_parser.OFPActionOutput(out_port))
        if out_group is not None:
            self.logger.warning('Group is not supported in OFP: %d',
                                self.ofp.OFP_VERSION)

        self._mod_flow(command, cookie, priority, eth_type=eth_type,
                       dl_vlan=dl_vlan,
                       nw_src=nw_src, src_mask=src_mask,
                       nw_dst=nw_dst, dst_mask=dst_mask,
                       idle_timeout=idle_timeout, actions=actions,
                       in_port=in_port)

    def get_packet_in_inport(self, msg):
        return msg.in_port

    def _mod_flow(self, command, cookie, priority, eth_type=None, eth_dst=None,
                  dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                  dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                  in_port=None):
        ofp = self.ofp
        ofp_parser = self.ofp_parser

        wildcards = ofp.OFPFW_ALL
        if in_port:
            wildcards &= ~ofp.OFPFW_IN_PORT
        if eth_type:
            wildcards &= ~ofp.OFPFW_DL_TYPE
        if eth_dst:
            wildcards &= ~ofp.OFPFW_DL_DST
            if type(eth_dst) == str:
                eth_dst = haddr_to_bin(eth_dst)
        if dl_vlan:
            wildcards &= ~ofp.OFPFW_DL_VLAN
        if nw_src:
            v = (32 - src_mask) << ofp.OFPFW_NW_SRC_SHIFT | \
                ~ofp.OFPFW_NW_SRC_MASK
            wildcards &= v
            nw_src = ipv4_text_to_int(nw_src)
        if nw_dst:
            v = (32 - dst_mask) << ofp.OFPFW_NW_DST_SHIFT | \
                ~ofp.OFPFW_NW_DST_MASK
            wildcards &= v
            nw_dst = ipv4_text_to_int(nw_dst)
        if nw_proto:
            wildcards &= ~ofp.OFPFW_NW_PROTO
        match = ofp_parser.OFPMatch(wildcards, in_port=in_port, dl_src=None,
                                    dl_dst=eth_dst, dl_vlan=dl_vlan,
                                    dl_vlan_pcp=None, dl_type=eth_type,
                                    nw_tos=None, nw_proto=nw_proto,
                                    nw_src=nw_src, nw_dst=nw_dst, tp_src=None,
                                    tp_dst=None, nw_src_mask=src_mask,
                                    nw_dst_mask=dst_mask)
        actions = actions or []
        m = ofp_parser.OFPFlowMod(self.dp, match, cookie, command,
                                  idle_timeout=idle_timeout,
                                  priority=priority,
                                  actions=actions)
        self.dp.send_msg(m)


@OfCtl.register_of_version(ofproto_v1_2.OFP_VERSION)
class OfCtl_v1_2(OfCtl_v1_0):
    def __init__(self, dp, logger):
        super(OfCtl_v1_2, self).__init__(dp, logger)

    def _mod_routing_flow(self, command, cookie, priority, out_port, dl_vlan=0,
                          nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                          src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False,
                          eth_type=ether.ETH_TYPE_IP, in_port=None,
                          out_group=None):
        ofp_parser = self.dp.ofproto_parser

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
        if out_port is not None:
            actions.append(ofp_parser.OFPActionOutput(out_port))
        if out_group is not None:
            actions.append(ofp_parser.OFPActionGroup(group_id=out_group))

        self._mod_flow(command, cookie, priority, eth_type=eth_type,
                       dl_vlan=dl_vlan,
                       nw_src=nw_src, src_mask=src_mask,
                       nw_dst=nw_dst, dst_mask=dst_mask,
                       idle_timeout=idle_timeout, actions=actions,
                       in_port=in_port)

    def get_packet_in_inport(self, msg):
        in_port = self.dp.ofproto.OFPP_ANY
        for match_field in msg.match.fields:
            if match_field.header == self.dp.ofproto.OXM_OF_IN_PORT:
                in_port = match_field.value
                break
        return in_port

    def _mod_flow(self, command, cookie, priority, eth_type=None, eth_dst=None,
                  dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                  dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                  in_port=None):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        # Match
        match = ofp_parser.OFPMatch()
        if eth_type:
            match.set_dl_type(eth_type)
        if eth_dst:
            if type(eth_dst) == str:
                eth_dst = haddr_to_bin(eth_dst)
            match.set_dl_dst(eth_dst)
        if dl_vlan:
            match.set_vlan_vid(dl_vlan)
        if in_port:
            match.set_in_port(in_port)
        if nw_proto:
            match.set_ip_proto(nw_proto)
        # TODO: Handle ipv6 address
        if nw_src:
            match.set_ipv4_src_masked(ipv4_text_to_int(nw_src),
                                      mask_ntob(src_mask))
        if nw_dst:
            match.set_ipv4_dst_masked(ipv4_text_to_int(nw_dst),
                                      mask_ntob(dst_mask))
        if nw_proto:
            if eth_type == ether.ETH_TYPE_IP:
                match.set_ip_proto(nw_proto)
            elif eth_type == ether.ETH_TYPE_ARP:
                match.set_arp_opcode(nw_proto)

        # Instructions
        actions = actions or []
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        m = ofp_parser.OFPFlowMod(self.dp, cookie, 0, 0, command, idle_timeout,
                                  0, priority, ofp.OFP_NO_BUFFER, ofp.OFPP_ANY,
                                  ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(m)

    def set_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                           dst_macs, command):
        ofp_parser = self.dp.ofproto_parser
        actions = [[ofp_parser.OFPActionSetField(eth_src=src_macs[i]),
                    ofp_parser.OFPActionSetField(eth_dst=dst_macs[i]),
                    ofp_parser.OFPActionOutput(port)]
                   for i, port in enumerate(out_ports)]
        buckets = [ofp_parser.OFPBucket(0, port, self.dp.ofproto.OFPG_ANY,
                                        actions[i]) for
                   i, port in enumerate(watch_ports)]
        req = ofp_parser.OFPGroupMod(self.dp,
                                     command,
                                     self.dp.ofproto.OFPGT_FF,
                                     group_id,
                                     buckets)
        self.dp.send_msg(req)

    def modify_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                              dst_macs):
        self.set_failover_group(group_id, watch_ports, out_ports, src_macs,
                                dst_macs, self.dp.ofproto.OFPGC_MODIFY)

    def add_failover_group(self, group_id, watch_ports, out_ports, src_macs,
                           dst_macs):
        self.set_failover_group(group_id, watch_ports, out_ports, src_macs,
                                dst_macs, self.dp.ofproto.OFPGC_ADD)


@OfCtl.register_of_version(ofproto_v1_3.OFP_VERSION)
class OfCtl_v1_3(OfCtl_v1_2):
    def __init__(self, dp, logger):
        super(OfCtl_v1_3, self).__init__(dp, logger)

    def get_async_config_request(self):
        req = self.ofp_parser.OFPGetAsyncRequest(self.dp)
        self.dp.send_msg(req)

    def set_async_config(self, packet_in_mask=None, port_status_mask=None,
                         flow_removed_mask=None):
        return self.set_async_config_restrict(
            packet_in_mask=packet_in_mask,
            port_status_mask=port_status_mask,
            flow_removed_mask=flow_removed_mask,
            ofp=self.ofp,
            ofp_parser=self.ofp_parser)

    def set_async_config_restrict(self, packet_in_mask=None,
                                  port_status_mask=None,
                                  flow_removed_mask=None, ofp=ofproto_v1_3,
                                  ofp_parser=ofproto_v1_3_parser):
        if packet_in_mask is None:
            packet_in_mask = (1 << ofp.OFPR_ACTION |
                              1 << ofp.OFPR_INVALID_TTL)
        if port_status_mask is None:
            port_status_mask = (1 << ofp.OFPPR_ADD |
                                1 << ofp.OFPPR_DELETE |
                                1 << ofp.OFPPR_MODIFY)
        if flow_removed_mask is None:
            flow_removed_mask = (1 << ofp.OFPRR_IDLE_TIMEOUT |
                                 1 << ofp.OFPRR_HARD_TIMEOUT |
                                 1 << ofp.OFPRR_DELETE)
        m = ofp_parser.OFPSetAsync(
            self.dp, [packet_in_mask, 0], [port_status_mask, 0],
            [flow_removed_mask, 0])
        self.dp.send_msg(m)

    def async_config_to_str(self, msg):
        return ('packet_in_mask=0x%08x:0x%08x '
                'port_status_mask=0x%08x:0x%08x '
                'flow_removed_mask=0x%08x:0x%08x' % (
                    msg.packet_in_mask[0],
                    msg.packet_in_mask[1],
                    msg.port_status_mask[0],
                    msg.port_status_mask[1],
                    msg.flow_removed_mask[0],
                    msg.flow_removed_mask[1]))


@OfCtl.register_of_version(ofproto_v1_4.OFP_VERSION)
class OfCtl_v1_4(OfCtl_v1_3):
    def __init__(self, dp, logger):
        super(OfCtl_v1_4, self).__init__(dp, logger)

    def async_config_to_str(self, msg):
        return repr(msg.properties)

    def get_packet_in_inport(self, msg):
        return msg.match.get('in_port', self.ofp.OFPP_ANY)

    def set_async_config(self, packet_in_mask=None, port_status_mask=None,
                         flow_removed_mask=None):
        # Open vSwitch 2.3.0 doesn't support OpenFlow 1.4's SetAsyncConfig
        super(OfCtl_v1_4, self).set_async_config_restrict(
            packet_in_mask=packet_in_mask,
            port_status_mask=port_status_mask,
            flow_removed_mask=flow_removed_mask)
        # if packet_in_mask is None:
        # packet_in_mask = (1 << self.ofp.OFPR_TABLE_MISS |
        # 1 << self.ofp.OFPR_APPLY_ACTION |
        # 1 << self.ofp.OFPR_INVALID_TTL |
        # 1 << self.ofp.OFPR_ACTION_SET |
        # 1 << self.ofp.OFPR_GROUP |
        # 1 << self.ofp.OFPR_PACKET_OUT)
        # if port_status_mask is None:
        # port_status_mask = (1 << self.ofp.OFPPR_ADD |
        # 1 << self.ofp.OFPPR_DELETE |
        # 1 << self.ofp.OFPPR_MODIFY)
        # if flow_removed_mask is None:
        # flow_removed_mask = (1 << self.ofp.OFPRR_IDLE_TIMEOUT |
        # 1 << self.ofp.OFPRR_HARD_TIMEOUT |
        # 1 << self.ofp.OFPRR_DELETE |
        # 1 << self.ofp.OFPRR_GROUP_DELETE |
        # 1 << self.ofp.OFPRR_METER_DELETE |
        # 1 << self.ofp.OFPRR_EVICTION)
        # properties = [
        # self.ofp_parser.OFPAsyncConfigPropReasons(
        # self.ofp.OFPACPT_PACKET_IN_MASTER, mask=packet_in_mask),
        # self.ofp_parser.OFPAsyncConfigPropReasons(
        # self.ofp.OFPACPT_PORT_STATUS_MASTER, mask=port_status_mask),
        #     self.ofp_parser.OFPAsyncConfigPropReasons(
        # self.ofp.OFPACPT_FLOW_REMOVED_MASTER, mask=flow_removed_mask)]
        # req = self.ofp_parser.OFPSetAsync(self.dp, properties)
        # self.dp.send_msg(req)

    def _mod_flow(self, command, cookie, priority, eth_type=None, eth_dst=None,
                  dl_vlan=None, nw_src=None, src_mask=32, nw_dst=None,
                  dst_mask=32, nw_proto=None, idle_timeout=0, actions=None,
                  in_port=None):
        ofp = self.ofp
        ofp_parser = self.ofp_parser

        # Match
        match_params = {}
        if eth_type:
            match_params['eth_type'] = eth_type
        if eth_dst:
            match_params['eth_dst'] = eth_dst
        if dl_vlan:
            match_params['vlan_vid'] = dl_vlan
        if in_port:
            match_params['in_port'] = in_port
        if nw_src:
            match_params['ipv4_src'] = (
                nw_src, mask_ntob(src_mask))
        if nw_dst:
            match_params['ipv4_dst'] = (
                nw_dst, mask_ntob(dst_mask))
        if nw_proto:
            match_params['ip_proto'] = nw_proto
            if eth_type == ether.ETH_TYPE_ARP:
                match_params['arp_op'] = nw_proto
        match = ofp_parser.OFPMatch(**match_params)

        # Instructions
        actions = actions or []
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
        m = ofp_parser.OFPFlowMod(datapath=self.dp,
                                  cookie=cookie,
                                  cookie_mask=0,
                                  table_id=0,
                                  command=command,
                                  idle_timeout=idle_timeout,
                                  hard_timeout=0,
                                  priority=priority,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  out_port=ofp.OFPP_ANY,
                                  out_group=ofp.OFPG_ANY,
                                  flags=0,
                                  match=match,
                                  instructions=inst)
        self.dp.send_msg(m)
