import logging

from ryu.lib.packet.arp import ARP_REPLY, ARP_REQUEST
from ryu.lib.packet.icmp import icmp, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REPLY, \
    ICMP_TIME_EXCEEDED, ICMP_TTL_EXPIRED_CODE, ICMP_PORT_UNREACH_CODE, \
    ICMP_DEST_UNREACH
from ryu.lib import hub
from ryu.lib import mac as mac_lib
from ryu.lib.packet import packet
from ryu.ofproto import ether

from ryuo.constants import PRIORITY_MAC_LEARNING, \
    PRIORITY_IP_HANDLING, PRIORITY_L2_SWITCHING, ARP, IPV4, ICMP, TCP, UDP, \
    PRIORITY_TYPE_ROUTE, PRIORITY_ARP_HANDLING, PRIORITY_DEFAULT_ROUTING, \
    PRIORITY_NORMAL, MAX_SUSPENDPACKETS, PRIORITY_IMPLICIT_ROUTING, \
    IDLE_TIMEOUT, ETHERNET, ARP_REPLY_TIMER, PRIORITY_STATIC_ROUTING, \
    PRIORITY_VLAN_SHIFT, PRIORITY_NETMASK_SHIFT, PORT_UP, PORT_DOWN
from ryuo.local.ofctl import OfCtl
from ryuo.utils import nw_addr_aton, mask_ntob, ipv4_apply_mask, ip_addr_ntoa


class Router():
    def __init__(self, dp, routing):
        self.dp = dp
        self._init_logger()
        self._routing = routing
        self.ports = Ports(dp.ports)
        self.ofctl = OfCtl(dp, self._logger)
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self._init_flows()
        self._group_id = 1

    def set_port_address(self, ip_str, port_no):
        nw, mask, ip = nw_addr_aton(ip_str)
        # Check overlaps
        mask_b = mask_ntob(mask)
        for port in self.ports.values():
            if port.ip is None:
                continue
            port_mask = mask_ntob(port.netmask)
            if (port.nw == ipv4_apply_mask(ip, port.netmask)
                or nw == ipv4_apply_mask(port.ip, mask)):
                return None
        if port_no not in self.ports.keys():
            return None
        self.ports[port_no].set_ip(nw, mask, ip)
        self._logger.info('Setting IP %s/%d of %s', ip, mask, nw)

        priority, dummy = get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packet_in_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=nw, dst_mask=mask)
        self._logger.info('Set MAC learning for %s', ip)
        # IP handling
        priority, dummy = get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packet_in_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=ip)
        self._logger.info('Set IP handling for %s', ip)
        # L2 switching
        out_port = self.ofctl.dp.ofproto.OFPP_NORMAL
        priority, dummy = get_priority(PRIORITY_L2_SWITCHING)
        self.ofctl.set_routing_flow(
            0, priority, out_port,
            nw_src=nw, src_mask=mask,
            nw_dst=nw, dst_mask=mask)
        self._logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                          0)
        # Send GARP
        self.send_arp_request(ip, ip)
        return {'ip': ip, 'mask': mask, 'nw': nw}

    def delete(self):
        return

    def send_arp_request(self, src_ip, dst_ip, in_port=None, port=None):
        ports = [port]
        if port is None:
            ports = self.ports
        for send_port in ports.values():
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(ARP_REQUEST, src_mac, dst_mac, src_ip,
                                    dst_ip, arp_target_mac, inport, output)
        self._logger.info('Sending ARP request.')

    def packet_in(self, msg):
        pkt = packet.Packet(msg.data)
        headers = dict((p.protocol_name, p)
                       for p in pkt.protocols if type(p) != str)
        ofproto = self.dp.ofproto
        if msg.reason == ofproto.OFPR_INVALID_TTL:
            return self._packet_in_invalid_ttl(msg, headers)
        if ARP in headers:
            return self._packet_in_arp(msg, headers)
        if IPV4 in headers:
            if headers[IPV4].dst in self.get_ips():
                if ICMP in headers:
                    return self._packet_in_icmp_req(msg, headers)
                elif TCP in headers or UDP in headers:
                    return self._packet_in_tcp_udp(msg, headers)
            return self._packet_in_to_node(msg, headers)

    def on_port_status_change(self, msg):
        self._logger.info('Received port status message.')
        ofp = self.dp.ofproto
        port_no = msg.desc.port_no
        if port_no not in self.ports:
            return
        if msg.reason == ofp.OFPPR_ADD:
            self._on_port_up(port_no)
        elif msg.reason == ofp.OFPPR_DELETE:
            self._on_port_down(port_no)
        elif msg.reason == ofp.OFPPR_MODIFY:
            if msg.desc.state & ofp.OFPPS_LINK_DOWN != 0:
                self._on_port_down(port_no)
            else:
                self._on_port_up(port_no)
        if msg.reason != ofp.OFPPR_ADD and msg.reason != ofp.OFPPR_DELETE \
                and msg.reason != ofp.OFPPR_MODIFY:
            self._logger.warning('Unknown port status message.')
            return

    def _on_port_down(self, port_no):
        port = self.ports.get(port_no)
        if port is None:
            self._logger.error('Unknow port %d.', port_no)
        if port.status == PORT_DOWN:
            self._logger.warning('Port %d already down.', port_no)
        port.status = PORT_DOWN
        self._logger.info('Port %d down.', port_no)

    def _on_port_up(self, port_no):
        port = self.ports.get(port_no)
        if port is None:
            self._logger.error('Unknow port %d.', port_no)
        if port.status == PORT_UP:
            self._logger.warning('Port %d already up.', port_no)
        port.status = PORT_UP
        self._logger.info('Port %d up.', port_no)

    def get_ips(self):
        return [port.ip for port in self.ports.values()]

    def send_icmp_unreach_error(self, packet_buffer):
        # Send ICMP host unreach error.
        src_ip = self._get_send_port_ip(packet_buffer.header_list)
        if src_ip is not None:
            self.ofctl.reply_icmp(packet_buffer.in_port,
                                 packet_buffer.header_list,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=packet_buffer.data,
                                 src_ip=src_ip)
            self._logger.info('Send ICMP unreachable to %s',
                              packet_buffer.dst_ip)

    def set_group(self, src_macs, dst_macs, watch_ports, out_ports):
        self.ofctl.add_failover_group(self._group_id, watch_ports, out_ports,
                                      src_macs,
                             dst_macs)
        self._group_id += 1
        return self._group_id - 1

    def install_routing_entry(self, route):
        priority, dummy = get_priority(PRIORITY_TYPE_ROUTE, route=route)
        self.ofctl.set_routing_flow(0, priority, route.out_port,
                                    src_mac=route.src_mac,
                                    dst_mac=route.gateway_mac,
                                    nw_dst=route.dst_ip,
                                    dst_mask=route.netmask,
                                    dec_ttl=True,
                                    in_port=route.in_port,
                                    out_group=route.out_group)

    def _install_routing_entry(self, route, output, src_mac, dst_mac):
        priority, dummy = get_priority(PRIORITY_TYPE_ROUTE, route=route)
        self.ofctl.set_routing_flow(0, priority, output,
                                    src_mac=src_mac,
                                    dst_mac=dst_mac,
                                    nw_dst=route.dst_ip,
                                    dst_mask=route.netmask,
                                    dec_ttl=True)
        self._logger.info('Set flow to %s via %s', route.dst_ip,
                          route.gateway_ip)

    def _init_logger(self):
        self._logger = logging.getLogger('%s %d' % (__name__, self.dp.id))
        formatter = logging.Formatter('[%(name)s][%(levelname)s]: %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._logger.propagate = False

    def _init_flows(self):
        cookie = 0
        self.ofctl.set_sw_config_for_ttl()
        # ARP
        priority, dummy = get_priority(PRIORITY_ARP_HANDLING)
        self.ofctl.set_packet_in_flow(cookie, priority,
                                     dl_type=ether.ETH_TYPE_ARP)
        # Drop by default 
        priority, dummy = get_priority(PRIORITY_DEFAULT_ROUTING)
        outport = None
        self.ofctl.set_routing_flow(cookie, priority, outport)
        self.ofctl.set_routing_flow_v6(cookie, priority, outport)
        # Set flow: L2 switching (normal)
        priority, dummy = get_priority(PRIORITY_NORMAL)
        self.ofctl.set_normal_flow(cookie, priority)
        self._logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                          cookie)

    def _packet_in_arp(self, msg, headers):
        src_port = self.ports.get_by_ip(headers[ARP].src_ip)
        if src_port is None:
            return
        if self._routing.update_mac(self, msg, headers) is False:
            self._logger.info('Src %s is unknown, learning its mac',
                              headers[ARP].src_ip)
            self._learning_host_mac(msg, headers)
        in_port = self.ofctl.get_packet_in_inport(msg)
        src_ip = headers[ARP].src_ip
        dst_ip = headers[ARP].dst_ip
        self._logger.info('Receive ARP form %s to %s', src_ip, dst_ip)
        rt_ips = self.get_ips()
        if src_ip == dst_ip:
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
            self.ofctl.send_packet_out(in_port, output, msg.data)
        elif dst_ip not in rt_ips:
            dst_port = self.ports.get_by_ip(dst_ip)
            if dst_port is not None and src_port.ip == dst_port.ip:
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)
        else:
            if headers[ARP].opcode == ARP_REQUEST:
                src_mac = headers[ARP].src_mac
                dst_mac = self.ports[in_port].mac
                arp_target_mac = dst_mac
                output = in_port
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                self.ofctl.send_arp(ARP_REPLY, dst_mac, src_mac, dst_ip,
                                    src_ip, arp_target_mac, in_port, output)
                self._logger.info('Sending ARP reply to %s via port %d',
                                  dst_ip,
                                  output)
            elif headers[ARP].opcode == ARP_REPLY:
                packet_list = self.packet_buffer.get_data(src_ip)
                if packet_list:
                    for suspend_packet in packet_list:
                        self.packet_buffer.delete(pkt=suspend_packet)
                    output = self.ofctl.dp.ofproto.OFPP_TABLE
                    for suspend_packet in packet_list:
                        self.ofctl.send_packet_out(suspend_packet.in_port,
                                                   output,
                                                   suspend_packet.data)

    def _packet_in_invalid_ttl(self, msg, headers):
        srcip = ip_addr_ntoa(headers[IPV4].src)
        self._logger.info('Receive invalid ttl packet from %s', srcip)

        in_port = self.ofctl.get_packet_in_inport(msg)
        src_ip = self.ports[in_port].ip
        if src_ip == srcip:
            self._logger.info('Invalid packet from my self.')
            return
        if src_ip is not None:
            self.ofctl.reply_icmp(in_port, headers, ICMP_TIME_EXCEEDED,
                                 ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data, src_ip=src_ip)
            self._logger.info('Send ICMP time exceeded to %s from %s', srcip,
                              src_ip)

    def _packet_in_to_node(self, msg, headers):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self._logger.info('Suspend pakcet drop')
            return
        in_port = self.ofctl.get_packet_in_inport(msg)
        src_ip = headers[IPV4].src
        dst_ip = headers[IPV4].dst
        port = self.ports.get_by_ip(dst_ip)
        if port is not None:
            src_ip = port.ip
        else:
            route = self._routing.get_routing_data_by_dst_ip(self.dp.id,
                                                             dst_ip)
            if route is not None:
                self._logger.info('Receive IP packet from %s to %s.', src_ip,
                                  dst_ip)
                # Which port is in the same network with the gateway
                gateway = self.ports.get_by_ip(route.gateway_ip)
                if gateway is not None:
                    src_ip = gateway.ip
                    dst_ip = route.gateway_ip
                    self._logger.info('Gateway added: %s, route: %s', src_ip,
                                      dst_ip)
        if src_ip is not None:
            self.packet_buffer.add(in_port, headers, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port)
            self._logger.info('Send ARP request')

    def _packet_in_icmp_req(self, msg, headers):
        self._logger.info('Receive ICMP request from %s', headers[IPV4].src)
        in_port = self.ofctl.get_packet_in_inport(msg)
        self.ofctl.reply_icmp(in_port, headers, ICMP_ECHO_REPLY,
                             ICMP_ECHO_REPLY_CODE,
                             icmp_data=headers[ICMP].data)

    def _packet_in_tcp_udp(self, msg, headers):
        in_port = self.ofctl.get_packet_in_inport(msg)
        self.ofctl.reply_icmp(in_port, headers, ICMP_DEST_UNREACH,
                             ICMP_PORT_UNREACH_CODE, msg_data=msg.data)

    def _learning_host_mac(self, msg, header_list):
        # Set flow: routing to internal Host.
        out_port = self.ofctl.get_packet_in_inport(msg)
        src_mac = header_list[ARP].src_mac
        dst_mac = self.ports[out_port].mac
        src_ip = header_list[ARP].src_ip

        gateways = self._routing.get_gateways(self.dp.id)
        if src_ip not in gateways:
            port = self.ports.get_by_ip(src_ip)
            if port is not None:
                # cookie = self._id_to_cookie(REST_ADDRESSID,
                # address.address_id)
                priority, dummy = get_priority(PRIORITY_IMPLICIT_ROUTING)
                self.ofctl.set_routing_flow(0, priority,
                                            out_port,
                                            src_mac=dst_mac, dst_mac=src_mac,
                                            nw_dst=src_ip,
                                            idle_timeout=IDLE_TIMEOUT,
                                            dec_ttl=True)
                self._logger.info('Set implicit routing flow to %s', src_ip)

    def _get_send_port_ip(self, headers):
        try:
            src_mac = headers[ETHERNET].src
            if IPV4 in headers:
                src_ip = headers[IPV4].src
            else:
                src_ip = headers[ARP].src_ip
        except KeyError:
            self._logger.info('Receive unsupported packet.')
            return

        port = self.ports.get_by_ip(src_ip)
        if port is not None:
            return port.ip
        else:
            route = self._routing.get_routing_data_by_gateway_mac(self.dp.id,
                                                                  src_mac)
            if route is not None:
                port = self.ports.get_by_ip(route.gateway_ip)
                if port is not None:
                    return port.ip

        self._logger.info('Receive packet from unknown IP %s',
                          ip_addr_ntoa(src_ip))


class Ports(dict):
    def __init__(self, ports):
        super(Ports, self).__init__()
        for port in ports.values():
            self[port.port_no] = Port(port.port_no, port.hw_addr)

    def get_by_ip(self, ip):
        for port in self.values():
            if port.ip is None:
                continue
            if ipv4_apply_mask(ip, port.netmask) == port.nw:
                return port

    def get_by_mac(self, mac):
        for port in self.values():
            if port.mac == mac:
                return port


class Port(object):
    def __init__(self, port_no, mac):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = mac
        self.ip = None
        self.nw = None
        self.netmask = None
        self.links = {}
        self.status = PORT_UP

    def set_ip(self, nw, mask, ip):
        self.nw = nw
        self.netmask = mask
        self.ip = ip

    def add_link(self, link):
        self.links[link.dst.hw_addr] = link


class SuspendPacketList(list):
    def __init__(self, timeout_function):
        super(SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function

    def add(self, in_port, header_list, data):
        suspend_pkt = SuspendPacket(in_port, header_list, data,
                                    self.wait_arp_reply_timer)
        self.append(suspend_pkt)

    def delete(self, pkt=None, del_addr=None):
        if pkt is not None:
            del_list = [pkt]
        else:
            assert del_addr is not None
            del_list = [pkt for pkt in self if pkt.dst_ip in del_addr]

        for pkt in del_list:
            self.remove(pkt)
            hub.kill(pkt.wait_thread)
            pkt.wait_thread.wait()

    def get_data(self, dst_ip):
        return [pkt for pkt in self if pkt.dst_ip == dst_ip]

    def wait_arp_reply_timer(self, suspend_pkt):
        hub.sleep(ARP_REPLY_TIMER)
        if suspend_pkt in self:
            self.timeout_function(suspend_pkt)
            self.delete(pkt=suspend_pkt)


class SuspendPacket(object):
    def __init__(self, in_port, header_list, data, timer):
        super(SuspendPacket, self).__init__()
        self.in_port = in_port
        self.dst_ip = header_list[IPV4].dst
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)


def get_priority(priority_type, vid=0, route=None):
    log_msg = None
    priority = priority_type

    if priority_type == PRIORITY_TYPE_ROUTE:
        assert route is not None
        if route.dst_ip:
            priority_type = PRIORITY_STATIC_ROUTING
            priority = priority_type + route.netmask
            log_msg = 'static routing'
        else:
            priority_type = PRIORITY_DEFAULT_ROUTING
            priority = priority_type
            log_msg = 'default routing'

    if vid or priority_type == PRIORITY_IP_HANDLING:
        priority += PRIORITY_VLAN_SHIFT

    if priority_type > PRIORITY_STATIC_ROUTING:
        priority += PRIORITY_NETMASK_SHIFT

    return priority, log_msg


