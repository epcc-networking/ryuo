import time

import Pyro4
from ryu.controller import ofp_event, handler
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet.arp import ARP_REQUEST, ARP_REPLY
from ryu.lib.packet.icmp import icmp, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REPLY, \
    ICMP_PORT_UNREACH_CODE, ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, \
    ICMP_TTL_EXPIRED_CODE
from ryu.ofproto import ether
from ryu.lib import mac as mac_lib
from ryu.lib import hub
from ryu.topology.event import EventPortDelete, EventPortAdd, \
    EventPortModify, \
    EventLinkAdd, EventLinkDelete

from ryuo.constants import IPV4, ICMP, UDP, TCP, PRIORITY_TYPE_ROUTE, \
    PRIORITY_STATIC_ROUTING, PRIORITY_DEFAULT_ROUTING, PRIORITY_IP_HANDLING, \
    PRIORITY_VLAN_SHIFT, PRIORITY_NETMASK_SHIFT, PRIORITY_ARP_HANDLING, \
    PRIORITY_NORMAL, PRIORITY_IMPLICIT_ROUTING, ARP_REPLY_TIMER, \
    MAX_SUSPENDPACKETS, PRIORITY_MAC_LEARNING, PRIORITY_L2_SWITCHING, \
    PORT_UP, \
    ARP
from ryuo.local.local_controller import LocalController
from ryuo.config import ARP_EXPIRE_SECOND
from ryuo.utils import mask_ntob, nw_addr_aton, ipv4_apply_mask, ip_addr_ntoa


class KFRoutingLocal(LocalController):
    def __init__(self, *args, **kwargs):
        super(KFRoutingLocal, self).__init__(*args, **kwargs)
        self.ports = _Ports()  # port_no -> Port
        self.arp_table = _ArpTable()
        self.groups = None
        self.routing_table = _RoutingTable(self._logger)
        self.packet_buffer = _SuspendPacketList(
            self.send_icmp_unreachable_error)

    @Pyro4.expose
    def add_route(self, dst_ip, in_port, output_ports):
        group = self.groups.add_entry(output_ports)
        route = self.routing_table.add_entry(dst_ip=dst_ip,
                                             in_port=in_port,
                                             out_group=group.id)
        self._install_routing_entry(route)

    @Pyro4.expose
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

        priority, dummy = _get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packetin_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=nw, dst_mask=mask)
        self._logger.info('Set MAC learning for %s', ip)
        # IP handling
        priority, dummy = _get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packetin_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=ip)
        self._logger.info('Set IP handling for %s', ip)
        # L2 switching
        out_port = self.ofctl.dp.ofproto.OFPP_NORMAL
        priority, dummy = _get_priority(PRIORITY_L2_SWITCHING)
        self.ofctl.set_routing_flow(
            0, priority, out_port,
            nw_src=nw, src_mask=mask,
            nw_dst=nw, dst_mask=mask)
        self._logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                          0)
        # Send GARP
        self.send_arp_request(ip, ip)
        return {'ip': ip, 'mask': mask, 'nw': nw}

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
                output_port = send_port.port_no
                self.ofctl.send_arp(ARP_REQUEST, src_mac, dst_mac, src_ip,
                                    dst_ip, arp_target_mac, inport,
                                    output_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
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

    @handler.set_ev_cls(EventPortDelete)
    def _on_port_deleted(self, ev):
        del self.ports[ev.port.port_no]

    @handler.set_ev_cls(EventPortAdd)
    def _on_port_added(self, ev):
        self.ports[ev.port.port_no] = _Port(ev.port.port_no, ev.port.hw_addr)

    @handler.set_ev_cls(EventPortModify)
    def _on_port_modified(self, ev):
        port = ev.port
        if port.is_down():
            self.ports[port.port_no].down()
        else:
            self.ports[port.port_no].up()

    @handler.set_ev_cls(EventLinkAdd)
    def _on_link_added(self, ev):
        dst_port_no = ev.link.dst.port_no
        peer_mac = ev.link.src.hw_addr
        old_peer_mac = self.ports[dst_port_no].peer_mac
        if peer_mac != old_peer_mac:
            # TODO: update flow entries
            pass
        self.ports[dst_port_no].set_peer_mac(peer_mac)

    @handler.set_ev_cls(EventLinkDelete)
    def _on_link_deleted(self, ev):
        pass

    def get_ips(self):
        return [port.ip for port in self.ports.values()]

    def init_switch(self):
        cookie = 0
        self.ofctl.set_sw_config_for_ttl()
        priority, dummy = _get_priority(PRIORITY_ARP_HANDLING)
        self.ofctl.set_packet_in_flow(cookie, priority,
                                      dl_type=ether.ETH_TYPE_ARP)
        priority, dummy = _get_priority(PRIORITY_DEFAULT_ROUTING)
        self.ofctl.set_routing_flow(cookie, priority, None)
        self.ofctl.set_routing_flow_v6(cookie, priority, None)
        priority, dummy = _get_priority(PRIORITY_NORMAL)
        self.ofctl.set_normal_flow(cookie, priority)

    def _install_routing_entry(self, route):
        priority, dummy = _get_priority(PRIORITY_TYPE_ROUTE, route=route)
        self.ofctl.set_routing_flow(0,
                                    priority,
                                    route.out_port,
                                    nw_dst=route.dst_ip,
                                    dst_mask=route.netmask,
                                    dec_ttl=True,
                                    in_port=route.in_port,
                                    out_group=route.out_group)

    def _register(self, dp):
        super(KFRoutingLocal, self)._switch_enter(dp)
        for ofpport in dp.ports:
            self.ports[ofpport.port_no] = _Port(ofpport.port_no,
                                                ofpport.hw_addr)
        self.groups = _GroupTable(self.ofctl, self.ports)
        self.routing_table.clear()

    def _unregister(self):
        super(KFRoutingLocal, self)._switch_leave()
        self.groups = None
        self.arp_table.clear()

    def _packet_in_arp(self, msg, headers):
        src_port = self.ports.get_by_ip(headers[ARP].src_ip)
        if src_port is None:
            return
        self._learn_host_mac(msg, headers)
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = headers[ARP].src_ip
        dst_ip = headers[ARP].dst_ip
        self._logger.info('Receive ARP from %s to %s', src_ip, dst_ip)
        if headers[ARP].opcode == ARP_REQUEST:
            src_mac = headers[ARP].src_mac
            dst_mac = self.ports[in_port].mac
            arp_target_mac = dst_mac
            self.ofctl.send_arp(ARP_REPLY,
                                dst_mac,
                                src_mac,
                                dst_ip,
                                src_ip,
                                arp_target_mac,
                                self.dp.ofproto.OFPP_CONTROLLER,
                                in_port)
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

    def _learn_host_mac(self, msg, headers):
        # TODO: Only install flow when ARP table changed
        out_port = self.ofctl.get_packetin_inport(msg)
        src_mac = headers[ARP].src_mac
        dst_mac = self.ports[out_port].mac
        src_ip = headers[ARP].src_ip
        self.arp_table.add_entry(src_ip, src_mac)
        priority, dummy = _get_priority(PRIORITY_IMPLICIT_ROUTING)
        self.ofctl.set_routing_flow(0,
                                    priority,
                                    out_port,
                                    src_mac=dst_mac,
                                    dst_mac=src_mac,
                                    nw_dst=src_ip,
                                    idle_timeout=ARP_EXPIRE_SECOND,
                                    dec_ttl=True)
        self._logger.info('Set implicit routing flow to %s', src_ip)

    def _packet_in_invalid_ttl(self, msg, headers):
        src_ip = headers[IPV4].src
        self._logger('Received packet with invalid ttl from %s.', src_ip)
        in_port = self.ofctl.get_packetin_inport(msg)
        in_ip = self.ports[in_port].ip
        if src_ip in self.get_ips():
            self._logger.warning(
                'Receive packet with invalid ttl from myself.')
            return
        if in_ip is not None:
            self.ofctl.send_icmp(in_port,
                                 headers,
                                 ICMP_TIME_EXCEEDED,
                                 ICMP_TTL_EXPIRED_CODE,
                                 msg_data=msg.data,
                                 src_ip=in_ip)
            self._logger.info('Send ICMP time exceeded from %s to %s.',
                              in_ip,
                              src_ip)

    def _packet_in_icmp_req(self, msg, headers):
        self._logger.info('Receive ICMP request from %s', headers[IPV4].src)
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port,
                             headers,
                             ICMP_ECHO_REPLY,
                             ICMP_ECHO_REPLY_CODE,
                             icmp_data=headers[ICMP].data)

    def _packet_in_tcp_udp(self, msg, headers):
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port,
                             headers,
                             ICMP_DEST_UNREACH,
                             ICMP_PORT_UNREACH_CODE,
                             msg_data=msg.data)

    def _packet_in_to_node(self, msg, headers):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self._logger.warning('Suspend packet drop.')
            return
        in_port = self.ofctl.get_packetin_inport(msg)
        dst_ip = headers[IPV4].dst
        port = self.ports.get_by_ip(dst_ip)
        if port is not None:
            out_ip = port.ip
            if self.arp_table.get(dst_ip) is not None:
                self._logger.debug('Find mac in arp table')
                self.ofctl.send_packet_out(in_port,
                                           port,
                                           msg.data)
            else:
                self.packet_buffer.add(in_port, headers, msg.data)
                self.send_arp_request(out_ip, dst_ip, in_port=in_port)
                self._logger.info('Send ARP request for %s', dst_ip)
        else:
            self._logger.warning('Unknown dst ip %s', dst_ip)

    def _send_icmp_unreachable_error(self, in_port, headers, data, dst_ip):
        src_ip = self._get_send_port_ip(headers)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port,
                                 headers,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=data,
                                 src_ip=src_ip)
            self._logger.info('Send ICMP unreachable to %s', dst_ip)

    def send_icmp_unreachable_error(self, suspended_packet):
        return self._send_icmp_unreachable_error(suspended_packet.in_port,
                                                 suspended_packet.header_list,
                                                 suspended_packet.data,
                                                 suspended_packet.dst_ip)

    def _get_send_port_ip(self, headers):
        if IPV4 in headers:
            src_ip = headers[IPV4].src
        elif ARP in headers:
            src_ip = headers[ARP].src_ip
        else:
            self._logger.warning('Receive unsupported packet.')
            return
        port = self.ports.get_by_ip(src_ip)
        if port is not None:
            return port.ip
        else:
            output_port = self._get_output_port(src_ip)
            if output_port is not None:
                return output_port.ip
        self._logger.info('Receive packet from unknown IP %s', src_ip)

    def _get_output_port(self, dst_ip):
        route = self.routing_table.get_data_by_dst_ip(dst_ip)
        if route is None:
            return None
        group = self.groups[route.out_group]
        for port_no in group.output_ports:
            if self.ports[port_no].status == PORT_UP:
                return self.ports[port_no]
        return None


class _ArpEntry(object):
    def __init__(self, ip, mac):
        super(_ArpEntry, self).__init__()
        self.ip = ip
        self.mac = mac
        self.refreshed_at = time.time()

    def is_expired(self):
        return time.time() - self.refreshed_at > ARP_EXPIRE_SECOND

    def refresh(self):
        self.refreshed_at = time.time()


class _ArpTable(dict):
    def __init__(self):
        super(_ArpTable, self).__init__()

    def __getitem__(self, item):
        entry = super(_ArpTable, self).__getitem__(item)
        if entry is not None and not entry.is_expired():
            return entry

    def get(self, k, d=None):
        if k in self.keys():
            item = self[k]
            if not item.is_expired():
                return item
        return d

    def add_entry(self, ip, mac):
        self[ip] = _ArpEntry(ip, mac)


def _get_priority(priority_type, vid=0, route=None):
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


class _SuspendPacketList(list):
    def __init__(self, timeout_function):
        super(_SuspendPacketList, self).__init__()
        self.timeout_function = timeout_function

    def add(self, in_port, header_list, data):
        suspend_pkt = _SuspendPacket(in_port, header_list, data,
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


class _SuspendPacket(object):
    def __init__(self, in_port, header_list, data, timer):
        super(_SuspendPacket, self).__init__()
        self.in_port = in_port
        self.dst_ip = header_list[IPV4].dst
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)


class _Group(object):
    def __init__(self, group_id, watch_ports, output_ports, inport,
                 group_table):
        super(_Group, self).__init__()
        self.id = group_id
        self.output_ports = output_ports
        self.watch_ports = watch_ports
        self.inport = inport
        self.group_table = group_table

    def install(self):
        self._set(self.group_table.ofctl.dp.ofproto.OFPGC_ADD)

    def update(self):
        self._set(self.group_table.ofctl.dp.ofproto.OFPGC_MODIFY)

    def _set(self, command):
        ofctl = self.group_table.ofctl
        ports = self.group_table.ports
        output_ports = [
            port_no if port_no != self.inport else ofctl.dp.ofproto.OFPP_INPORT
            for port_no in self.output_ports]
        src_macs = [ports[port_no].mac for port_no in self.output_ports]
        dst_macs = [ports[port_no].peer_mac for port_no in self.output_ports]
        ofctl.set_failover_group(self.id, self.watch_ports, output_ports,
                                 src_macs, dst_macs, command)


class _GroupTable(dict):
    def __init__(self, ofctl, ports):
        super(_GroupTable, self).__init__()
        self.group_id = 0
        self.ofctl = ofctl
        self.ports = ports

    def clear(self):
        super(_GroupTable, self).clear()

    def add_entry(self, output_ports, inport):
        group = _Group(self.group_id, output_ports, output_ports, inport, self)
        self[self.group_id] = group
        self.group_id += 1
        return group

    def update_entry(self, port_no):
        for group in self.values():
            if port_no in group.output_ports:
                group.update()


class _Route(object):
    def __init__(self, route_id, dst_ip, netmask, src_mac,
                 in_port, out_group):
        super(_Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.src_mac = src_mac
        self.in_port = in_port
        self.out_group = out_group


class _RoutingTable(dict):
    def __init__(self, logger):
        super(_RoutingTable, self).__init__()
        self._logger = logger
        self.route_id = 0

    def add_entry(self, dst_ip, src_mac, in_port, out_group):
        dst, netmask, dummy = nw_addr_aton(dst_ip)
        ip_str = ip_addr_ntoa(dst)
        key = '%s/%d' % (ip_str, netmask)
        if key in self:
            self._logger.warning('Routing entry overlapped')
        routing_data = _Route(route_id=self.route_id,
                              dst_ip=dst,
                              netmask=netmask,
                              src_mac=src_mac,
                              in_port=in_port,
                              out_group=out_group)
        self[key] = routing_data
        self.route_id += 1
        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]

    def get_gateways(self):
        return [route.gateway_ip for route in self.values()]

    def get_data_by_dst_ip(self, dst_ip):
        get_route = None
        mask = 0
        for route in self.values():
            if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                if mask < route.netmask:
                    get_route = route
                    mask = route.netmask
        return get_route


class _Ports(dict):
    def __init__(self):
        super(_Ports, self).__init__()

    def get_by_ip(self, ip):
        for port in self.values():
            if port.ip is None:
                continue
            if ipv4_apply_mask(ip, port.netmask) == port.ip:
                return port

    def get_by_mac(self, mac):
        for port in self.values():
            if port.mac == mac:
                return port


class _Port(object):
    _PORT_UP = 1
    _PORT_DOWN = 0

    def __init__(self, port_no, mac):
        super(_Port, self).__init__()
        self.port_no = port_no
        self.ip = None
        self.nw = None
        self.netmask = None
        self.mac = mac
        self.peer_mac = None
        self.links = {}
        self.status = self._PORT_UP

    def set_ip(self, nw, mask, ip):
        self.nw = nw
        self.netmask = mask
        self.ip = ip

    def add_link(self, link):
        self.links[link.dst.hw_addr] = link

    def is_up(self):
        return self.status == self._PORT_UP

    def up(self):
        self.status = self._PORT_UP

    def down(self):
        self.status = self._PORT_DOWN

    def set_peer_mac(self, mac):
        self.peer_mac = mac

    def set_mac(self, mac):
        self.mac = mac