#!/usr/bin/env python2
import time

import Pyro4
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet.arp import ARP_REQUEST
from ryu.ofproto import ether
from ryu.lib import mac as mac_lib

from config import ARP_EXPIRE_SECOND
from constants import IPV4, ICMP, UDP, TCP, PRIORITY_TYPE_ROUTE, \
    PRIORITY_STATIC_ROUTING, PRIORITY_DEFAULT_ROUTING, PRIORITY_IP_HANDLING, \
    PRIORITY_VLAN_SHIFT, PRIORITY_NETMASK_SHIFT, PRIORITY_ARP_HANDLING, \
    PRIORITY_NORMAL
from local_controller import LocalController
from resilient_router import ARP


class RoutingLocal(LocalController):
    def __init__(self, *args, **kwargs):
        super(RoutingLocal, self).__init__(*args, **kwargs)
        self._group_id = 0
        self.arp_table = ArpTable()

    @Pyro4.expose
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
                outport = send_port.port_no
                self.ofctl.send_arp(ARP_REQUEST, src_mac, dst_mac, src_ip,
                                    dst_ip, arp_target_mac, inport, outport)

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
        pass

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_change(self, ev):
        pass

    def get_ips(self):
        return [port.ip for port in self.ports.values()]

    def init_switch(self):
        cookie = 0
        self.ofctl.set_sw_config_for_ttl()
        priority, dummy = get_priority(PRIORITY_ARP_HANDLING)
        self.ofctl.set_packet_in_flow(cookie, priority,
                                      dl_type=ether.ETH_TYPE_ARP)
        priority, dummy = get_priority(PRIORITY_DEFAULT_ROUTING)
        self.ofctl.set_routing_flow(cookie, priority, None)
        self.ofctl.set_routing_flow_v6(cookie, priority, None)
        priority, dummy = get_priority(PRIORITY_NORMAL)
        self.ofctl.set_normal_flow(cookie, priority)

    def _install_routing_entry(self, route):
        priority, dummy = get_priority(PRIORITY_TYPE_ROUTE, route=route)
        self.ofctl.set_routing_flow(0,
                                    priority,
                                    route.out_port,
                                    src_mac=route.src_mac,
                                    dst_mac=route.gateway_mac,
                                    nw_dst=route.dst_ip,
                                    dst_mask=route.netmask,
                                    dec_ttl=True,
                                    in_port=route.in_port,
                                    out_group=route.out_group)

    def _set_group(self, src_macs, dst_macs, watch_ports, out_ports):
        self.ofctl.set_group(self._group_id,
                             watch_ports,
                             out_ports,
                             src_macs,
                             dst_macs)
        self._group_id += 1

    def _register(self, dp):
        super(RoutingLocal, self)._register(dp)
        self._group_id = 0

    def _unregister(self):
        super(RoutingLocal, self)._unregister()
        self.arp_table.clear()

    def _packet_in_arp(self, msg, headers):
        pass

    def _packet_in_invalid_ttl(self, msg, headers):
        pass

    def _packet_in_icmp_req(self, msg, headers):
        pass

    def _packet_in_tcp_udp(self, msg, headers):
        pass

    def _packet_in_to_node(self, msg, headers):
        pass


class ArpEntry(object):
    def __init__(self, ip, mac):
        super(ArpEntry, self).__init__()
        self.ip = ip
        self.mac = mac
        self.refreshed_at = time.time()

    def is_expired(self):
        return time.time() - self.refreshed_at > ARP_EXPIRE_SECOND

    def refresh(self):
        self.refreshed_at = time.time()


class ArpTable(dict):
    def __init__(self):
        super(ArpTable, self).__init__()

    def __getitem__(self, item):
        entry = super(ArpTable, self).__getitem__(item)
        if entry is not None and not entry.is_expired:
            return entry


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

