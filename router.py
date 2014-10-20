import json
import socket
import struct

from webob import Response
from ryu.base import app_manager
from ryu.app.wsgi import route
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.lib import hub
from ryu.lib import addrconv
from ryu.lib import dpid as dpid_lib
from ryu.lib import mac  as mac_lib
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3
from ryu.topology.api import get_all_switch
from ryu.topology.api import get_all_link


MAX_SUSPENDPACKETS = 50  # Threshold of the packet suspends thread count.
DEFAULT_TTL = 64
ARP_REPLY_TIMER = 2  # sec

PORTNO_PATTERN = r'[0-9]{1,8}|all'
ROUTER_ID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff


class RouterRestController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RouterRestController, self).__init__(req, link, data, **config)
        self.router_app = data['router_app']

    @route('topo', '/topo/links', methods=['GET'])
    def get_links(self, req, **kwargs):
        links = self.router_app.get_all_links()
        return JsonResponse([link.to_dict() for link in links])

    @route('topo', '/topo/switches', methods=['GET'])
    def get_switches(self, req, **kwargs):
        switches = self.router_app.get_all_switches()
        return JsonResponse([switch.to_dict() for switch in switches])

    @route('route', '/router/{router_id}', methods=['GET'],
           requirements={'router_id': ROUTER_ID_PATTERN})
    def get_router(self, req, **kwargs):
        router = self.router_app.get_router(int(kwargs['router_id']))
        if router is None:
            return ErrorResponse(404, 'Router not found')
        return JsonResponse(router)

    @route('router', '/router/{router_id}/{port_no}', methods=['GET'],
           requirements={'router_id': ROUTER_ID_PATTERN,
                         'port_no': PORTNO_PATTERN})
    def get_port(self, req, **kwargs):
        return JsonResponse(self.router_app.get_port(int(kwargs['router_id']),
                                                int(kwargs['port_no']))) 

    @route('router', '/router/{router_id}/{port_no}/address',
           methods=['POST'],
           requirements={'router_id': ROUTER_ID_PATTERN,
                         'port_no': PORTNO_PATTERN})
    def set_port_address(self, req, **kwargs):
        address = kwargs.get('address') 
        if address is None:
            return ErrorResponse(400, 'Empty address.')
        return JsonResponse(address,
                            self.router_app.set_port(int(kwargs['router_id']),
                                                     int(kwargs['port_no'])))

    @route('router', '/router/{router_id}/{port_no}/address',
           methods=['DELETE'],
           requirements={'router_id': ROUTER_ID_PATTERN,
                         'port_no': PORTNO_PATTERN})
    def delete_port_address(self, req, **kwargs):
        return JsonResponse(
            self.router_app.delete_port_address(
                int(kwargs['router_id']),
                int(kwargs['port_no'])))

    @route('router', '/router/routing', methods=['POST'])
    def routing(self, req, **kwargs):
        return JsonResponse(self.router_app.routing())

class RouterApp(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {'dpset': dpset.DPSet,
                 'wsgi':  WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(RouterApp, self).__init__(*args, **kwargs)
        wsgi = kwargs['wsgi']
        wsgi.register(RouterRestController, {'router_app': self})

        self.routers = {}

    def get_all_links(self):
        return get_all_link(self)

    def get_all_switches(self):
        return get_all_switch(self)

    def get_router(self, router_id):
        return self.routers[router_id]

    def get_port(self, router_id, port_no):
        return None

    def set_port_address(self, address, router_id, port_no):
        router = self.get_router(router_id)
        return router.set_address(address, port_no)

    def del_port_address(self, router_id, port_no):
        return None 

    def routing(self):
        links = self.get_all_links()
        switches = self.get_all_switches()

        if links is None or switches is None:
            return
        dpids = [switch.ports[0].dpid for switch in switches]
        self.logger.info(str(dpids))
        graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                    for src_dpid in dpids} 
        via = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                    for src_dpid in dpids} 
        tmp_graph = {src_dpid: {dst_dpid: None for dst_dpid in dpids}
                    for src_dpid in dpids} 
        for link in links:
            dst_dpid = link.dst.dpid
            src_dpid = link.src.dpid
            graph[src_dpid][dst_dpid] = link
            via[src_dpid][dst_dpid] = link
            tmp_graph[src_dpid][dst_dpid] = 1

        self.logger.info(str(graph))
        # Shortest path for each node
        for k in dpids:
            for src in dpids:
                for dst in dpids:
                    if src == dst:
                        continue
                    src_k = tmp_graph[src][k]
                    k_dst = tmp_graph[k][src]
                    src_dst = tmp_graph[src][dst]
                    if (src_k is not None and k_dst is not None and
                            (src_dst is None or src_dst > src_k + k_dst)):
                        tmp_graph[src][dst] = src_k + k_dst
                        tmp_k = k
                        if graph[src][k] is not None:
                            via[src][dst] = graph[src][k]
                        else:
                            via[src][dst] = via[src][k]
        # Routing entries
        for src in dpids:
            router = self.get_router(src)
            for dst in dpids:
                if src == dst:
                    continue
                ports = self.get_router(dst).ports
                out_link = via[src][dst]
                if out_link is None:
                    continue
                self.logger.info(out_link)
                for port in ports:
                    addr = port.nw
                    gateway_ip = (self.get_router(out_link.dst.dpid)
                                      .get_port(out_link.dst.port_no)
                                      .get_ip())
                    self.logger.info(gateway_ip)
                    dst_str = '%s/%d' % (port.ip, port.netmask)
                    router.set_routing_data(dst_str, 
                                            out_link.src.hw_addr,
                                            out_link.dst.hw_addr,
                                            gateway_ip,
                                            out_link.src.port_no)    
        return {src_dpid: {dst_dpid: via[src_dpid][dst_dpid].to_dict() 
                                for dst_dpid in dpids
                                if via[src_dpid][dst_dpid] is not None} 
                    for src_dpid in dpids}

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            self._register_router(ev.dp)
        else:
            self._unregister_router(ev.dp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        dpid = ev.msg.datapath.id
        if dpid in self.routers:
            self.routers[dpid].packet_in(ev.msg)

    def _register_router(self, dp):
        router = Router(dp, self.logger) 
        self.routers[dp.id] = router 
        self.logger.info('Router %d comes up.', dp.id)

    def _unregister_router(self, dp):
        if dp.id in self.routers:
            self.routers[dp.id].delete()
            del self.routers[dp.id]
            self.logger.info('Router %d leaves.', dp.id)

class Router():
    def __init__(self, dp, logger):
        self.dp = dp
        self.logger = logger 
        self.ports = Ports(dp.ports)
        self.ofctl = OfCtl(dp, logger)
        self.packet_buffer = SuspendPacketList(self.send_icmp_unreach_error)
        self.routing_tbl = RoutingTable(self.logger)
        
    def set_ip(self, port_no, ip_str):
        nw, mask, ip = nw_addr_aton(ip_str) 
        # Check overlaps
        mask_b = mask_ntob(mask)
        for port in self.ports.values():
            port_mask = mask_ntob(port.netmask)
            if (port.nw == ipv4_apply_mask(ip, port.netmask) 
                or nw == ipv4_apply_mask(port.ip, mask)):
                return None
        if port_no in self.ports.keys():
            return None
        self.ports[port_no].set_ip(nw, mask, ip)

        priority = get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packetin_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=nw, dst_mask=mask)
        self.logger.info('Set MAC learning for %s', ip)
        # IP handling
        priority = get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packetin_flow(0, priority, dl_type=ether.ETH_TYPE_IP,
                                     dst_ip=ip)
        self.logger.info('Set IP handling for %s', ip)
        # L2 switching
        # TODO
        # Send GARP
        self.send_arp_request(ip, ip)
        return {'ip': ip, 'mask': mask, 'nw': nw}

    def delete(self):
        return

    def send_arp_request(self, src_ip, dst_ip, in_port=None, port=None):
        ports = [port]
        if port is None:
            ports = self.ports
        for send_port in ports:
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output = send_port.port_no
                self.ofctl.send_arp(arp.ARP_REQUEST, src_mac, dst_mac, src_ip,
                                    dst_ip, arp_target_mac, inport, output)

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

    def get_ips(self):
        return [port.ip for port in self.ports]

    def send_icmp_unreach_error(self, packet_buffer):
        # Send ICMP host unreach error.
        src_ip = self._get_send_port_ip(packet_buffer.header_list)
        if src_ip is not None:
            self.ofctl.send_icmp(packet_buffer.in_port,
                                 packet_buffer.header_list,
                                 icmp.ICMP_DEST_UNREACH,
                                 icmp.ICMP_HOST_UNREACH_CODE,
                                 msg_data=packet_buffer.data,
                                 src_ip=src_ip)

            dstip = ip_addr_ntoa(packet_buffer.dst_ip)

    def set_routing_data(self, destination, outmac, gateway_mac, gateway_ip,
                         output):
        dst_ip = ip_addr_aton(gateway_ip)
        port = self.ports.get_by_ip(dst_ip)
        if port is None:
            self.logger.info('No port with ip %s', dst_ip)
            return
        else:
            src_ip = port.ip
            route = self.routing_tbl.add(destination, gateway_ip, gateway_mac)
            if route is None:
                self.logger.info('Routing entry creation failed')
            self._install_routing_entry(route, output, outmac, gateway_mac)
            return route.route_id

    def _install_routing_entry(self, route, output, src_mac, dst_mac):
        priority = get_priority(PRIORITY_TYPE_ROUTE)
        self.ofctl.set_routing_flow(0, priority, output,
                                    src_mac=src_mac,
                                    dst_mac=dst_mac,
                                    nw_dst=route.dst_ip,
                                    dst_mask=route.netmask,
                                    dec_ttl=True)
        self.logger.info('Set flow to %s via %s', route.dst_ip,
                         route.gateway_ip)

    def _init_flows(self):
        cookie = 0
        self.ofctl.set_sw_config_for_ttl()
        # ARP
        priority = get_priority(PRIORITY_ARP_HANDLING)
        self.ofctl.set_packetin_flow(cookie, priority, dl_type=ether.ETH_TYPE_ARP)
        # Drop by default 
        priority = get_priority(PRIORITY_DEFAULT_ROUTING)
        outport = None
        self.ofctl.set_routing_flow(cookie, priority, outport)
        self.ofctl.set_routing_flow_v6(cookie, priority, outport)

    def _packet_in_arp(self, msg, headers):
        src_port = self.ports.get_by_ip(headers[ARP].src_ip) 
        if src_port is None:
            return
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = headers[ARP].src_ip
        dst_ip = headers[ARP].dst_ip
        src_ip_str = ip_addr_ntoa(src_ip) 
        dst_ip_str = ip_addr_ntoa(dst_ip)
        rt_ips = self.get_ips()
        if src_ip == dst_ip:
            output = self.ofctl.dp.ofproto.OFPP_NORMAL
            self.ofctl.send_packet_out(in_port, output, msg.data)
        elif dst_ip not in rt_ips:
            dst_port = self.ports.get_by_ip(dst_ip)
            if (dst_port is not None
                and src_port.ip == dst_port.ip):
                output = self.ofctl.dp.ofproto.OFPP_NORMAL
                self.ofctl.send_packet_out(in_port, output, msg.data)
        else:
            if headers[ARP].opcode == arp.ARP_REV_REQUEST:
                src_mac = headers[ARP].src_mac
                dst_mac = self.ports[in_port].mac
                arp_target_mac = dst_mac
                output = in_port
                in_port = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                self.ofctl.send_arp(arp.ARP_REPLY, dst_mac, src_mac, dst_ip,
                                    src_ip, arp_target_mac, in_port, output)
            elif headers[ARP].opcode == arp.ARP_REPLY:
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
        self.logger.info('Receive invalid ttl packet from %s', srcip)

        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = self._get_send_port_ip(headers)
        if src_ip is not None:
            self.ofctl.send_icmp(in_port, headers, icmp.ICMP_TIME_EXCEEDED,
                                 icmp.ICMP_TTL_EXPIRED_CODE,
                                msg_data=msg.data, src_ip=src_ip)
            self.logger('Send ICMP time exceeded to %s', src_ip)

    def _packet_in_to_node(self, msg, headers):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self.logger.info('Suspend pakcet drop')
            return
        in_port = self.ofctl.get_packetin_inport(msg)
        src_ip = headers[IPV4].src
        dst_ip = headers[IPV4].dst
        srcip = ip_addr_ntoa(src_ip)
        dstip = ip_addr_ntoa(dst_ip) 
        port = self.ports.get_by_ip(dst_ip)
        if port is not None:
            src_ip = port.ip
        else:
            route = self.routing_tbl.get_data(dst_ip=dst_ip)
            if route is not None:
                self.logger.info('Receive IP packet from %s to %s.', src_ip,
                                 dst_ip)
                gateway = self.ports.get_by_ip(route.gateway_ip)
                if gateway is not None:
                    src_ip = gateway.ip
                    dst_ip = route.gateway_ip
                    self.logger.info('Gateway added: %s, route: %s', src_ip,
                                     dst_ip)
        if src_ip is not None:
            self.packet_buffer.add(in_port, headers, msg.data)
            self.send_arp_request(src_ip, dst_ip, in_port=in_port)
            self.logger.info('Send ARP request')

    def _packet_in_icmp_req(self, msg, headers):
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, headers, icmp.ICMP_ECHO_REPLY,
                             icmp.ICMP_ECHO_REPLY_CODE,
                             icmp_data=headers[ICMP].data)

    def _packet_in_tcp_udp(self, msg, headers):
        in_port = self.ofctl.get_packetin_inport(msg)
        self.ofctl.send_icmp(in_port, headers, icmp.ICMP_DEST_UNREACH,
                             icmp.ICMP_PORT_UNREACH_CODE, msg_data=msg.data)

    def _get_send_port_ip(self, headers):
        try:
            src_mac = headers[ETHERNET].src
            if IPV4 in headers:
                src_ip = headers[IPV4].src
            else:
                src_ip = headers[ARP].src_ip
        except KeyError:
            self.logger.info('Receive unsupported packet.')
            return

        port = self.ports.get_by_ip(src_ip)
        if port is not None:
            return port.ip
        else:
            route = self.routing_tbl.get_data(gw_mac=src_mac)
            if route is not None:
                port = self.ports.get_by_ip(route.gateway_ip)
                if port is not None:
                    return port.ip

        self.logger.info('Receive packet from unknown IP %s',
                         ip_addr_ntoa(src_ip))

class RoutingTable(dict):
    def __init__(self, logger):
        super(RoutingTable, self).__init__()
        self.logger = logger 
        self.route_id = 1

    def add(self, dst_nw_addr, gateway_ip, gateway_mac):
        dst, netmask, dummy = nw_addr_aton(dst_nw_addr)
        gateway_ip = ip_addr_aton(gateway_ip)

        overlap_route = None
        if dst_nw_addr in self:
            overlap_route = self[dst_nw_addr].route_id

        if overlap_route is not None:
            self.logger.info('Destination overlaps route id: %d',
                             overlap_route)
            return

        routing_data = Route(self.route_id, dst, netmask, gateway_ip,
                             gateway_mac)
        ip_str = ip_addr_ntoa(dst)
        key = '%s/%d' % (ip_str, netmask)
        self[key] = routing_data
        self.route_id += 1

        return routing_data

    def delete(self, route_id):
        for key, value in self.items():
            if value.route_id == route_id:
                del self[key]

    def get_gateways(self):
        return [routing_data.gateway_ip for routing_data in self.values()]

    def get_data(self, gw_mac=None, dst_ip=None):
        if gw_mac is not None:
            for route in self.values():
                if gw_mac == route.gateway_mac:
                    return route
            return None
        elif dst_ip is not None:
            get_route = None
            mask = 0
            for route in self.values():
                if ipv4_apply_mask(dst_ip, route.netmask) == route.dst_ip:
                    if mask < route.netmask:
                        get_route = route
                        mask = route.netmask
            return get_route 

class Route(object):
    def __init__(self, route_id, dst_ip, netmask, gateway_ip, gateway_mac):
        super(Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac 

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
        self.mask = None
    
    def set_ip(self, nw, mask, ip):
        self.nw = nw
        self.mask = mask
        self.ip = ip


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


class OfCtl(object):
    def __init__(self, dp, logger):
        super(OfCtl, self).__init__()
        self.dp = dp
        self.logger = logger

    def send_packet_out(self, in_port, output, data, data_str=None):
        actions = [self.dp.ofproto_parser.OFPActionOutput(output, 0)]
        self.dp.send_packet_out(buffer_id=UINT32_MAX, in_port=in_port,
                                actions=actions, data=data)
        # TODO: Packet library convert to string
        # if data_str is None:
        # data_str = str(packet.Packet(data))
        # self.logger.debug('Packet out = %s', data_str, extra=self.sw_id)

    def get_packetin_inport(self, msg):
        return msg.in_port

    def set_routing_flow(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False,
                         dl_type=ether.ETH_TYPE_IP):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser

        actions = []
        if dec_ttl:
            actions.append(ofp_parser.OFPActionDecNwTtl())
        if src_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_src=src_mac))
        if dst_mac:
            actions.append(ofp_parser.OFPActionSetField(eth_dst=dst_mac))
        if outport is not None:
            actions.append(ofp_parser.OFPActionOutput(outport, 0))

        self.set_flow(cookie, priority, dl_type=dl_type, dl_vlan=dl_vlan,
                      nw_src=nw_src, src_mask=src_mask,
                      nw_dst=nw_dst, dst_mask=dst_mask,
                      idle_timeout=idle_timeout, actions=actions)

    def set_routing_flow_v6(self, cookie, priority, outport, dl_vlan=0,
                         nw_src=0, src_mask=128, nw_dst=0, dst_mask=128,
                         src_mac=0, dst_mac=0, idle_timeout=0, dec_ttl=False):
        self.set_routing_flow(cookie, priority, outport, dl_vlan=dl_vlan,
                              nw_src=nw_src, src_mask=src_mask, nw_dst=nw_dst,
                              dst_mask=dst_mask, src_mac=src_mac,
                              dst_mac=dst_mac, idle_timeout=idle_timeout,
                              dec_ttl=dec_ttl)

    def set_sw_config_for_ttl(self):
        packet_in_mask = (1 << self.dp.ofproto.OFPR_ACTION |
                          1 << self.dp.ofproto.OFPR_INVALID_TTL)
        port_status_mask = (1 << self.dp.ofproto.OFPPR_ADD |
                            1 << self.dp.ofproto.OFPPR_DELETE |
                            1 << self.dp.ofproto.OFPPR_MODIFY)
        flow_removed_mask = (1 << self.dp.ofproto.OFPRR_IDLE_TIMEOUT |
                             1 << self.dp.ofproto.OFPRR_HARD_TIMEOUT |
                             1 << self.dp.ofproto.OFPRR_DELETE)
        m = self.dp.ofproto_parser.OFPSetAsync(
            self.dp, [packet_in_mask, 0], [port_status_mask, 0],
            [flow_removed_mask, 0])
        self.dp.send_msg(m)
        self.logger.info('Set SW config for TTL error packet in.')

    def set_flow(self, cookie, priority, dl_type=0, dl_dst=0, dl_vlan=0,
                 nw_src=0, src_mask=32, nw_dst=0, dst_mask=32,
                 nw_proto=0, idle_timeout=0, actions=None):
        ofp = self.dp.ofproto
        ofp_parser = self.dp.ofproto_parser
        cmd = ofp.OFPFC_ADD

        # Match
        match = ofp_parser.OFPMatch()
        if dl_type:
            match.set_dl_type(dl_type)
        if dl_dst:
            match.set_dl_dst(dl_dst)
        if dl_vlan:
            match.set_vlan_vid(dl_vlan)
        # TODO: Handle ipv6 address
        if nw_src:
            match.set_ipv4_src_masked(ipv4_text_to_int(nw_src),
                                      mask_ntob(src_mask))
        if nw_dst:
            match.set_ipv4_dst_masked(ipv4_text_to_int(nw_dst),
                                      mask_ntob(dst_mask))
        if nw_proto:
            if dl_type == ether.ETH_TYPE_IP:
                match.set_ip_proto(nw_proto)
            elif dl_type == ether.ETH_TYPE_ARP:
                match.set_arp_opcode(nw_proto)

        # Instructions
        actions = actions or []
        inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]

        m = ofp_parser.OFPFlowMod(self.dp, cookie, 0, 0, cmd, idle_timeout,
                                  0, priority, UINT32_MAX, ofp.OFPP_ANY,
                                  ofp.OFPG_ANY, 0, match, inst)
        self.dp.send_msg(m)

    def set_packetin_flow(self, cookie, priority, dl_type=0, dl_dst=0,
                          dl_vlan=0, dst_ip=0, dst_mask=32, nw_proto=0):
        miss_send_len = UINT16_MAX
        actions = [self.dp.ofproto_parser.OFPActionOutput(
            self.dp.ofproto.OFPP_CONTROLLER, miss_send_len)]
        self.set_flow(cookie, priority, dl_type=dl_type, dl_dst=dl_dst,
                      dl_vlan=dl_vlan, nw_dst=dst_ip, dst_mask=dst_mask,
                      nw_proto=nw_proto, actions=actions)

    def send_icmp(self, in_port, protocol_list, icmp_type, icmp_code,
                  icmp_data=None, msg_data=None, src_ip=None):
        # Generate ICMP reply packet
        csum = 0
        offset = ethernet.ethernet._MIN_LEN

        ether_proto = ether.ETH_TYPE_IP

        eth = protocol_list[ETHERNET]
        e = ethernet.ethernet(eth.src, eth.dst, ether_proto)

        if icmp_data is None and msg_data is not None:
            ip_datagram = msg_data[offset:]
            if icmp_type == icmp.ICMP_DEST_UNREACH:
                icmp_data = icmp.dest_unreach(data_len=len(ip_datagram),
                                              data=ip_datagram)
            elif icmp_type == icmp.ICMP_TIME_EXCEEDED:
                icmp_data = icmp.TimeExceeded(data_len=len(ip_datagram),
                                              data=ip_datagram)

        ic = icmp.icmp(icmp_type, icmp_code, csum, data=icmp_data)

        ip = protocol_list[IPV4]
        if src_ip is None:
            src_ip = ip.dst
        ip_total_length = ip.header_length * 4 + ic._MIN_LEN
        if ic.data is not None:
            ip_total_length += ic.data._MIN_LEN
            if ic.data.data is not None:
                ip_total_length += + len(ic.data.data)
        i = ipv4.ipv4(ip.version, ip.header_length, ip.tos,
                      ip_total_length, ip.identification, ip.flags,
                      ip.offset, DEFAULT_TTL, inet.IPPROTO_ICMP, csum,
                      src_ip, ip.src)

        pkt = packet.Packet()
        pkt.add_protocol(e)
        pkt.add_protocol(i)
        pkt.add_protocol(ic)
        pkt.serialize()

        # Send packet out
        self.send_packet_out(in_port, self.dp.ofproto.OFPP_IN_PORT,
                             pkt.data, data_str=str(pkt))

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



def JsonResponse(obj, status=200):
    return Response(status=status, content_type='application/json',
                    body=json.dumps(obj))

def ErrorResponse(status, msg):
    return JsonResponse(msg, status=status) 

PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NETMASK_SHIFT = 32

PRIORITY_NORMAL = 0
PRIORITY_ARP_HANDLING = 1
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_MAC_LEARNING = 2
PRIORITY_STATIC_ROUTING = 2
PRIORITY_IMPLICIT_ROUTING = 3
PRIORITY_L2_SWITCHING = 4
PRIORITY_IP_HANDLING = 5

PRIORITY_TYPE_ROUTE = 'priority_route'

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

    if log_msg is None:
        return priority
    else:
        return priority, log_msg


def ip_addr_aton(ip_str, err_msg=None):
    try:
        return addrconv.ipv4.bin_to_text(socket.inet_aton(ip_str))
    except (struct.error, socket.error) as e:
        if err_msg is not None:
            e.message = '%s %s' % (err_msg, e.message)
        raise ValueError(e.message)


def ip_addr_ntoa(ip):
    return socket.inet_ntoa(addrconv.ipv4.text_to_bin(ip))


def mask_ntob(mask, err_msg=None):
    try:
        return (UINT32_MAX << (32 - mask)) & UINT32_MAX
    except ValueError:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)


def ipv4_apply_mask(address, prefix_len, err_msg=None):
    assert isinstance(address, str)
    address_int = ipv4_text_to_int(address)
    return ipv4_int_to_text(address_int & mask_ntob(prefix_len, err_msg))


def ipv4_int_to_text(ip_int):
    assert isinstance(ip_int, (int, long))
    return addrconv.ipv4.bin_to_text(struct.pack('!I', ip_int))


def ipv4_text_to_int(ip_text):
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]


def nw_addr_aton(nw_addr, err_msg=None):
    ip_mask = nw_addr.split('/')
    default_route = ip_addr_aton(ip_mask[0], err_msg=err_msg)
    netmask = 32
    if len(ip_mask) == 2:
        try:
            netmask = int(ip_mask[1])
        except ValueError as e:
            if err_msg is not None:
                e.message = '%s %s' % (err_msg, e.message)
            raise ValueError(e.message)
    if netmask < 0:
        msg = 'illegal netmask'
        if err_msg is not None:
            msg = '%s %s' % (err_msg, msg)
        raise ValueError(msg)
    nw_addr = ipv4_apply_mask(default_route, netmask, err_msg)
    return nw_addr, netmask, default_route

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__


