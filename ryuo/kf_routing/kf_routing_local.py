import time

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet.arp import ARP_REQUEST, ARP_REPLY
from ryu.lib.packet.icmp import ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REPLY, \
    ICMP_DEST_UNREACH, ICMP_TIME_EXCEEDED, \
    ICMP_TTL_EXPIRED_CODE, ICMP_ECHO_REQUEST, ICMP_HOST_UNREACH_CODE
from ryu.ofproto import ether, ofproto_v1_2, ofproto_v1_0
from ryu.lib import mac as mac_lib
from ryu.lib import hub

from ryuo.kf_routing.app import KFRoutingApp
from ryuo.kf_routing.switch_control import OVSSwitchControl
from ryuo.topology.event import EventPortDelete, EventPortAdd, \
    EventPortModify, EventLinkAdd
from ryuo.constants import IPV4, ICMP, UDP, TCP, PRIORITY_TYPE_ROUTE, \
    PRIORITY_STATIC_ROUTING, PRIORITY_DEFAULT_ROUTING, PRIORITY_IP_HANDLING, \
    PRIORITY_VLAN_SHIFT, PRIORITY_NETMASK_SHIFT, PRIORITY_ARP_HANDLING, \
    PRIORITY_NORMAL, PRIORITY_IMPLICIT_ROUTING, ARP_REPLY_TIMER, \
    MAX_SUSPENDPACKETS, PRIORITY_L2_SWITCHING, \
    PORT_UP, ARP, PRIORITY_MAC_LEARNING
from ryuo.local.local_app import LocalApp
from ryuo.config import ARP_EXPIRE_SECOND
from ryuo.utils import nw_addr_aton, ipv4_apply_mask, expose


class KFRoutingLocal(LocalApp):
    def __init__(self, *args, **kwargs):
        kwargs['ryuo_name'] = KFRoutingApp.__name__
        super(KFRoutingLocal, self).__init__(*args, **kwargs)
        self.ports = _Ports()  # port_no -> Port
        self.arp_table = None
        self.groups = None
        self.routing_table = None
        self.disabled_failover_ports = None
        self.packet_buffer = _SuspendPacketList(
            self.send_icmp_unreachable_error)
        self.pending_arps = _PendingArps(self)
        self.switch_ctl = OVSSwitchControl()

    @expose
    def add_route(self, dst_ip, group_id):
        group = self.groups[group_id]
        route = self.routing_table.add_entry(dst_ip=dst_ip,
                                             in_port=group.inport,
                                             out_group=group)
        self._install_routing_entry(route)
        self._logger.info('Route to %s from port %d to ports %s',
                          dst_ip, group.inport,
                          str(self.groups[group_id].output_ports))

    @expose
    def add_routes(self, dst_ips, group_id):
        for dst_ip in dst_ips:
            self.add_route.lock_free(self, dst_ip, group_id)

    @expose
    def add_group(self, in_port, output_ports):
        group = self.groups.add_entry(output_ports, in_port)
        return group.id

    @expose
    def batch_set_port_address(self, ips):
        for port_no in ips:
            ip_data = ips[port_no]
            nw = ip_data[0]
            mask = ip_data[1]
            ip = ip_data[2]
            peer_ip = ip_data[3]
            self.set_port_address.lock_free(self, port_no, ip, mask, nw,
                                            peer_ip)

    @expose
    def set_port_address(self, port_no, ip, mask, nw, peer_ip=None):
        if port_no not in self.ports.keys():
            return None
        port = self.ports[port_no]
        port.set_ip(nw, mask, ip)
        port.set_peer_ip(peer_ip)
        self._logger.info('Setting IP %s/%d of %s', ip, mask, nw)

        # IP handling
        priority, dummy = _get_priority(PRIORITY_IP_HANDLING)
        self.ofctl.set_packet_in_flow(0, priority, eth_type=ether.ETH_TYPE_IP,
                                      dst_ip=ip)
        self._logger.info('Set IP handling for %s', ip)
        # MAC Learning
        priority, dummy = _get_priority(PRIORITY_MAC_LEARNING)
        self.ofctl.set_packet_in_flow(0, priority, eth_type=ether.ETH_TYPE_IP,
                                      dst_ip=nw, dst_mask=mask)
        self._logger.info('Set MAC learning for %s', ip)
        # L2 switching
        # out_port = self.ofctl.dp.ofproto.OFPP_NORMAL
        out_port = None
        priority, dummy = _get_priority(PRIORITY_L2_SWITCHING)
        self.ofctl.set_routing_flow(
            0, priority, out_port,
            nw_src=nw, src_mask=mask,
            nw_dst=nw, dst_mask=mask)
        self._logger.info('Set L2 switching (normal) flow [cookie=0x%x]',
                          0)
        # Send GARP
        self.send_arp(ip, ip, port=port_no, code=ARP_REQUEST)
        self.send_arp(ip, ip, port=port_no, code=ARP_REPLY)
        if peer_ip is not None:
            self.switch_ctl.enable_bfd(port.name, port.peer_mac, ip, peer_ip,
                                       1, 1)

    def send_arp(self, src_ip, dst_ip, in_port=None, port=None,
                 code=ARP_REQUEST):
        ports = [self.ports[port]]
        if port is None:
            ports = self.ports.values()
        for send_port in ports:
            if in_port is None or in_port != send_port.port_no:
                src_mac = send_port.mac
                dst_mac = mac_lib.BROADCAST_STR
                arp_target_mac = mac_lib.DONTCARE_STR
                inport = self.ofctl.dp.ofproto.OFPP_CONTROLLER
                output_port = send_port.port_no
                self.ofctl.send_arp(code, src_mac, dst_mac, src_ip,
                                    dst_ip, arp_target_mac, inport,
                                    output_port)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        headers = dict((p.protocol_name, p)
                       for p in pkt.protocols if type(p) != str)
        ofproto = self.dp.ofproto
        if (ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION and
                    msg.reason == ofproto.OFPR_INVALID_TTL):
            return self._packet_in_invalid_ttl(msg, headers)
        if ARP in headers:
            return self._packet_in_arp(msg, headers)
        if IPV4 in headers:
            if headers[IPV4].dst in self.get_ips():
                if ICMP in headers:
                    if headers[ICMP].type == ICMP_ECHO_REQUEST:
                        return self._packet_in_icmp_req(msg, headers)
                    self._logger.warning('Unsupported ICMP type, ignore.')
                elif TCP in headers or UDP in headers:
                    return self._packet_in_tcp_udp(msg, headers)
            else:
                return self._packet_in_to_node(msg, headers)

    @set_ev_cls(EventPortDelete)
    def _on_port_deleted(self, ev):
        del self.ports[ev.port.port_no]

    @set_ev_cls(EventPortAdd)
    def _on_port_added(self, ev):
        self._init_port(ev.port)

    @set_ev_cls(EventPortModify)
    def _on_port_modified(self, ev):
        port = ev.port
        if port.is_down():
            self.ports[port.port_no].down()
        else:
            self.ports[port.port_no].up()
        if self.dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            self._update_routes()

    @set_ev_cls(EventLinkAdd)
    def _on_link_added(self, ev):
        dst_port_no = ev.link.dst.port_no
        peer_mac = ev.link.src.hw_addr
        old_peer_mac = self.ports[dst_port_no].peer_mac
        if peer_mac != old_peer_mac:
            # TODO: update flow entries
            pass
        self.ports[dst_port_no].set_peer_mac(peer_mac)

    def _init_port(self, ofpport):
        if ofpport.port_no > self.dp.ofproto.OFPP_MAX:
            return
        self.ports[ofpport.port_no] = _Port(ofpport.port_no, ofpport.hw_addr,
                                            ofpport.name)
        priority, dummy = _get_priority(PRIORITY_ARP_HANDLING)
        self.ofctl.set_packet_in_flow(
            0, priority,
            eth_type=ether.ETH_TYPE_ARP,
            eth_dst=ofpport.hw_addr,
            in_port=ofpport.port_no)
        self.ofctl.set_packet_in_flow(
            0, priority,
            eth_type=ether.ETH_TYPE_ARP,
            eth_dst=mac_lib.BROADCAST_STR,
            in_port=ofpport.port_no)

    def get_ips(self):
        return [port.ip for port in self.ports.values()]

    def _init_switch(self):
        cookie = 0
        self.ofctl.set_async_config()
        # priority, dummy = _get_priority(PRIORITY_ARP_HANDLING)
        # self.ofctl.set_packet_in_flow(cookie, priority,
        # dl_type=ether.ETH_TYPE_ARP)
        priority, dummy = _get_priority(PRIORITY_DEFAULT_ROUTING)
        self.ofctl.set_routing_flow(cookie, priority, None)
        self.ofctl.set_routing_flow_v6(cookie, priority, None)
        priority, dummy = _get_priority(PRIORITY_NORMAL)
        self.ofctl.set_normal_flow(cookie, priority)

        self.ofctl.get_async_config_request()

    def _install_routing_entry(self, route):
        priority, dummy = _get_priority(PRIORITY_TYPE_ROUTE, route=route)
        if self.dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            self.ofctl.set_routing_flow(0,
                                        priority,
                                        None,
                                        nw_dst=route.dst_ip,
                                        dst_mask=route.netmask,
                                        dec_ttl=True,
                                        in_port=route.in_port,
                                        out_group=route.out_group.id)
        else:
            group = route.out_group
            port = self._get_active_port(group.watch_ports, group.output_ports)
            src_mac = self.ports[port].mac
            dst_mac = self.ports[port].peer_mac
            route.active_out_port = port
            if port == route.in_port:
                port = self.dp.ofproto.OFPP_IN_PORT
            self.ofctl.set_routing_flow(0,
                                        priority,
                                        port,
                                        src_mac=src_mac,
                                        dst_mac=dst_mac,
                                        nw_dst=route.dst_ip,
                                        dst_mask=route.netmask,
                                        dec_ttl=True,
                                        in_port=route.in_port)

    def _update_routes(self):
        for route in self.routing_table.values():
            group = route.out_group
            active_port = self._get_active_port(group.watch_ports,
                                                group.output_ports)
            if (active_port is not None and
                        active_port != route.active_out_port):
                src_mac = self.ports[active_port].mac
                dst_mac = self.ports[active_port].peer_mac
                priority, dummy = _get_priority(PRIORITY_TYPE_ROUTE,
                                                route=route)
                self._logger.info(
                    'Route from port %d to %s failover from %d to %d',
                    route.in_port, route.dst_ip, route.active_out_port,
                    active_port)
                route.active_out_port = active_port
                if active_port == route.in_port:
                    active_port = self.dp.ofproto.OFPP_IN_PORT
                self.ofctl.update_routing_flow(0, priority, active_port,
                                               src_mac=src_mac,
                                               dst_mac=dst_mac,
                                               nw_dst=route.dst_ip,
                                               dst_mask=route.netmask,
                                               dec_ttl=True,
                                               in_port=route.in_port)

    def _switch_enter(self, dp):
        super(KFRoutingLocal, self)._switch_enter(dp)
        for ofpport in dp.ports.values():
            self._init_port(ofpport)
        self.groups = _GroupTable(self.ofctl, self.ports)
        self.routing_table = _RoutingTable(self._logger)
        self.arp_table = _ArpTable(self._logger)
        self.disabled_failover_ports = _DisabledFailoverPorts()
        self._init_switch()

    def _switch_leave(self):
        super(KFRoutingLocal, self)._switch_leave()
        self.groups = None
        self.arp_table = None
        self.routing_table = None

    def _packet_in_arp(self, msg, headers):
        src_ip = headers[ARP].src_ip
        dst_ip = headers[ARP].dst_ip
        in_port = self.ofctl.get_packet_in_inport(msg)
        self._logger.info('Receive ARP %s from %s to %s, port %d',
                          'Request' if headers[ARP].opcode == ARP_REQUEST
                          else 'Reply'
                          , src_ip, dst_ip, in_port)
        src_port = self.ports.get_by_ip(headers[ARP].src_ip)
        if src_port is None:
            return
        if src_ip not in [port.ip for port in self.ports.values()]:
            self._learn_host_mac(msg, headers)
        if headers[ARP].opcode == ARP_REQUEST:
            src_mac = headers[ARP].src_mac
            dst_mac = self.ports[in_port].mac
            arp_target_mac = src_mac
            self.ofctl.send_arp(ARP_REPLY,
                                dst_mac,
                                src_mac,
                                dst_ip,
                                src_ip,
                                arp_target_mac,
                                self.dp.ofproto.OFPP_CONTROLLER,
                                in_port)
        elif headers[ARP].opcode == ARP_REPLY:
            self.pending_arps.delete(src_ip)
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
        # TODO: Only install flow when ARP table changed.
        # TODO: Better Arp Table management.
        out_port = self.ofctl.get_packet_in_inport(msg)
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
                                    # idle_timeout=ARP_EXPIRE_SECOND,
                                    dec_ttl=True)
        self._logger.info('Set implicit routing flow to %s', src_ip)

    def _packet_in_invalid_ttl(self, msg, headers):
        src_ip = headers[IPV4].src
        dst_ip = headers[IPV4].dst
        self._logger.info('Received packet with invalid ttl from %s to %s.',
                          src_ip, dst_ip)
        in_port = self.ofctl.get_packet_in_inport(msg)
        in_ip = self.ports[in_port].ip
        if src_ip in self.get_ips():
            self._logger.warning(
                'Receive packet with invalid ttl from myself.')
            return
        if in_ip is not None:
            self.ofctl.reply_icmp(in_port,
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
        in_port = self.ofctl.get_packet_in_inport(msg)
        src_ip = self.ports[in_port].ip
        self.ofctl.reply_icmp(in_port,
                              headers,
                              ICMP_ECHO_REPLY,
                              ICMP_ECHO_REPLY_CODE,
                              icmp_data=headers[ICMP].data,
                              src_ip=src_ip)

    def _packet_in_tcp_udp(self, msg, headers):
        # Ignore all tcp/udp packets
        pass
        # in_port = self.ofctl.get_packet_in_inport(msg)
        # self.ofctl.reply_icmp(in_port,
        # headers,
        # ICMP_DEST_UNREACH,
        # ICMP_PORT_UNREACH_CODE,
        # msg_data=msg.data)
        # self._logger.info('Receive TCP/UDP from %s, sending icmp
        # unreachable',
        # headers[IPV4].src)

    def _packet_in_to_node(self, msg, headers):
        if len(self.packet_buffer) >= MAX_SUSPENDPACKETS:
            self._logger.warning('Suspend packet drop.')
            return
        in_port = self.ofctl.get_packet_in_inport(msg)
        dst_ip = headers[IPV4].dst
        self._logger.debug('Packet in to node %s', dst_ip)
        port = self.ports.get_by_ip(dst_ip)
        if port is not None:
            out_ip = port.ip
            if self.arp_table.get(dst_ip) is not None:
                self._logger.debug('Find mac in arp table')
                self.ofctl.send_packet_out(in_port,
                                           port.port_no,
                                           msg.data)
            else:
                self.packet_buffer.add(in_port, headers, msg.data)
                if not self.pending_arps.contains(dst_ip):
                    self.pending_arps.add(dst_ip, out_ip, port.port_no)
        else:
            self._logger.warning('Unknown dst ip %s', dst_ip)

    def _send_icmp_unreachable_error(self, in_port, headers, data, dst_ip):
        src_ip = self._get_send_port_ip(headers)
        if src_ip is not None:
            self.ofctl.reply_icmp(in_port,
                                  headers,
                                  ICMP_DEST_UNREACH,
                                  ICMP_HOST_UNREACH_CODE,
                                  msg_data=data,
                                  src_ip=src_ip)
            self._logger.info('Send ICMP unreachable to %s', dst_ip)

    def send_icmp_unreachable_error(self, suspended_packet):
        return self._send_icmp_unreachable_error(suspended_packet.in_port,
                                                 suspended_packet.header_list,
                                                 suspended_packet.data,
                                                 suspended_packet.src_ip)

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
        group = route.out_group
        active_port_no = self._get_active_port(group.watch_ports,
                                               group.output_ports)
        if active_port_no is not None:
            return self.ports[active_port_no]
        return None

    def _get_active_port(self, watch_ports, out_ports):
        for idx, port_no in enumerate(watch_ports):
            if self.ports[port_no].status == PORT_UP:
                return out_ports[idx]

    @set_ev_cls(ofp_event.EventOFPGetAsyncReply, MAIN_DISPATCHER)
    def get_async_reply_handler(self, ev):
        msg = ev.msg
        self._logger.info('OFPGetAsyncReply: %s',
                          self.ofctl.async_config_to_str(msg))


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
    def __init__(self, logger):
        super(_ArpTable, self).__init__()
        self._logger = logger

    def get(self, k, d=None):
        if k in self.keys():
            item = self[k]
            if not item.is_expired():
                return item
        return d

    def get_ip(self, mac):
        for k in self.keys():
            if self[k] == mac:
                return k

    def add_entry(self, ip, mac):
        self[ip] = _ArpEntry(ip, mac)
        self._logger.info('Arp entry added: %s %s.', ip, mac)


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


class _PendingArps(object):
    def __init__(self, app):
        super(_PendingArps, self).__init__()
        self.items = []
        self.app = app

    def add(self, ip, out_ip, out_port):
        self.items.append(_ArpRequest(ip, self, out_ip, out_port))

    def delete(self, ip):
        to_delete = [item for item in self.items if item.ip == ip]
        if len(to_delete) == 0:
            return
        hub.kill(to_delete[0].wait_thread)
        self.items = [item for item in self.items if item.ip != ip]

    def contains(self, ip):
        seleted = [item for item in self.items if item.ip == ip]
        if len(seleted) == 0:
            return False
        if seleted[0].done:
            self.delete(ip)
            return False
        return True


class _ArpRequest(object):
    def __init__(self, ip, parent, out_ip, out_port):
        self.ip = ip
        self.parent = parent
        self.out_ip = out_ip
        self.out_port = out_port
        self.wait_thread = hub.spawn(self.timer)
        self.done = False

    def timer(self):
        for i in range(0, 15):
            self.parent.app._logger.info('Sending ARP for %s on %d',
                                         self.ip, self.out_port)
            self.parent.app.send_arp(self.out_ip, self.ip, port=self.out_port)
            time.sleep(1)
        self.done = True


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
            try:
                self.remove(pkt)
                hub.kill(pkt.wait_thread)
                pkt.wait_thread.wait()
            except ValueError:
                pass

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
        self.src_ip = header_list[IPV4].src
        self.header_list = header_list
        self.data = data
        # Start ARP reply wait timer.
        self.wait_thread = hub.spawn(timer, self)


class _Group(object):
    def __init__(self, group_id, watch_ports, output_ports, inport,
                 group_table):
        super(_Group, self).__init__()
        self.id = group_id
        self.inport = inport
        self.group_table = group_table
        self.output_ports = output_ports
        self.watch_ports = watch_ports

    def __eq__(self, other):
        return self.inport == other.inport \
               and self.output_ports == other.output_ports \
               and self.watch_ports == other.watch_ports

    def __ne__(self, other):
        return not self.__eq__(other)

    def install(self):
        output_ports, src_macs, dst_macs = self._get_ports_and_macs()
        ofctl = self.group_table.ofctl
        ofctl.add_failover_group(self.id, self.watch_ports, output_ports,
                                 src_macs, dst_macs)

    def update(self):
        output_ports, src_macs, dst_macs = self._get_ports_and_macs()
        ofctl = self.group_table.ofctl
        ofctl.modify_failover_group(self.id, self.watch_ports, output_ports,
                                    src_macs, dst_macs)

    def _get_ports_and_macs(self):
        ports = self.group_table.ports
        ofctl = self.group_table.ofctl
        output_ports = [
            port_no if port_no != self.inport else
            ofctl.dp.ofproto.OFPP_IN_PORT for port_no in self.output_ports]
        src_macs = [ports[port_no].mac for port_no in self.output_ports]
        dst_macs = [ports[port_no].peer_mac for port_no in self.output_ports]
        return output_ports, src_macs, dst_macs


class _GroupTable(dict):
    def __init__(self, ofctl, ports):
        super(_GroupTable, self).__init__()
        self.group_id = 1
        self.ofctl = ofctl
        self.ports = ports

    def clear(self):
        super(_GroupTable, self).clear()

    def add_entry(self, output_ports, inport):
        # Reuse group if possible
        for group in self.values():
            if group.inport == inport and group.output_ports == output_ports:
                return group
        group = _Group(self.group_id, output_ports, output_ports, inport, self)
        self[self.group_id] = group
        self.group_id += 1
        group.install()
        return group

    def update_entry(self, port_no):
        for group in self.values():
            if port_no in group.output_ports:
                group.update()


class _Route(object):
    def __init__(self, route_id, dst_ip, netmask, in_port, out_group):
        super(_Route, self).__init__()
        self.route_id = route_id
        self.dst_ip = dst_ip
        self.netmask = netmask
        self.in_port = in_port
        self.out_group = out_group

        # Used only in OpenFlow 1.0
        self.active_out_port = None


class _RoutingTable(dict):
    def __init__(self, logger):
        super(_RoutingTable, self).__init__()
        self._logger = logger
        self.route_id = 0

    def add_entry(self, dst_ip, in_port, out_group):
        dst, netmask, ip_str = nw_addr_aton(dst_ip)
        key = '%d:%s/%d' % (in_port, dst, netmask)
        if key in self:
            self._logger.error('Route %s overlapped.', key)
        routing_data = _Route(route_id=self.route_id,
                              dst_ip=dst,
                              netmask=netmask,
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
            if ipv4_apply_mask(ip, port.netmask) == port.nw:
                return port

    def get_by_mac(self, mac):
        for port in self.values():
            if port.mac == mac:
                return port


class _Port(object):
    _PORT_UP = 1
    _PORT_DOWN = 0

    def __init__(self, port_no, mac, name):
        super(_Port, self).__init__()
        self.port_no = port_no
        self.name = name
        self.ip = None
        self.nw = None
        self.netmask = None
        self.mac = mac
        self.peer_mac = None
        self.links = {}
        self.status = self._PORT_UP
        self.peer_ip = None

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

    def set_peer_ip(self, ip):
        self.peer_ip = ip


class _DisabledFailoverPorts(dict):
    """
    disabled port -> [downed 1st option port_no]
    """

    def __init__(self):
        super(_DisabledFailoverPorts, self).__init__()

    def disable_port(self, port, due_port):
        if port not in self:
            self[port] = set()
        self[port].add(due_port)

    def port_recoverd(self, due_port):
        updated = False
        for port in self:
            if due_port in self[port]:
                self[port].remove(due_port)
                updated = True
            if len(self[port]) == 0:
                del self[port]
        return updated
