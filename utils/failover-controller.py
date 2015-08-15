#!/usr/bin/env python2

"""
L3 switch with failover support.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ether
from ryu.ofproto import ofproto_v1_3

class L3Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L3Switch, self).__init__(*args, **kwargs)

    def add_route(self, datapath, dst_ip, out_port):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
                eth_type = 0x800,
                ipv4_dst = (dst_ip, '255.255.255.0'))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath     = datapath,
                match        = match,
                cookie       = 0,
                command      = ofproto.OFPFC_ADD,
                idle_timeout = 0,
                hard_timeout = 0,
                priority     = ofproto.OFP_DEFAULT_PRIORITY,
                flags        = ofproto.OFPFF_SEND_FLOW_REM,
                instructions = inst)

        datapath.send_msg(mod)

    def send_port_mod(self, port_no, datapath, hw_addr):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        mask = 0
        advertise = ()
        config = 0
        req = ofp_parser.OFPPortMod(datapath, port_no, hw_addr, config, mask,
                advertise)
        datapath.send_msg(req)

    def flood_entry(self, datapath, all_ports, enabled_ports):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_paser
        for in_port in all_ports:
            match = ofproto_parser.OFPMatch(eth_dst = 'ff:ff:ff:ff:ff:ff',
                                            in_port = in_port)
            actions = [ofproto_parser.OF]


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg   = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = ev.msg.datapath_id

        self.logger.info("DPID %d comes up", dpid)

        routing_table = [[],
                         ['10.0.6.2', 2],
                         ['10.0.6.2', 2],
                         ['10.0.6.2', 2],
                         ['10.0.6.2', 1]]
        self.add_route(datapath, routing_table[dpid][0], routing_table[dpid][1])
        # Flow Miss
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(
                datapath = datapath,
                buffer_id = msg.buffer_id,
                in_port = msg.match['in_port'],
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                data = None)
        
        datapath.send_msg(out)
        self.logger.info("Packet in");

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

