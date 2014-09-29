# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_group_mod(self, datapath, group_id, port1, port2):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        max_len = 2000
        actions1 = [ofp_parser.OFPActionOutput(port1, max_len)]
        actions2 = [ofp_parser.OFPActionOutput(port2, max_len)]

        weight = 0
        watch_group = 0
        buckets = [ofp_parser.OFPBucket(weight, port1, watch_group, actions1),
                   ofp_parser.OFPBucket(weight, port2, watch_group, actions2)]

        req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_ADD,
                ofp.OFPGT_FF,
                group_id, buckets)

        datapath.send_msg(req)

    def install_entry(self, datapath, dst, group_id):
        ofproto = datapath.ofproto
        ofproto_parser = datapath.ofproto_parser

        match = ofproto_parser.OFPMatch(eth_dst = dst)
        actions = [ofproto_parser.OFPActionGroup(group_id = group_id)]
        inst = [ofproto_parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = ofproto_parser.OFPFlowMod(
                datapath     = datapath,
                match        = match,
                cookie       = group_id,
                command      = ofproto.OFPFC_ADD,
                idle_timeout = 0,
                hard_timeout = 0,
                priority     = ofproto.OFP_DEFAULT_PRIORITY,
                flags        = ofproto.OFPFF_SEND_FLOW_REM,
                instructions = inst)  

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = ev.msg.datapath_id

        self.logger.info("DPID %d comes up", dpid)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.send_group_mod(datapath, 1, 1, 2)
        self.send_group_mod(datapath, 2, 2, 3)
        self.send_group_mod(datapath, 3, 3, 1)

        self.install_entry(datapath, '00:00:00:00:00:01', 1)
        self.install_entry(datapath, '00:00:00:00:00:02', 2)
        self.install_entry(datapath, '00:00:00:00:00:03', 3)

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

