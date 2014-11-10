#!/usr/bin/env python2
import logging

import Pyro4
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_2

from config import CENTRAL_HOST_NAME, LOCAL_HOST_NAME
from constants import PORT_UP, PORT_DOWN
from local_common.port import Port
from ofctl import OfCtl
from utils import config_logger, ipv4_apply_mask


Pyro4.config.REQUIRE_EXPOSE = True


class LocalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LocalController, self).__init__(*args, **kwargs)
        self._setup_logger()
        self._rpc_daemon = None

    def _run_rpc_daemon(self, dpid):
        self._rpc_daemon = Pyro4.Daemon()
        uri = self._rpc_daemon.register(self)
        self._ns = Pyro4.locateNS()
        self.name = LOCAL_HOST_NAME % dpid
        self._ns.register(self.name, uri)
        host_uri = self._ns.lookup(CENTRAL_HOST_NAME)
        self.host = Pyro4.Proxy(host_uri)
        self._logger.info('Central host uri: %s', host_uri)
        self.host.register(self.name)
        self._rpc_daemon.requestLoop()

    def _register(self, dp):
        self._setup_logger(dp.id)
        self.dp = dp
        self.ports = Ports(dp.ports)
        self.ofctl = OfCtl(dp, self._logger)
        self.init_switch()
        hub.spawn(self._run_rpc_daemon, dp.id)
        self._logger.info('Ready to work')

    def _unregister(self):
        if self._rpc_daemon is not None:
            self._rpc_daemon.close()
            self.ofctl = None
            self._rpc_daemon = None
            self.dp = None

    def _setup_logger(self, dpid=None):
        if dpid is None:
            dpid = '?'
        self._logger = logging.getLogger(
            self.__class__.__name__ + ' ' + str(dpid))
        config_logger(self._logger)

    def init_switch(self):
        pass

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            self._register(ev.dp)
        else:
            self._unregister()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_change(self, ev):
        self._logger.info('Received port status message.')
        ofp = self.dp.ofproto
        msg = ev.msg
        port_no = msg.desc.port_no
        if port_no not in self.ports:
            self.ports[port_no] = Port(port_no, msg.desc.hw_addr)
            self._logger.info('Port %d added.', port_no)
        if msg.reason == ofp.OFPPR_ADD:
            self._on_port_up(port_no)
        elif msg.reason == ofp.OFPPR_DELETE:
            self._on_port_down(port_no)
        elif msg.reason == ofp.OFPPR_MODIFY:
            if msg.desc.state & ofp.OFPPS_LINK_DOWN != 0:
                self._on_port_down(port_no)
            else:
                self._on_port_up(port_no)
        else:
            self._logger.warning('Unknown port status message.')

    def _on_port_up(self, port_no):
        self.ports[port_no].status = PORT_UP
        self._logger.info('Port %d up.', port_no)

    def _on_port_down(self, port_no):
        self.ports[port_no].status = PORT_DOWN
        self._logger.info('Port %d down.', port_no)


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
