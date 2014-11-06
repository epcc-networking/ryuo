#!/usr/bin/env python2
import logging

import Pyro4
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_2

from utils import config_logger


Pyro4.config.REQUIRE_EXPOSE = True


class LocalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LocalController, self).__init__(*args, **kwargs)
        self._setup_logger()
        self._rpc_daemon = None

    def _run_rpc_daemon(self, dpid):
        daemon = Pyro4.Daemon()
        uri = daemon.register(self)
        self._ns = Pyro4.locateNS()
        self._ns.register('local-%d' % dpid, uri)
        host_uri = self._ns.lookup('central-host')
        self.host = Pyro4.Proxy(host_uri)
        self._logger.info('Central host uri: %s', host_uri)
        self.host.register(dpid)
        self._logger.info(uri)
        daemon.requestLoop()

    def _register(self, dp):
        self._setup_logger(dp.id)
        self._rpc_daemon = hub.spawn(self._run_rpc_daemon, dp.id)
        self._logger.info('Ready to work')

    def _unregister(self):
        if self._rpc_daemon is not None:
            self._rpc_daemon.close()
            self._rpc_daemon = None

    def _setup_logger(self, dpid=None):
        if dpid is None:
            dpid = '?'
        self._logger = logging.getLogger(
            self.__class__.__name__ + ' ' + str(dpid))
        config_logger(self._logger)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            self._register(ev.dp)
        else:
            self._unregister()
