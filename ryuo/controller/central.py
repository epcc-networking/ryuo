#!/usr/bin/env python2
import logging
from threading import Lock

import Pyro4
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

from ryuo.utils import config_logger, lock_class, expose


Pyro4.config.REQUIRE_EXPOSE = True
Pyro4.config.SERIALIZER = 'pickle'
Pyro4.config.SERIALIZERS_ACCEPTED = {'json', 'marshal', 'serpent', 'pickle'}
Pyro4.config.THREADPOOL_SIZE = 160


@lock_class([], Lock)
class Ryuo(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(Ryuo, self).__init__(*args, **kwargs)
        self._setup_logger()
        self._rpc_daemon = None
        self.uri = None
        self.name = self.__class__.__name__
        self.local_apps = {}  # {dpid: ryu instance}
        self._rpc_thread = hub.spawn(self._run_rpc_daemon)
        self.threads.append(self._rpc_thread)

    def _setup_logger(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        config_logger(self._logger)
        self._logger.info('Starting')

    @expose
    def ryuo_register(self, uri):
        self._logger.info("App with uri %s connected.", uri)

    @expose
    def ryuo_unregister(self, uri):
        self._logger.info('App with uri %s leaves.', uri)

    @expose
    def ryuo_switch_enter(self, dpid, uri):
        self._logger.info('Switch %d comes up on uri: %s', dpid, uri)
        self.local_apps[dpid] = Pyro4.Proxy(uri)

    @expose
    def ryuo_switch_leave(self, dpid, uri):
        self._logger.info('Switch %d leaves on uri %s.', dpid, uri)
        del self.local_apps[dpid]

    def _run_rpc_daemon(self):
        self._rpc_daemon = Pyro4.Daemon()
        self.uri = self._rpc_daemon.register(self)
        ns = Pyro4.locateNS()
        ns.register(self.name, self.uri)
        self._logger.info('Ryuo running with name %s and uri %s.', self.name,
                          self.uri)
        self._rpc_daemon.requestLoop()
        self._logger.info('Request loop existing...')

    def close(self):
        self._rpc_daemon.shutdown()
        hub.joinall(self.threads)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def stub(self, evt):
        pass

