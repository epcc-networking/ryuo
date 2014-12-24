import logging
from multiprocessing import Lock

import Pyro4
from ryu.base import app_manager
from ryu.controller import dpset
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_2, ofproto_v1_3

from ryuo.utils import config_logger, lock_class
from ryuo.config import CENTRAL_HOST_NAME
from ryuo.local.ofctl import OfCtl


Pyro4.config.REQUIRE_EXPOSE = True
Pyro4.config.SERIALIZER = 'pickle'
Pyro4.config.SERIALIZERS_ACCEPTED = {'json', 'marshal', 'serpent', 'pickle'}
Pyro4.config.HOST = '192.168.0.10'


@lock_class([], Lock)
class LocalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LocalController, self).__init__(*args, **kwargs)
        self._setup_logger()
        self._rpc_thread = None
        self.uri = None
        self.ryuo_name = kwargs.get('ryuo_name', CENTRAL_HOST_NAME)
        self.app_name = None
        self.name = self.__class__.__name__

        self._rpc_daemon = Pyro4.Daemon()
        self.uri = self._rpc_daemon.register(self)
        self._ns = Pyro4.locateNS()
        host_uri = self._ns.lookup(self.ryuo_name)
        self._ns._pyroRelease()
        self.ryuo = Pyro4.Proxy(host_uri)
        self._logger.info('%s host uri: %s', self.ryuo_name, host_uri)
        self.ryuo.ryuo_register(self.uri)
        self._rpc_thread = hub.spawn(self._run_rpc_daemon)
        self.threads.append(self._rpc_thread)

    def close(self):
        self.ryuo.ryuo_unregister(self.uri)
        self._rpc_daemon.shutdown()
        self._rpc_daemon = None
        hub.joinall(self.threads)

    def _run_rpc_daemon(self):
        self._rpc_daemon.requestLoop()

    def _switch_enter(self, dp):
        self.app_name = "%s-%d" % (self.__class__.__name__, dp.id)
        self._ns._pyroReconnect()
        self._ns.register(self.app_name, self.uri)
        self._ns._pyroRelease()
        self._setup_logger(dp.id)
        self.dp = dp
        self.ofctl = OfCtl(dp, self._logger)
        self._logger.info('Switch entered, ready to work')

        self.ryuo.ryuo_switch_enter(dp.id, self.uri)

    def _switch_leave(self):
        self.ryuo.ryuo_switch_leave(self.dp.id, self.uri)
        self._ns._pyroReconnect()
        self._ns.remove(self.app_name)
        self._ns._pyroRelease()
        self.app_name = None
        self.ofctl = None
        self.dp = None

    def _setup_logger(self, dpid=None):
        if dpid is None:
            dpid = '?'
        self._logger = logging.getLogger(
            self.__class__.__name__ + ' ' + str(dpid))
        config_logger(self._logger)

    @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
    def datapath_handler(self, ev):
        if ev.enter:
            self._switch_enter(ev.dp)
        else:
            self._switch_leave()
