from socket import error as SocketError

from ryu.app.wsgi import WSGIApplication, ControllerBase, websocket, \
    WebSocketRPCClient
from ryu.contrib.tinyrpc import InvalidReplyError
from ryu.controller.handler import set_ev_cls

from ryuo.controller.central import Ryuo
from ryuo.topology.app import TopologyApp
from ryuo.topology.event import EventSwitchEnter, EventSwitchLeave, \
    EventLinkAdd, EventLinkDelete


class WebSocketTopology(Ryuo):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'topology': TopologyApp
    }

    def __init__(self, *args, **kwargs):
        super(WebSocketTopology, self).__init__(*args, **kwargs)
        self.rpc_clients = []
        wsgi = kwargs['wsgi']
        wsgi.register(WebSocketTopologyController, {'app': self})

    @set_ev_cls(EventSwitchEnter)
    def _event_switch_enter(self, ev):
        msg = ev.switch.to_dict()
        self._rpc_broadcall('event_switch_enter', msg)

    @set_ev_cls(EventSwitchLeave)
    def _event_switch_leave(self, ev):
        msg = ev.switch.to_dict()
        self._rpc_broadcall('event_switch_leave', msg)

    @set_ev_cls(EventLinkAdd)
    def _event_link_add(self, ev):
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_add', msg)

    @set_ev_cls(EventLinkDelete)
    def _event_link_delete(self, ev):
        msg = ev.link.to_dict()
        self._rpc_broadcall('event_link_delete', msg)

    def _rpc_broadcall(self, func_name, msg):
        disconnected_clients = []
        for rpc_client in self.rpc_clients:
            rpc_server = rpc_client.get_proxy()
            try:
                getattr(rpc_server, func_name)(msg)
            except SocketError:
                self._logger.debug('WebSocket disconnected: %s', rpc_client.ws)
                disconnected_clients.append(rpc_client)
            except InvalidReplyError as e:
                self._logger.error(e)
        for client in disconnected_clients:
            self.rpc_clients.remove(client)


class WebSocketTopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(WebSocketTopologyController, self).__init__(
            req, link, data, **config)
        self.app = data['app']

    @websocket('topology', '/topology/ws')
    def _websocket_handler(self, ws):
        rpc_client = WebSocketRPCClient(ws)
        self.app.rpc_clients.append(rpc_client)
        rpc_client.serve_forever()
