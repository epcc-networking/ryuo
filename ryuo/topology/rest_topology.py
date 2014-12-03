from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from ryu.lib import dpid as dpid_lib

from ryuo.controller.central import Ryuo
from ryuo.topology.api import get_switch, get_link
from ryuo.utils import json_response


class TopologyAPI(Ryuo):
    _CONTEXTS = {
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(TopologyAPI, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(TopologyController, {'topology_api_app': self})


class TopologyController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TopologyController, self).__init__(req, link, data, **config)
        self.topology_api_app = data['topology_api_app']

    @route('topology', '/topology/switches',
           methods=['GET'])
    def list_switches(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/topology/switches/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_switch(self, req, **kwargs):
        return self._switches(req, **kwargs)

    @route('topology', '/topology/links',
           methods=['GET'])
    def list_links(self, req, **kwargs):
        return self._links(req, **kwargs)

    @route('topology', '/topology/links/{dpid}',
           methods=['GET'], requirements={'dpid': dpid_lib.DPID_PATTERN})
    def get_links(self, req, **kwargs):
        return self._links(req, **kwargs)

    def _switches(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        switches = get_switch(self.topology_api_app, dpid)
        return json_response([switch.to_dict() for switch in switches])

    def _links(self, req, **kwargs):
        dpid = None
        if 'dpid' in kwargs:
            dpid = dpid_lib.str_to_dpid(kwargs['dpid'])
        links = get_link(self.topology_api_app, dpid)
        return json_response([link.to_dict() for link in links])


