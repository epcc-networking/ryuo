#!/usr/bin/env python2
import Pyro4
from ryu.controller.handler import set_ev_cls
from ryu.topology import event

from ryuo.common.central import Ryuo


class TopologyApp(Ryuo):
    def __init__(self, *args, **kwargs):
        super(TopologyApp, self).__init__(args, kwargs)
        self.links = {}  # {dpid: [links]}

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        dpid = req.dpid
        if dpid is None:
            links = [link for link in self.links[dpid] for dpid in
                     self.links.keys()]
        else:
            links = self.links[dpid]
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @Pyro4.expose
    def report_links(self, dpid, links):
        self.links[dpid] = links
        self._logger.info('Link report from %d', dpid)