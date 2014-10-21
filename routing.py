import logging

_logger = logging.getLogger(__name__)


class Routing(object):
    def __init__(self):
        super(Routing, self).__init__()

    def routing(self, links, switches, routers):
        raise NotImplementedError()

    def update_routing_table(self, links, switches, routers):
        raise NotImplementedError()


