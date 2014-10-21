from routing import Routing


class KFRouting(Routing):
    def __init__(self):
        super(KFRouting, self).__init__()
        self._routing_tables = {}


