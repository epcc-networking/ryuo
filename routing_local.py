#!/usr/bin/env python2
from local_controller import LocalController


class RoutingLocal(LocalController):
    def __init__(self, *args, **kwargs):
        super(RoutingLocal, self).__init__(*args, **kwargs)

