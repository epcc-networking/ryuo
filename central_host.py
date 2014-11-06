#!/usr/bin/env python2
import logging

import Pyro4

from utils import config_logger


Pyro4.config.REQUIRE_EXPOSE = True


class Host(object):
    def __init__(self):
        super(Host, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        config_logger(self._logger)

    @Pyro4.expose
    def register(self, id):
        self._logger.info('Local %d comes up', id)


if __name__ == '__main__':
    host = Host()
    daemon = Pyro4.Daemon()
    uri = daemon.register(host)
    ns = Pyro4.locateNS()
    ns.register('central-host', uri)
    daemon.requestLoop()

