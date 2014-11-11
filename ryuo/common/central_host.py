#!/usr/bin/env python2
import logging

import Pyro4

from ryuo.config import CENTRAL_HOST_NAME, LOG_LEVEL
from utils import config_logger


Pyro4.config.REQUIRE_EXPOSE = True


class Host(object):
    def __init__(self):
        super(Host, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        config_logger(self._logger)
        self._logger.info('Starting')

    @Pyro4.expose
    def register(self, name, uri):
        self._logger.info('%s comes up, with uri: %s', name, uri)


if __name__ == '__main__':
    logging.basicConfig(level=LOG_LEVEL)
    host = Host()
    daemon = Pyro4.Daemon()
    uri = daemon.register(host)
    ns = Pyro4.locateNS()
    ns.register(CENTRAL_HOST_NAME, uri)
    daemon.requestLoop()

