import Pyro4


class RPCDaemon(object):
    def __init__(self):
        self._deamon = Pyro4.Daemon()

    def register(self, obj):
        return self._deamon.register(obj)

    def requestLoop(self):
        self._deamon.requestLoop()