import Pyro4


class AppLookupServer(object):
    def __init__(self):
        self._ns = Pyro4.locateNS()
        self._connection = _NSConnection(self._ns)

    def lookup(self, name):
        with self._connection:
            return Pyro4.Proxy(self._ns.lookup(name))

    def remove(self, name):
        with self._connection:
            self._ns.remove(name)

    def register(self, name, uri):
        with self._connection:
            self._ns.register(name, uri)


class _NSConnection(object):
    def __init__(self, ns):
        self._ns = ns

    def __enter__(self):
        return self._ns._pyroReconnect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._ns._pyroRelease()