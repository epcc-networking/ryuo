class Port(object):
    _PORT_UP = 1
    _PORT_DOWN = 0

    def __init__(self, port_no, mac):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = mac
        self.ip = None
        self.nw = None
        self.netmask = None
        self.links = {}
        self.status = self._PORT_UP

    def set_ip(self, nw, mask, ip):
        self.nw = nw
        self.netmask = mask
        self.ip = ip

    def add_link(self, link):
        self.links[link.dst.hw_addr] = link

    def is_up(self):
        return self.status == self._PORT_UP

    def up(self):
        self.status = self._PORT_UP

    def down(self):
        self.status = self._PORT_DOWN
