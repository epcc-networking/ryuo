PORT_UP = 1
PORT_DOWN = 0


class Port(object):
    def __init__(self, port_no, mac):
        super(Port, self).__init__()
        self.port_no = port_no
        self.mac = mac
        self.ip = None
        self.nw = None
        self.netmask = None
        self.links = {}
        self.status = PORT_UP

    def set_ip(self, nw, mask, ip):
        self.nw = nw
        self.netmask = mask
        self.ip = ip

    def add_link(self, link):
        self.links[link.dst.hw_addr] = link