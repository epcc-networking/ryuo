from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str


class PortData(object):
    """
    Passing port information between ryuo and ryu.
    """

    def __init__(self, dpid, ofproto=None, ofpport=None, port_no=None):
        super(PortData, self).__init__()
        self.dpid = dpid
        if ofpport and ofproto:
            self.port_no = ofpport.port_no
            self.hw_addr = ofpport.hw_addr
            self.name = ofpport.name
            self.is_reserved = self.port_no > ofproto.OFPP_MAX
            self.is_down = (ofpport.state & ofproto.OFPPS_LINK_DOWN) > 0 \
                           or (ofpport.config & ofproto.OFPPC_PORT_DOWN)
        else:
            self.port_no = port_no
            self.hw_addr = None
            self.name = None
            self.is_down = False
            self.is_reserved = False


class Port(object):
    """
    Act as ryu.topology.switches.Port but don't hold
    an ofproto object
    """

    def __init__(self, port_data):
        super(Port, self).__init__()
        self.dpid = port_data.dpid

        self.port_no = port_data.port_no
        self.hw_addr = port_data.hw_addr
        self.name = port_data.name

        self._is_reserved = port_data.is_reserved
        self._is_down = port_data.is_down
        self.port_data = port_data

    def is_reserved(self):
        return self._is_reserved

    def is_down(self):
        return self._is_down

    def is_alive(self):
        return not self.is_down()

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'port_no': port_no_to_str(self.port_no),
                'hw_addr': self.hw_addr,
                'name': self.name.rstrip('\0')}

    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
               (self.dpid, self.port_no, LIVE_MSG[self.is_alive()])


class Switch(object):
    def __init__(self, dpid):
        super(Switch, self).__init__()
        self.dp = None
        self.dpid = dpid
        self.ports = {}  # port_no -> Port

    def add_port(self, port_data):
        port = Port(port_data)
        if not port.is_reserved():
            self.ports[port.port_no] = port

    def del_port(self, port_data):
        del self.ports[port_data.port_no]

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'ports': [port.to_dict for port in self.ports.values()]}

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dpid
        for port in self.ports.values():
            msg += str(port) + ' '
        msg += '>'
        return msg

