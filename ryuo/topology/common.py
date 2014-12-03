import logging

from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str


LOG = logging.getLogger(__name__)


class PortData(object):
    """
    Passing port information between ryuo and ryu.
    """

    def __init__(self, dpid, ofpport=None, ofproto=None, port_no=None,
                 hw_addr=None):
        super(PortData, self).__init__()
        self.dpid = dpid

        self.port_no = port_no
        self.hw_addr = hw_addr
        self.ofpport = None
        if ofpport:
            self.port_no = ofpport.port_no
            self.hw_addr = ofpport.hw_addr
            self.ofpport = ofpport
            self.OFPP_MAX = ofproto.OFPP_MAX
            self.OFPPS_LINK_DOWN = ofproto.OFPPS_LINK_DOWN
            self.OFPPC_PORT_DOWN = ofproto.OFPPC_PORT_DOWN


class Port(object):
    """
    Act as ryu.topology.switches.Port but don't hold
    an ofproto object
    """

    LIVE_MSG = {False: 'DOWN', True: 'LIVE'}

    def __init__(self, port_data):
        super(Port, self).__init__()
        self.dpid = port_data.dpid

        self.port_no = port_data.port_no
        self.hw_addr = port_data.hw_addr

        if port_data.ofpport:
            self.hw_addr = port_data.ofpport.hw_addr
            self.name = port_data.ofpport.name
        else:
            self.name = "N/A"

        self.port_data = port_data

    def modify(self, ofpport):
        self.port_data.ofpport = ofpport
        self.hw_addr = ofpport.hw_addr
        self.name = ofpport.name

    def is_reserved(self):
        return self.port_no > self.port_data.OFPP_MAX

    def is_down(self):
        ofpport = self.port_data.ofpport
        return (ofpport.state & self.port_data.OFPPS_LINK_DOWN) > 0 \
               or (ofpport.config & self.port_data.OFPPC_PORT_DOWN) > 0

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
        return 'Port<dpid=%s, port_no=%s, %s>' % \
               (self.dpid, self.port_no, self.LIVE_MSG[self.is_alive()])


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
        return port

    def update_port(self, port_data):
        port = self.ports[port_data.port_no]
        if port_data.ofpport is None:
            port_data.ofpport = port.port_data.ofpport
        port.port_data = port_data
        port.hw_addr = port_data.hw_addr
        return port

    def del_port(self, port_data):
        port = self.ports[port_data.port_no]
        del self.ports[port_data.port_no]
        return port

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'ports': [port.to_dict() for port in self.ports.values()]}

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dpid
        for port in self.ports.values():
            msg += str(port) + ' '
        msg += '>'
        return msg
