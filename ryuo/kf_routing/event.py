from ryu.controller import event


class EventAddressBase(event.EventBase):
    def __init__(self, address):
        super(EventAddressBase, self).__init__()
        self.address = address

    def __str__(self):
        return '%s<dpid=%s, port=%d, ip=%s/%d>' % (self.__class__.__name__,
                                                   self.address.dpid,
                                                   self.address.port_no,
                                                   self.address.ip,
                                                   self.address.netmask)


class EventAddressAdd(EventAddressBase):
    def __init__(self, address):
        super(EventAddressAdd, self).__init__(address)


class EventAddressRemove(EventAddressBase):
    def __init__(self, address):
        super(EventAddressRemove, self).__init__(address)


class Address(object):
    def __init__(self, dpid, port_no, ip, netmask):
        self.dpid = dpid
        self.port_no = port_no
        self.ip = ip
        self.netmask = netmask

    def to_dict(self):
        return {'dpid': self.dpid,
                'port_no': self.port_no,
                'ip': self.ip,
                'netmask': self.netmask}
