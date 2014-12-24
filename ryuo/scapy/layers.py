from array import array

from scapy.fields import XIntField, IntField, StrFixedLenField
from scapy.layers.inet import UDP
from scapy.packet import Packet


class Pktgen(Packet):
    name = 'PKTGEN'
    fields_desc = [XIntField('magic', 0xbe9be955),
                   IntField('seq', 0),
                   IntField('tvsec', 0),
                   IntField('tvusec', 0),
                   StrFixedLenField('data', '\x00\x00\x00\x00\x00\x00',
                                    length=6)]


old_udp_guess_payload = UDP.default_payload_class


def udp_guess_payload_class(self, payload):
    if array('B', payload)[0:4].tolist() == [0xbe, 0x9b, 0xe9, 0x55]:
        return Pktgen
    else:
        return old_udp_guess_payload(self, payload)


UDP.default_payload_class = udp_guess_payload_class