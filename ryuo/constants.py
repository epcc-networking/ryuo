from ryu.lib import dpid as dpid_lib

from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib.packet import icmp

MAX_SUSPENDPACKETS = 50  # Threshold of the packet suspends thread count.
DEFAULT_TTL = 64
ARP_REPLY_TIMER = 2  # sec
IDLE_TIMEOUT = 1800  # sec

PORTNO_PATTERN = r'[0-9]{1,8}|all'
ROUTER_ID_PATTERN = dpid_lib.DPID_PATTERN + r'|all'

UINT16_MAX = 0xffff
UINT32_MAX = 0xffffffff
UINT64_MAX = 0xffffffffffffffff

PRIORITY_VLAN_SHIFT = 1000
PRIORITY_NETMASK_SHIFT = 32

PRIORITY_NORMAL = 0
PRIORITY_ARP_HANDLING = 1
PRIORITY_DEFAULT_ROUTING = 1
PRIORITY_MAC_LEARNING = 2
PRIORITY_STATIC_ROUTING = 2
PRIORITY_IMPLICIT_ROUTING = 3
PRIORITY_L2_SWITCHING = 4
PRIORITY_IP_HANDLING = 5

PRIORITY_TYPE_ROUTE = 'priority_route'

ETHERNET = ethernet.ethernet.__name__
IPV4 = ipv4.ipv4.__name__
ARP = arp.arp.__name__
ICMP = icmp.icmp.__name__
TCP = tcp.tcp.__name__
UDP = udp.udp.__name__

PORT_UP = 1
PORT_DOWN = 0

LINK_UP = 1
LINK_DOWN = 0