import subprocess
import time

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

from ryuo.mininet.node import RyuoOVSSwitch, TestingHost
from ryuo.mininet.topology import RyuoTopoFromTopoZoo
from ryuo.tests.utils import add_addresses, request_routing


def assign_ip_to_switches(begin_net, net, ips=None):
    """
    Assign ip to each switch ports, in form '10.0.%d.[1,2]/24' % network_num
    :param begin_net: first network_num we can use
    :param net: Mininet object
    :return: (next available network_num, [[ip, dpid, port_no]])
    """
    if ips is None:
        ips = []
    for link in net.links:
        intf1 = link.intf1
        intf2 = link.intf2
        dpid1 = int(intf1.node.dpid, 16)
        dpid2 = int(intf2.node.dpid, 16)
        port1 = intf1.node.ports[intf1]
        port2 = intf2.node.ports[intf2]
        n1 = begin_net / 200
        n2 = begin_net % 200
        ips.append(['10.%d.%d.1/24' % (n1, n2), dpid1, port1])
        ips.append(['10.%d.%d.2/24' % (n1, n2), dpid2, port2])
        begin_net += 1
    return begin_net, ips


def attach_host_to_switches(begin_net, net, ips=None):
    """
    Attach a host to each switch, assign IPs in form '10.0.%d.1/24' to switch,
    '10.0.%d.2/24' to host.
    :param begin_net: first network_num we can use
    :param net: Mininet object
    :return: (next available network_num, [[ip, dpid, port_no]])
    """
    if ips is None:
        ips = []
    for switch in net.switches:
        host = net.addHost('h%d' % int(switch.dpid, 16))
        link = net.addLink(switch, host)
        n1 = begin_net / 200
        n2 = begin_net % 200
        ips.append(['10.%d.%d.1/24' % (n1, n2), int(switch.dpid, 16),
                    switch.ports[link.intf1]])
        host.setIP('10.%d.%d.2' % (n1, n2), 24)
        host.setDefaultRoute('via 10.%d.%d.1' % (n1, n2))
        begin_net += 1
    return begin_net, ips


def mn_from_gml(normal, assign_ip, end_hosts, routing, ryuo_ip, mn_wait,
                gml_file, openflow, local_app_dir, local_apps, ping_all):
    RyuoOVSSwitch.setup()
    subprocess.call(['mn', '-c'])
    if normal:
        net = Mininet(topo=RyuoTopoFromTopoZoo(gml_file,
                                               openflow,
                                               local_app_dir),
                      switch=OVSSwitch,
                      controller=RemoteController,
                      host=TestingHost,
                      link=TCLink)
    else:
        net = Mininet(topo=RyuoTopoFromTopoZoo(gml_file,
                                               openflow,
                                               local_app_dir,
                                               ' '.join(local_apps)),
                      switch=RyuoOVSSwitch,
                      controller=RemoteController,
                      host=TestingHost,
                      link=TCLink)
    net_num = 1
    ips = []
    if assign_ip:
        net_num, ips = assign_ip_to_switches(net_num, net, ips)
    if assign_ip and end_hosts:
        net_num, ips = attach_host_to_switches(net_num, net, ips)
    net.start()
    time.sleep(mn_wait)
    add_addresses(ips, ryuo_ip)
    if routing:
        request_routing(ryuo_ip)
        time.sleep(5)
    if ping_all:
        net.pingAll()
    return net


