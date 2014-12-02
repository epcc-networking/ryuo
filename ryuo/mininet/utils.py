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
        ips.append(['10.0.%d.1/24' % begin_net, dpid1, port1])
        ips.append(['10.0.%d.2/24' % begin_net, dpid2, port2])
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
        ips.append(['10.0.%d.1/24' % begin_net, int(switch.dpid, 16),
                    switch.ports[link.intf1]])
        host.setIP('10.0.%d.2' % begin_net, 24)
        host.setDefaultRoute(link.intf2)
        begin_net += 1
    return begin_net, ips