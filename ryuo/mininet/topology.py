import math

from mininet.topo import Topo
import networkx


class RyuoTopoFromTopoZoo(Topo):
    """
    Mininet topology that can be created from a gml file.
    All nodes are converted into switches, hosts can be attached
    to arbitrary switch.
    Latency is computed using Longitude and Latitude.
    """

    def __init__(self, gml_file, protocols='OpenFlow13',
                 controller_dir='.', *ryu_args):
        Topo.__init__(self)

        graph = networkx.read_gml(gml_file)

        switches = {int(node['id']): self._add_switch(node,
                                                      controller_dir,
                                                      ryu_args,
                                                      protocols)
                    for node in graph.node.values()}

        for node1 in graph.edge:
            node2s = [node2 for node2 in graph.edge[node1] if node2 < node1]
            for node2 in node2s:
                self._add_link(switches, graph.node[node1], graph.node[node2])

    @staticmethod
    def _get_latency(node1, node2):
        """
        Calculate the link delay using:
        https://github.com/sjas/assessing-mininet/blob/master/parser/GraphML
        -Topo-to-Mininet-Network-Generator.py#L323
        :param node1:
        :param node2:
        :return:
        """
        lat1 = float(node1['Latitude'])
        long1 = float(node1['Longitude'])
        lat2 = float(node2['Latitude'])
        long2 = float(node2['Longitude'])
        first_product = math.sin(lat2) * math.sin(lat1)
        second_product_first_part = math.cos(lat2) * math.cos(lat1)
        second_product_second_part = math.cos(long2 - long1)

        distance = math.radians(
            math.acos(RyuoTopoFromTopoZoo._ensure(
                first_product
                + (second_product_first_part * second_product_second_part)))) \
                   * 6378.137
        return (distance * 1000) / 197000

    @staticmethod
    def _ensure(number):
        if number > 1.0:
            return 1.0
        elif number < -1.0:
            return -1.0
        else:
            return number

    def _add_link(self, switches, node1, node2):
        """
        Convert link information to actual link parameters.
        :param switches:
        :param link:
        :return:
        """
        if 'Latitude' in node1 and 'Longitude' in node1 and \
                        'Latitude' in node2 and 'Longitude' in node2:
            self.addLink(switches[node1['id']],
                         switches[node2['id']],
                         delay='%dms' % self._get_latency(node1, node2))
        else:
            self.addLink(switches[node1['id']], switches[node2['id']])

    def _add_switch(self, node, controller_dir, ryu_args, protocols):
        return self.addSwitch('s%d' % (1 + node['id']),
                              controller_dir=controller_dir,
                              ryu_args=ryu_args,
                              port=6634 + node['id'],
                              protocols=protocols)


class FatTree(Topo):
    def __init__(self, k, link_params=None):
        super(Topo, self).__init__()
        cores = [self.addSwitch('s%d-%d-%d' % (k, i, j),
                                dpid=self._get_dpid(k, i, j)) for i in
                 range(1, k / 2 + 1) for j in range(1, k / 2 + 1)]
        pods = [[self.addSwitch('s%d-%d-%d' % (pod, switch, 1),
                                dpid=self._get_dpid(pod, switch, 1)) for switch
                 in range(k)] for pod in range(k)]

        hosts = [[[self.addHost('h-%d-%d-%d' % (pod, switch, num),
                                ip='10.%d.%d.%d/24' % (pod, switch, num),
                                defaultRoute='10.%d.%d.1' % (pod, switch))
                   for num in range(2, k / 2 + 2)] for switch in range(k / 2)]
                 for pod in range(k)]

        self.ips = {}  # dpid -> ip
        for i in range(1, k / 2 + 1):
            for j in range(1, k / 2 + 1):
                self.ips[self._get_dpid(k, i, j)] = '10.%d.%d.%d/24' % (
                    k, i, j)

        for pod in range(k):
            for switch in range(k):
                self.ips[self._get_dpid(pod, switch, 1)] = '10.%d.%d.1' % (
                    pod, switch)

        for idx, core in enumerate(cores):
            for pod in pods:
                self.addLink(core, pod[idx / (k / 2)])

        for pod in pods:
            for idx, switch in enumerate(pod[0:k / 2]):
                self.addLink(switch, pod[idx + k / 2])

        for podid, pod in enumerate(pods):
            for switchid, switch in enumerate(pod[0:k / 2]):
                for i in range(2, k / 2 + 2):
                    self.addLink(switch, hosts[podid][switchid][i])

    @staticmethod
    def _get_dpid(a, b, c):
        return str(a).zfill(3) + str(b).zfill(3) + str(c).zfill(3)


