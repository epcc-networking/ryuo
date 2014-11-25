import random

from ryuo.tests.tester import Tester, deadline
from ryuo.tests.utils import name_to_dpid
from ryuo.topology.api import get_all_link


class TopoTester(Tester):
    def __init__(self, *args, **kwargs):
        super(TopoTester, self).__init__(
            '/home/zsy/Projects/resilient/ryuo/tests/topo/Aarnet.gml',
            'ryuo.topology.topology_local',
            '/home/zsy/Projects/resilient', *args, **kwargs)

    def test_1_links(self):
        pass

    def verify_1_links(self, dummy):
        links = get_all_link(self)
        if len(links) / 2 == len(self.net.links):
            links = [(link.src.dpid, link.dst.dpid) for link in links]
            mn_links = self.net.topo.links()
            for (src, dst) in mn_links:
                src_dpid = name_to_dpid(src)
                dst_dpid = name_to_dpid(dst)
                return ((src_dpid, dst_dpid) in links) or (
                    (dst_dpid, src_dpid) in links)
        return False

    @deadline(seconds=2)
    def test_link_down(self):
        links = random.sample(self.net.links,
                              random.randint(1, len(self.net.links)))
        for link in links:
            self.net.configLinkStatus(
                link.intf1.node.name, link.intf2.node.name, 'down')

        return links

    def verify_link_down(self, down_links):
        links = [(link.src.dpid, link.dst.dpid) for link in get_all_link(self)]
        for down_link in down_links:
            src = name_to_dpid(down_link.intf1.node.dpid)
            dst = name_to_dpid(down_link.intf2.node.dpid)
            if (src, dst) in links or (dst, src) in links:
                return False
        return True

    @deadline(seconds=2)
    def clean_link_down(self, links):
        for link in links:
            self.net.configLinkStatus(
                link.intf1.node.name, link.intf2.node.name, 'up')
