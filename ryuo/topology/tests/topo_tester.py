import random
import time

from ryu.base import app_manager

from ryuo.tests.tester import Tester, ryuo_test
from ryuo.tests.utils import name_to_dpid
from ryuo.topology.api import get_all_link


class TopoTester(Tester):
    def __init__(self, *args, **kwargs):
        super(TopoTester, self).__init__(
            '/home/zsy/Projects/resilient/ryuo/tests/topo/Aarnet.gml',
            'ryuo.topology.topology_local',
            '/home/zsy/Projects/resilient', *args, **kwargs)

    @ryuo_test(order=1)
    def all_links(self):
        pass

    def verify_all_links(self, dummy):
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

    @ryuo_test(order=2, repeat=5)
    def links_down(self):
        links = random.sample(self.net.links,
                              random.randint(1, len(self.net.links)))
        for link in links:
            self.net.configLinkStatus(
                link.intf1.node.name, link.intf2.node.name, 'down')
        time.sleep(len(links))
        return links

    def verify_links_down(self, down_links):
        links = [(link.src.dpid, link.dst.dpid) for link in get_all_link(self)]
        res = True
        for down_link in down_links:
            src = int(down_link.intf1.node.dpid, 16)
            dst = int(down_link.intf2.node.dpid, 16)
            self._logger.info((src, dst))
            if (src, dst) in links:
                self._logger.error('%d <-> %d should be down.', src, dst)
                res = False
            if (dst, src) in links:
                self._logger.error('%d <-> %d should be down.', dst, src)
                res = False
        return res

    def clean_links_down(self, links):
        for link in links:
            self.net.configLinkStatus(
                link.intf1.node.name, link.intf2.node.name, 'up')
        time.sleep(len(links))

    @ryuo_test(order=3)
    def links_up_again(self):
        pass

    def verify_links_up_again(self, dummy):
        return self.verify_all_links(dummy)


app_manager.require_app('ryuo.topology.app')