from ryuo.tests.tester import Tester
from ryuo.tests.utils import name_to_dpid
from ryuo.topology.api import get_all_link


class TopoTester(Tester):
    def __init__(self, *args, **kwargs):
        super(TopoTester, self).__init__(
            '/home/zsy/Projects/resilient/ryuo/tests/topo/Aarnet.gml',
            'ryuo.topology.topology_local',
            '/home/zsy/Projects/resilient', *args, **kwargs)

    def test_links(self):
        pass

    def verify_links(self):
        links = get_all_link(self)
        if len(links) / 2 == len(self.net.links):
            links = [(link.src.dpid, link.dst.dpid) for link in links]
            mn_links = self.net.topo.links()
            self._logger.info(mn_links)
            for (src, dst) in mn_links:
                src_dpid = name_to_dpid(src)
                dst_dpid = name_to_dpid(dst)
                return ((src_dpid, dst_dpid) in links) or (
                    (dst_dpid, src_dpid) in links)

        return False


