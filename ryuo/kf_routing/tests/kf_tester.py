import subprocess
import time
import random

from ryuo.mininet.utils import assign_ip_to_switches, attach_host_to_switches
from ryuo.tests.tester import Tester
from ryuo.tests.utils import add_addresses


class KFTester(Tester):
    def __init__(self, *args, **kwargs):
        super(KFTester, self).__init__(
            '/home/zsy/Projects/resilient/ryuo/tests/topo/Abilene.gml',
            'ryuo.topology.topology_local ryuo.kf_routing.kf_routing_local',
            '/home/zsy/Projects/resilient', *args, **kwargs)
        self.ips_to_assign = None

    def setup_mininet(self):
        super(KFTester, self).setup_mininet()
        current_net_num = 1
        current_net_num, ips = assign_ip_to_switches(current_net_num, self.net)
        current_net_num, ips = attach_host_to_switches(current_net_num,
                                                       self.net, ips)
        self.ips_to_assign = ips

    def on_all_apps_up(self):
        time.sleep(3)
        add_addresses(self.ips_to_assign, '127.0.0.1')
        time.sleep(2)
        # curl -X POST http://127.0.0.1:8080/router/routing
        subprocess.call(
            ['curl', '-X', 'POST', 'http://127.0.0.1:8080/router/routing'])

    def test_1_ping_all(self):
        time.sleep(5)
        return self.net.pingAll(timeout=2)

    def verify_1_ping_all(self, res):
        return True if res == 0 else False

    def test_2_random_one_link_down(self):
        """
        Randomly break one link, the degree of the two nodes connected by
        the selected link must larger than 1
        :return: the selected link
        """
        link = None
        while True:
            link = random.choice(self.net.links)
            if len(link.intf1.node.ports) > 2 and len(
                    link.intf2.node.ports) > 2:
                break
        self.net.configLinkStatus(link.intf1.node.name,
                                  link.intf2.node.name,
                                  'down')
        return link

    def verify_2_random_one_link_down(self, down_link):
        return self.net.pingAll(timeout=2) == 0

    def clean_2_random_one_link_down(self, down_link):
        self.net.configLinkStatus(down_link.intf1.node.name,
                                  down_link.intf2.node.name,
                                  'up')

    def test_3_link_up_again(self):
        pass

    def verify_3_link_up_again(self, dummy):
        return self.net.pingAll(timeout=2) == 0


