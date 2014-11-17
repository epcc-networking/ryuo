#!/usr/bin/env python2
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

from ryuo.mininet.node import RyuoOVSSwitch


OFP = 'OpenFlow13'


class RyuoTestingTopo(Topo):
    """
    Simple topology to test keep forwarding smart up-link selection
               2.2  4.1
              ,---s2----,
           2.1|      4.2|
    1.2    1.1|3.1   3.2|6.1   6.2  9.1  9.2
    h1--------s1--------s3--------s6--------h2
                     5.1|         |8.2
                     5.2|         |8.1
                        s4--------s5
                          7.1  7.2

    h1 to h2: h1-s1-s3-s6-h2
    The correct route from h1 to h2 when link s3-s6 is down
    is h1-s1-s3-s4-s5-s6-h2
    """

    def __init__(self, *ryu_args):
        Topo.__init__(self)

        h1 = self.addHost('h1',
                          ip='10.0.1.2/24',
                          defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2',
                          ip='10.0.9.2/24',
                          defaultRoute='via 10.0.9.1')

        working_dir = '/home/zsy/Projects/resilient'

        s = [self.addSwitch('s%d' % (i + 1),
                            controller_working_dir=working_dir,
                            ryu_args=ryu_args,
                            port=6634 + i,
                            protocols=OFP) for i in range(0, 6)]

        self.addLink(h1, s[0])
        self.addLink(h2, s[5])

        graph = [[0, 1, 1, 0, 0, 0],
                 [1, 0, 1, 0, 0, 0],
                 [1, 1, 0, 1, 0, 1],
                 [0, 0, 1, 0, 1, 0],
                 [0, 0, 0, 1, 0, 1],
                 [0, 0, 1, 0, 1, 0]]

        for i in range(0, 6):
            for j in range(i + 1, 6):
                if graph[i][j] == 1:
                    self.addLink(s[i], s[j])


if __name__ == '__main__':
    RyuoOVSSwitch.setup()
    setLogLevel('debug')

    local_apps = 'ryuo.topology.topology_local'

    net = Mininet(topo=RyuoTestingTopo(local_apps),
                  switch=RyuoOVSSwitch,
                  controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()