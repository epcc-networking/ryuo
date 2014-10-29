#!/usr/bin/env python2
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

OFP = 'OpenFlow13'


class KeepForwardingTestTopo(Topo):
    """
    Simple topology to test keep forwarding implementation

               4.1     4.2   7.1   7.2
               ,----------s4---------,
               |                     |
    1.2     1.1|3.1     3.2  6.1  6.2|8.1   8.2
    h1---------s1----------s3--------s5------h2
               |           |
               |           |
               '----s2-----'
             2.1 2.2  5.1  5.2
    """

    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost('h1',
                          ip='10.0.1.2/24',
                          defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2',
                          ip='10.0.8.2/24',
                          defaultRoute='via 10.0.8.1')

        s = [self.addSwitch('s%d' % (i + 1), protocols=OFP) for i in
             range(0, 5)]

        self.addLink(h1, s[0])
        self.addLink(h2, s[4])

        graph = [[0, 1, 1, 1, 0],
                 [1, 0, 1, 0, 0],
                 [1, 1, 0, 0, 1],
                 [1, 0, 0, 0, 1],
                 [0, 0, 1, 1, 0]]

        for i in range(0, 5):
            for j in range(0, i):
                if graph[i][j] == 1:
                    self.addLink(s[i], s[j])


def run():
    OVSSwitch.setup()
    setLogLevel('debug')

    net = Mininet(topo=KeepForwardingTestTopo(),
                  switch=OVSSwitch,
                  controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    run()