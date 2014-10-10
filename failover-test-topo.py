#!/usr/bin/env python2

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.node import Host
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.log import setLogLevel
from mininet.link import Intf

class FailoverTestTopo(Topo):
    """
    Simple topology to test failover group
                        10.0.2.2  10.0.3.1
                     ,----------s2----------,
    10.0.1.2 10.0.1.1|10.0.2.1      10.0.3.2|10.0.6.1 10.0.6.2
    h1---------------s1                     s4--------------h2
                     |10.0.4.1      10.0.5.2|
                     '----------s3----------'
                        10.0.4.2  10.0.5.1
    """

    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost(
                'h1',
                ip   = '10.0.1.2/24',
                defaultRoute = 'via 10.0.1.1')
        h2 = self.addHost(
                'h2',
                ip = '10.0.6.2/24',
                defaultRoute = 'via 10.0.6.1')

        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')

        self.addLink(h1, s1)
        self.addLink(h2, s4)
        self.addLink(s1, s2) 
        self.addLink(s2, s4) 
        self.addLink(s1, s3) 
        self.addLink(s3, s4) 

def run():
    OVSSwitch.setup()
    setLogLevel('debug')

    net = Mininet(
            topo        = FailoverTestTopo(),
            switch      = OVSSwitch,
            controller  = RemoteController)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
