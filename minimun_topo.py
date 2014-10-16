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

class MinimumTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost('h1', ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
        h2 = self.addHost('h2', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')

        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        self.addLink(h1, s1)
        self.addLink(h2, s1)

def run():
    OVSSwitch.setup()
    setLogLevel('debug')

    net = Mininet(topo=MinimumTopo(), switch=OVSSwitch,
                  controller=RemoteController)
    net.start()
    CLI(net)
    net.stop()

if __name__  == '__main__':
    run()
