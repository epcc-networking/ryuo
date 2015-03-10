#!/usr/bin/env python2
import argparse
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo
import time
from ryuo.mininet.node import TestingHost
from ryuo.tests.utils import add_addresses


class ManySwitchesTopo(Topo):
    def __init__(self, num_of_switches):
        Topo.__init__(self)

        hosts = [self.addHost("h%d" % (i + 1), ip='10.0.%d.2/24' % i,
                              defaultRoute='via 10.0.%d.1' % i) for i in
                 range(num_of_switches)]
        switches = [self.addSwitch("s%d" % (i + 1), protocols='OpenFlow13') for
                    i in range(num_of_switches)]
        for index, host in enumerate(hosts):
            self.addLink(host, switches[index])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--controller-ip', required=True)
    parser.add_argument('-o', '--normal-openflow', default=False,
                        action='store_true')
    parser.add_argument('-n', '--number-of-switches', default=10, type=int)
    args = parser.parse_args()

    if args.normal_openflow:
        net = Mininet(topo=ManySwitchesTopo(args.number_of_switches),
                      switch=OVSSwitch,
                      controller=RemoteController('c1', ip=args.controller_ip),
                      host=TestingHost)
    else:
        net = None
        pass
    try:
        net.start()
        time.sleep(10)
        address = [['10.0.%d.1/24' % i, i + 1, 1] for i in
                   range(args.number_of_switches)]
        add_addresses(address, args.controller_ip)
        # CLI(net)
        time.sleep(1)
        for i, host in enumerate(net.hosts):
            host.sendCmd(
                'ping 10.0.%d.1 -i 0.5 > data/pings/%d.txt' % (i, i))
        time.sleep(20)
    except Exception as e:
        print e
    finally:
        net.stop()
