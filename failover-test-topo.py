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

class VLANIntf(Intf):
    def config(self, mac=None, ip=None, ifconfig=None,
            up=True, **params):
        r = {}
        self.setParam( r, 'setMAC', mac=mac )
        self.setParam( r, 'setIP', ip=ip )
        self.setParam( r, 'isUp', up=up )
        self.setParam( r, 'ifconfig', ifconfig=ifconfig )
        if 'vlan' in params.keys():
            self.vlan = params['vlan']
            self.cmd('ifconfig %s inet 0' % self.name)
            self.cmd('ip link add link %s name %s.%d type vlan id %d' 
                % (self.name, self.name, self.vlan, self.vlan))
            self.cmd('ifconfig %s.%d inet %s' % (self.name, self.vlan, ip))
            self.name = '%s.%d' % (self.name, self.vlan)

        return r

class VLANHost(Host):

   def config(self, vlan=100, **params):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""

        r = super(Host, self).config(**params)

        intf = self.defaultIntf()
        # remove IP from default, "physical" interface
        self.cmd('ifconfig %s inet 0' % intf)
        # create VLAN interface 
        self.cmd('ip link add link %s name %s.%d type vlan id %d' 
                % (intf, intf, vlan, vlan))
        #self.cmd('vconfig add %s %d' % (intf, vlan))
        # assign the host's IP to the VLAN interface
        self.cmd('ifconfig %s.%d inet %s' % (intf, vlan, params['ip']))
                # update the intf name and host's intf map
        newName = '%s.%d' % (intf, vlan)
        # update the (Mininet) interface to refer to VLAN interface name
        intf.name = newName
        # add VLAN interface to host's name to intf map
        self.nameToIntf[newName] = intf

        return r

class FailoverTestTopo(Topo):
    """
    Simple topology to test failover group
                        10.0.2.2  10.0.3.1
                        vlan 102  vlan 103
                     ,----------s2----------,
    10.0.1.2 10.0.1.1|10.0.2.1      10.0.3.2|10.0.6.1 10.0.6.2
    h1---------------s1                     s4--------------h2
         vlan 101    |10.0.4.1      10.0.5.2|    vlan 106
                     '----------s3----------'
                        vlan 104  vlan 105
                        10.0.4.2  10.0.5.1
    """

    def __init__(self):
        Topo.__init__(self)

        h1 = self.addHost(
                'h1',
                #cls  = VLANHost,
                vlan = 101,
                ip   = '10.0.1.2/24',
                defaultRoute = 'via 10.0.1.1')
        h2 = self.addHost(
                'h2',
                #cls  = VLANHost,
                vlan = 106,
                ip = '10.0.6.2/24',
                defaultRoute = 'via 10.0.6.1')

        s1 = self.addSwitch('s1', protocols='OpenFlow13')
        s2 = self.addSwitch('s2', protocols='OpenFlow13')
        s3 = self.addSwitch('s3', protocols='OpenFlow13')
        s4 = self.addSwitch('s4', protocols='OpenFlow13')

        self.addLink(h1, s1, #intf=VLANIntf,
                params2={ 'ip': '10.0.1.1/24', 'vlan': 101 })
        self.addLink(h2, s4, #intf=VLANIntf,
                params2={ 'ip': '10.0.6.1/24', 'vlan': 106 })
        self.addLink(s1, s2, #intf=VLANIntf,
                params1={ 'ip': '10.0.2.1/24', 'vlan': 102 },
                params2={ 'ip': '10.0.2.2/24', 'vlan': 102 })
        self.addLink(s2, s4, #intf=VLANIntf,
                params1={ 'ip': '10.0.3.2/24', 'vlan': 103 },
                params2={ 'ip': '10.0.3.1/24', 'vlan': 103 })
        self.addLink(s1, s3, #intf=VLANIntf,
                params1={ 'ip': '10.0.4.1/24', 'vlan': 104 },
                params2={ 'ip': '10.0.4.2/24', 'vlan': 104 })
        self.addLink(s3, s4, #intf=VLANIntf,
                params1={ 'ip': '10.0.5.1/24', 'vlan': 105 },
                params2={ 'ip': '10.0.5.2/24', 'vlan': 105 })

def run():
    OVSSwitch.setup()
    setLogLevel('debug')

    net = Mininet(
            topo       = FailoverTestTopo(),
            switch     = OVSSwitch,
            controller = RemoteController)
    net.start()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
