#!/usr/bin/env python2
import subprocess

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import RemoteController

from ryuo.mininet.node import RyuoOVSSwitch
from ryuo.mininet.topology import RyuoTopoFromTopoZoo


def on_topology(topology_gml_file):
    local_apps = 'ryuo.topology.topology_local'
    working_dir = '/home/zsy/Projects/resilient'
    # Clean up environment
    mn_c = subprocess.Popen(['mn', '-c'])
    mn_c.wait()
    # Run Ryuo name server
    ryuo_ns = subprocess.Popen(
        ['bash', '/home/zsy/Projects/resilient/ryuo-ns'],
        cwd=working_dir)
    # Run Ryuo app
    ryuo_app = subprocess.Popen(['ryu-manager', 'ryuo.topology.topology_app'],
                                cwd=working_dir)
    net = Mininet(topo=RyuoTopoFromTopoZoo(topology_gml_file,
                                           'OpenFlow13',
                                           working_dir,
                                           local_apps),
                  switch=RyuoOVSSwitch,
                  controller=RemoteController,
                  link=TCLink)
    net.start()
    print 'OK'
    net.stop()
    ryuo_app.kill()
    ryuo_ns.kill()


def test():
    RyuoOVSSwitch.setup()
    on_topology('/home/zsy/Projects/resilient/ryuo/tests/topo/Aarnet.gml')

