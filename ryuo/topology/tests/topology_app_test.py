#!/usr/bin/env python2
import subprocess
import time

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
    ryuo_ns = subprocess.Popen(['/home/zsy/Projects/resilient/ryuo-ns'])
    time.sleep(3)
    # Run Ryuo app
    ryuo_app = subprocess.Popen(['ryu-manager', 'ryuo.topology.app'],
                                cwd=working_dir, stdout=subprocess.PIPE)
    time.sleep(4)
    net = Mininet(topo=RyuoTopoFromTopoZoo(topology_gml_file,
                                           'OpenFlow13',
                                           working_dir,
                                           local_apps),
                  switch=RyuoOVSSwitch,
                  controller=RemoteController,
                  link=TCLink)
    net.start()
    time.sleep(10)
    net.stop()
    ryuo_app.kill()
    ryuo_ns.kill()


def test():
    RyuoOVSSwitch.setup()
    on_topology('/home/zsy/Projects/resilient/ryuo/tests/topo/Aarnet.gml')

