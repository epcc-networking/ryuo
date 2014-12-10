import os
import re
import subprocess
import time
import argparse

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str

from ryuo.mininet.node import RyuoOVSSwitch
from ryuo.mininet.topology import RyuoTopoFromTopoZoo
from ryuo.mininet.utils import assign_ip_to_switches, attach_host_to_switches


def name_to_dpid(name):
    nums = re.findall(r'\d+', name)
    if nums:
        return int(nums[0])


def add_addresses(addresses, controller_ip):
    for address in addresses:
        ip = address[0]
        router = address[1]
        port = address[2]
        subprocess.call(['curl',
                         '-X',
                         'POST',
                         '-d',
                         '{"address": "%s"}' % ip,
                         'http://%s:8080/router/%s/%s/address' % (
                             controller_ip, dpid_to_str(router),
                             port_no_to_str(port))])


def request_routing(controller_ip):
    subprocess.call(['curl', '-X', 'POST',
                     'http://%s:8080/router/routing' % controller_ip])


def mn_from_gml(normal, assign_ip, end_hosts, routing, ryuo_ip, mn_wait,
                gml_file, openflow, local_app_dir, local_apps, ping_all):
    RyuoOVSSwitch.setup()
    subprocess.call(['mn', '-c'])
    if normal:
        net = Mininet(topo=RyuoTopoFromTopoZoo(gml_file,
                                               openflow,
                                               local_app_dir),
                      switch=OVSSwitch,
                      controller=RemoteController,
                      link=TCLink)
    else:
        net = Mininet(topo=RyuoTopoFromTopoZoo(gml_file,
                                               openflow,
                                               local_app_dir,
                                               ' '.join(local_apps)),
                      switch=RyuoOVSSwitch,
                      controller=RemoteController,
                      link=TCLink)
    net_num = 1
    ips = []
    if assign_ip:
        net_num, ips = assign_ip_to_switches(net_num, net, ips)
    if assign_ip and end_hosts:
        net_num, ips = attach_host_to_switches(net_num, net, ips)
    net.start()
    time.sleep(mn_wait)
    add_addresses(ips, ryuo_ip)
    if routing:
        request_routing(ryuo_ip)
    if ping_all:
        net.pingAll()
    return net


def mn_from_gml_argparser():
    parser = argparse.ArgumentParser(
        description='Create Mininet topology from gml file.')
    parser.add_argument('-g', '--gml-file', help='GML topology description',
                        action='store', required=True)
    parser.add_argument('-o', '--openflow', help='OpenFlow version',
                        action='store', default='OpenFlow13')
    parser.add_argument('-l', '--local-apps', help='local ryu apps to run',
                        action='store', nargs='+')
    parser.add_argument('-d', '--local-app-dir', help='Location of local apps',
                        action='store', default=os.getcwd())
    parser.add_argument('-a', '--assign-ip', action='store_true',
                        help="assign IPs to switch ports")
    parser.add_argument('-e', '--end-hosts', action='store_true',
                        help='attach host to each switch')
    parser.add_argument('-n', '--normal', action='store_true',
                        help="don't use ryuo local controller")
    parser.add_argument('-c', '--ryuo-ip', action='store', default='127.0.0.1',
                        help='IP address of Ryuo controller')
    parser.add_argument('-r', '--request-routing', action='store_true',
                        default=False, help='request routing after assign ips')
    parser.add_argument('-q', '--no-cli', help='no mininet cli',
                        default=False, action='store_true')
    parser.add_argument('-p', '--ping-all', help='mininet ping all',
                        action='store_true', default=False)
    parser.add_argument('-w', '--wait-for-mininet', type=int, default=20,
                        help='seconds to wait mininet')
    return parser
