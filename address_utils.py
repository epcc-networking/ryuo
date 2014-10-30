#!/usr/bin/env python2
from subprocess import call

from ryu.lib.dpid import dpid_to_str
from ryu.lib.port_no import port_no_to_str


def add_addresses(addresses, controller_ip):
    for address in addresses:
        ip = address[0]
        router = address[1]
        port = address[2]
        call(['curl',
              '-X',
              'POST',
              '-d',
              '{"address": "%s"}' % ip,
              'http://%s:8080/router/%s/%s/address' % (
                  controller_ip, dpid_to_str(router), port_no_to_str(port))])