#!/usr/bin/env python2
from subprocess import call

IP = '127.0.0.1'

if __name__ == '__main__':
    # IP            Router Port
    addresses = [['10.0.1.1/24', 1, 1],
                 ['10.0.2.1/24', 1, 2],
                 ['10.0.3.1/24', 1, 3],
                 ['10.0.4.1/24', 1, 4],
                 ['10.0.2.2/24', 2, 1],
                 ['10.0.5.1/24', 2, 2],
                 ['10.0.3.2/24', 3, 1],
                 ['10.0.5.2/24', 3, 2],
                 ['10.0.6.1/24', 3, 3],
                 ['10.0.4.2/24', 4, 1],
                 ['10.0.7.1/24', 4, 2],
                 ['10.0.6.2/24', 5, 1],
                 ['10.0.7.2/24', 5, 2],
                 ['10.0.8.1/24', 5, 3]]
    for address in addresses:
        ip = address[0]
        router = address[1]
        port = address[2]
        call(['curl',
              '-X',
              'POST',
              '-d',
              '\'{"address": "%s"}\'' % ip,
              'http://%s:8080/router/%d/%d/address' % (IP, router, port)])