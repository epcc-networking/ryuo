import os
import subprocess

from mininet.log import warn, info
from mininet.node import OVSSwitch, Host, RemoteController
from mininet.node import Controller


class RyuoOVSSwitch(OVSSwitch):
    """Open vSwitch switch, with local ryu controller."""

    def __init__(self, name, failMode='secure', datapath='kernel',
                 inband=False, protocols=None,
                 controller_dir='', ryu_args=None, **params):
        super(RyuoOVSSwitch, self).__init__(name, failMode, datapath, inband,
                                            protocols, **params)
        self.controller = RyuoLocalController('%s-ryu' % name,
                                              controller_dir,
                                              *ryu_args,
                                              **params)

    def start(self, controllers):
        self.controller.start()
        super(RyuoOVSSwitch, self).start([self.controller])

    def stop(self, deleteIntfs=True):
        super(RyuoOVSSwitch, self).stop(deleteIntfs)
        self.controller.stop()


class RyuoLocalController(Controller):
    """Run Ryu controller that directly controls each switch."""

    def __init__(self, name, working_dir, *ryuArgs, **kwargs):
        """Init.
        name: name to give controller.
        ryuArgs: arguments and modules to pass to Ryu
        working_dir: working dir of the controller"""
        ryuCoreDir = working_dir
        if not ryuArgs:
            warn('warning: no Ryu modules specified; '
                 'running simple_switch only\n')
            ryuArgs = [ryuCoreDir + 'simple_switch.py']
        elif type(ryuArgs) not in ( list, tuple ):
            ryuArgs = [ryuArgs]

        Controller.__init__(self, name,
                            command='ryu-manager',
                            cargs='--ofp-tcp-listen-port %s ' +
                                  ' '.join(ryuArgs),
                            cdir=ryuCoreDir,
                            **kwargs)


class OutputDelayedController(RemoteController):
    def __init__(self, name, ip='127.0.0.2', port=6633, delay=1, **kwargs):
        super(OutputDelayedController, self).__init__(name, ip=ip,
                                                      port=port,
                                                           **kwargs)
        self.delay = delay

    @staticmethod
    def _clear_delay():
        command = 'tc qdisc del dev lo root'
        subprocess.call(command.split(' '))

    def start(self):
        self._clear_delay()
        command = 'tc qdisc add dev lo root handle 1: prio'
        subprocess.call(command.split(' '))
        command = 'tc qdisc add dev lo parent 1:3 handle 10: ' \
                  'netem  delay %dms' % self.delay
        subprocess.call(command.split(' '))
        command = 'tc filter add dev lo protocol ip parent 1:0 prio 3 u32 ' \
                  'match ip dst %s/32 flowid 1:3' % self.ip
        subprocess.call(command.split(' '))

    def stop(self):
        self._clear_delay()


class TestingHost(Host):
    _PG_CTRL = '/proc/net/pktgen/pgctrl'

    def __init__(self, name, inNamespace=True, **params):
        super(TestingHost, self).__init__(name, inNamespace, **params)

        self.thread_device = None
        self.device = None
        self.pg_device = None
        self.pktgen_popen = None
        self.tshark_popen = None

        self.iperf_popen = None

    def enable_pktgen(self):
        self.cmd(['rmmod', 'pktgen'])
        self.cmd(['modprobe', 'pktgen'])

    def pgset(self, value, pgdev, wait=True):
        command = ['bash', '-c', '\'echo "%s" > %s\'' % (value, pgdev)]
        info(' '.join(command) + '\n')
        pgsetter = self.popen(command, shell=True)
        if not wait:
            return pgsetter
        stdout, stderr = pgsetter.communicate()
        if len(stderr) > 0:
            raise RuntimeError(stderr)
        pgsetter.wait()
        result_reader = self.popen('cat', pgdev)
        result, dummy = result_reader.communicate()
        if 'Result: OK' in result:
            return
        for line in result.split('\n'):
            if 'Result:' in line:
                raise RuntimeError(line)

    def setup_pktgen(self, thread, pkt_size, dst, dst_mac, udp_port=7000,
                     src_mac=None, delay=0, clone_skb=0, device=None, count=0):
        """

        :param thread:
        :param pkt_size:
        :param dst:
        :param dst_mac:
        :param src_mac:
        :param delay: time between packets, nanoseconds
        :param clone_skb:
        :param device:
        :return:
        """
        self.thread_device = '/proc/net/pktgen/kpktgend_%d' % thread
        if device is None:
            device = self.defaultIntf().name
        self.device = device
        self.pg_device = '/proc/net/pktgen/%s' % device

        self.pgset('rem_device_all', self.thread_device)
        self.pgset('add_device %s' % self.device, self.thread_device)

        self.pgset('pkt_size %d' % pkt_size, self.pg_device)
        self.pgset('dst %s' % dst, self.pg_device)
        self.pgset('dst_mac %s' % dst_mac, self.pg_device)
        if src_mac is not None:
            self.pgset('src_mac %s' % src_mac, self.pg_device)
        self.pgset('delay %d' % delay, self.pg_device)
        self.pgset('clone_skb %d' % clone_skb, self.pg_device)
        self.pgset('udp_dst_min %d' % udp_port, self.pg_device)
        self.pgset('udp_dst_max %d' % udp_port, self.pg_device)
        self.pgset('flag UDPSRC_RND', self.pg_device)
        self.pgset('count %d' % count, self.pg_device)

    def start_pktgen(self):
        self.pktgen_popen = self.pgset('start', self._PG_CTRL, False)

    def stop_pktgen(self):
        self.pktgen_popen.kill()
        self.pgset('stop', self._PG_CTRL)

    def start_tshark(self, user, group='wireshark'):
        with open(os.devnull, 'w') as f:
            command = ['bin/tshark-wrapper', '-u', user, '-g', group,
                       '-a', '-i %s -w %s-pktgen.pcapng' % (
                    self.defaultIntf().name, self.name)]
            self.tshark_popen = self.popen(command)

    def stop_tshark(self):
        self.tshark_popen.kill()

