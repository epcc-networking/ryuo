import subprocess


def enable_pktgen():
    subprocess.call(['modprobe', 'pktgen'])


def pgset(value, pgdev):
    with open(pgdev, 'w') as f:
        subprocess.call(['echo', value], stdout=f)
    with open(pgdev, 'r') as f:
        result = f.read()
        if 'Result: OK' in result:
            return
        for line in result.split('\n'):
            if 'Result:' in line:
                raise RuntimeError(line)


def start_pktgen():
    pgset('start', '/proc/net/pktgen/pgctrl')


def stop_pktgen():
    pgset('stop', '/proc/net/pktgen/pgctrl')


class PktGenerator(object):
    def __init__(self, thread, device, pkt_size, dst, src, dstmac, srcmac=None,
                 delay=0, clone_skb=0):
        super(PktGenerator, self).__init__()
        enable_pktgen()

        self.thread_device = '/proc/net/pktgen/kpktgend_%d' % thread
        self.device = device
        self.pg_device = '/proc/net/pktgen/%s' % device

        pgset('rem_device_all', self.thread_device)
        pgset('add_device', self.device)
        pgset('pkt_size %d' % pkt_size, self.pg_device)
        pgset('dst %s' % dst, self.pg_device)
        pgset('src %s' % src, self.pg_device)
        pgset('dstmac %s' % dstmac, self.pg_device)
        if srcmac is not None:
            pgset('srcmac %s' % srcmac, self.pg_device)
        pgset('delay %d' % delay, self.pg_device)
        pgset('clone_skb %d' % clone_skb, self.pg_device)

    def start(self):
        start_pktgen()

    def stop(self):
        stop_pktgen()

    def destroy(self):
        pgset('rem_device_all', self.thread_device)