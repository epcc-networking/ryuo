import subprocess


class SwitchControl(object):
    def enable_bfd(self, interface, remote_mac, local_ip, remote_ip,
                   min_rx, min_tx):
        pass

    def set_bfd_ip(self, interface, local_ip, remote_ip):
        pass

    def disable_bfd(self, interface):
        pass


class OVSSwitchControl(SwitchControl):
    def set_bfd_ip(self, interface, local_ip, remote_ip):
        commands = ['bfd:bfd_src_ip=%s' % local_ip,
                    'bfd:bfd_dst_ip=%s' % remote_ip]
        for command in commands:
            if command.endswith('None'):
                continue
            subprocess.call(['ovs-vsctl', 'set', 'Interface', interface,
                             command])

    def enable_bfd(self, interface, remote_mac, local_ip, remote_ip,
                   min_rx, min_tx):
        self.set_bfd_ip(interface, local_ip, remote_ip)
        commands = ['bfd:bfd_local_dst_mac=%s' % remote_mac,
                    'bfd:min_rx=%d' % min_rx,
                    'bfd:min_tx=%d' % min_tx,
                    'bfd:enable=true']
        for command in commands:
            subprocess.call(['ovs-vsctl', 'set', 'Interface', interface,
                             command])

    def disable_bfd(self, interface):
        subprocess.call(['ovs-vsctl', 'set', 'Interface', interface,
                         'bfd:enable=false'])
