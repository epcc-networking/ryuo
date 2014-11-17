from mininet.log import warn
from mininet.node import OVSSwitch
from mininet.node import Controller


class RyuoOVSSwitch(OVSSwitch):
    """Open vSwitch switch, with local ryu controller."""

    def __init__(self, name, failMode='secure', datapath='kernel',
                 inband=False, protocols=None,
                 controller_working_dir='', ryu_args=None, **params):
        super(RyuoOVSSwitch, self).__init__(name, failMode, datapath, inband,
                                            protocols, **params)
        self.controller = RyuoLocalController('%s-ryu' % name,
                                              controller_working_dir,
                                              *ryu_args,
                                              **params)

    def start(self, controllers):
        self.controller.start()
        super(RyuoOVSSwitch, self).start([self.controller])

    def stop(self):
        super(RyuoOVSSwitch, self).stop()
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
