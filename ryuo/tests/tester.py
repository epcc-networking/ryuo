import subprocess
import time

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import RemoteController

from ryuo.controller.central import Ryuo
from ryuo.mininet.node import RyuoOVSSwitch
from ryuo.mininet.topology import RyuoTopoFromTopoZoo
from ryuo.topology.api import get_all_switch


def deadline(seconds):
    def _real_dec(func):
        def warpper(*args, **kwargs):
            func(*args, **kwargs)
            time.sleep(seconds)

        return warpper

    return _real_dec


class Tester(Ryuo):
    def __init__(self, gml_file, local_apps, working_dir, *args, **kwargs):
        super(Ryuo, self).__init__(*args, **kwargs)

        self.net = None
        self.pending = []
        self.results = {}
        self.run_mininet(gml_file, local_apps, working_dir)
        for test in dir(self):
            if test.startswith('test_'):
                self.pending.append(test)

    def run_tests(self):
        while len(self.net.switches) != len(get_all_switch(self)):
            self._logger.info('Waiting for local apps to connect...')
            time.sleep(5)
        self._logger.info('Tests begins.')
        self.run_next_test()
        self._logger.info(self.results)

    def run_next_test(self):
        while len(self.pending) > 0:
            test = self.pending.pop()
            test_name = '_'.join(test.split('_')[1:])
            self._logger.info('Starting test %s', test_name)
            getattr(self, test)()
            verifier = getattr(self, 'verify_%s' % test_name, None)
            if verifier is None:
                self._logger.info('No verifier for %s', test_name)
            self.results[test_name] = verifier()
            if self.results[test_name]:
                self._logger.info('%s pass', test_name)
            else:
                self._logger.info('%s failed', test_name)

    def run_mininet(self, gml_file, local_apps, working_dir):
        RyuoOVSSwitch.setup()
        # Clean up environment
        mn_c = subprocess.Popen(['mn', '-c'])
        mn_c.wait()
        self.net = Mininet(topo=RyuoTopoFromTopoZoo(gml_file,
                                                    'OpenFlow13',
                                                    working_dir,
                                                    local_apps),
                           switch=RyuoOVSSwitch,
                           controller=RemoteController,
                           link=TCLink)
        self.net.start()

