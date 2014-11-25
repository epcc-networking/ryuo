import subprocess
import time

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import RemoteController
from ryu.lib import hub

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
        super(Tester, self).__init__(*args, **kwargs)

        self.net = None
        self.pending = []
        self.results = {}
        self.gml_file = gml_file
        self.local_apps_to_run = local_apps
        self.working_dir = working_dir
        for test in dir(self):
            if test.startswith('test_'):
                self.pending.append(test)
        self.test_thread = hub.spawn(self.run_tests)
        self.threads.append(self.test_thread)

    def run_tests(self):
        self.run_mininet()
        up_switches = 0
        total_switches = len(self.net.switches)
        while up_switches != total_switches:
            self._logger.info('Waiting for local apps (%d/%d) to connect...',
                              up_switches, total_switches)
            up_switches = len(get_all_switch(self))
            time.sleep(5)
        self._logger.info('Tests begins.')
        self.run_next_test()
        self._logger.info(self.results)
        self.close()

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
            cleaner = getattr(self, 'clean_%s' % test_name, None)
            if cleaner is not None:
                cleaner()
            if self.results[test_name]:
                self._logger.info('Test %s pass', test_name)
            else:
                self._logger.info('Test %s failed', test_name)

    def run_mininet(self):
        RyuoOVSSwitch.setup()
        # Clean up environment
        mn_c = subprocess.Popen(['mn', '-c'])
        mn_c.wait()
        self.net = Mininet(topo=RyuoTopoFromTopoZoo(self.gml_file,
                                                    'OpenFlow13',
                                                    self.working_dir,
                                                    self.local_apps_to_run),
                           switch=RyuoOVSSwitch,
                           controller=RemoteController,
                           link=TCLink)
        self.net.start()

    def close(self):
        self.net.stop()
        super(Tester, self).close()

