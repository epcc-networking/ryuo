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
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            time.sleep(seconds)
            return res

        return wrapper

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
        self.pending = sorted(self.pending, reverse=True)
        self.test_thread = hub.spawn(self.run_tests)
        self.threads.append(self.test_thread)

    def on_all_apps_up(self):
        pass

    def run_tests(self):
        self.setup_mininet()
        self.net.start()
        up_switches = 0
        total_switches = len(self.net.switches)
        while up_switches != total_switches:
            self._logger.info('Waiting for local apps (%d/%d) to connect...',
                              up_switches, total_switches)
            up_switches = len(get_all_switch(self))
            time.sleep(5)
        self.on_all_apps_up()
        self._logger.info('Tests begins.')
        self.run_next_test()
        self._logger.info(self.results)
        self.close()

    def run_next_test(self):
        while len(self.pending) > 0:
            test = self.pending.pop()
            test_name = '_'.join(test.split('_')[1:])
            self._logger.info('Starting test %s', test_name)
            res = getattr(self, test)()
            verifier = getattr(self, 'verify_%s' % test_name, None)
            if verifier is None:
                self._logger.info('No verifier for %s', test_name)
            self.results[test_name] = verifier(res)
            cleaner = getattr(self, 'clean_%s' % test_name, None)
            if cleaner is not None:
                self._logger.info('Clean up test %s...', test_name)
                cleaner(res)
            if self.results[test_name]:
                self._logger.info('Test %s pass', test_name)
            else:
                self._logger.info('Test %s failed', test_name)

    def setup_mininet(self):
        RyuoOVSSwitch.setup()
        # Clean up environment
        subprocess.call(['mn', '-c'])
        self.net = Mininet(topo=RyuoTopoFromTopoZoo(self.gml_file,
                                                    'OpenFlow13',
                                                    self.working_dir,
                                                    self.local_apps_to_run),
                           switch=RyuoOVSSwitch,
                           controller=RemoteController,
                           link=TCLink)

    def close(self):
        self.net.stop()
        super(Tester, self).close()

