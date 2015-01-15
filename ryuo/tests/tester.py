import inspect
import os
import subprocess
import time
import sys

from mininet.link import TCLink
from mininet.net import Mininet
from mininet.node import RemoteController
from ryu.lib import hub

from ryuo.controller.central import Ryuo
from ryuo.mininet.node import RyuoOVSSwitch
from ryuo.mininet.topology import RyuoTopoFromTopoZoo
from ryuo.topology.api import get_all_switch


def ryuo_test(deadline=0, repeat=1, order=sys.maxint):
    def _real_dec(func):
        def wrapper(self, *args, **kwargs):
            to_repeat = repeat
            name = func.__name__
            test_res = 0
            self._logger.info('Test %s start...', name)
            run = 1
            while to_repeat > 0:
                self._logger.info('Test %s, run %d', name, run)
                res = func(self, *args, **kwargs)
                time.sleep(deadline)
                verifier = getattr(self, 'verify_%s' % name)
                run_res = verifier(res)
                test_res += 1 if run_res else 0
                if run_res:
                    self._logger.info('Success')
                else:
                    self._logger.error('Failed')
                cleaner = getattr(self, 'clean_%s' % name, None)
                if cleaner is not None:
                    cleaner(res)
                to_repeat -= 1
                run += 1
            return test_res, repeat

        wrapper.__order__ = order
        wrapper.__test_name__ = func.__name__
        return wrapper

    return _real_dec


class Tester(Ryuo):
    _NAME = 'Tester'

    def __init__(self, gml_file, local_apps, working_dir, *args, **kwargs):
        super(Tester, self).__init__(*args, **kwargs)

        self.net = None
        self.pending = []
        self.results = {}
        self.gml_file = gml_file
        self.local_apps_to_run = local_apps
        self.working_dir = working_dir
        for name, func in inspect.getmembers(type(self)):
            if hasattr(func, '__order__'):
                self.pending.append(func)
        self._logger.info('%d tests loaded.', len(self.pending))
        self.pending = sorted(self.pending, key=lambda f: f.__order__)
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
            time.sleep(5)
            up_switches = len(get_all_switch(self))
        self.on_all_apps_up()
        self._logger.info('Tests begins.')
        result = 0
        for test in self.pending:
            pass_cnt, total = test(self)
            self.results[test.__test_name__] = "%d/%d" % (pass_cnt, total)
            if pass_cnt != total:
                result = 1
        self._logger.info(self.results)
        self.close()
        os._exit(result)

    def setup_mininet(self):
        RyuoOVSSwitch.setup()
        # Clean up environment
        subprocess.call(['mn', '-c'])
        self.net = Mininet(topo=RyuoTopoFromTopoZoo(self.gml_file,
                                                    'OpenFlow10',
                                                    self.working_dir,
                                                    self.local_apps_to_run),
                           switch=RyuoOVSSwitch,
                           controller=RemoteController,
                           link=TCLink)

    def close(self):
        self.net.stop()
        super(Tester, self).close()
