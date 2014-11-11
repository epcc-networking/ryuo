import logging


class BaseAppConfig(object):
    def __init__(self):
        super(BaseAppConfig, self).__init__()
        self._app_name = 'APP-NAME'
        self._log_level = logging.INFO

    def app_name(self):
        return 'APP-NAME'

    def ryuo_name(self):
        return self.app_name() + '-RYUO'

    def local_controller_name(self, dpid):
        return "%s-%d" % (self.app_name(), dpid)

    def log_level(self):
        return self._log_level

