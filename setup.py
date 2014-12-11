from setuptools import setup

setup(name='ryuo',
      version='0.1',
      scripts=['bin/mn-from-gml',
               'bin/run-traffic-records',
               'bin/traffic-recorder',
               'bin/ryuo-ns'],
      packages=['ryuo'],
      package_dir={'ryuo': 'ryuo'},
      description='Software-defined Networking Framework with 2-Layer '
                  'Controller based on Ryu',
      install_requires=['ryu', 'pyro4', 'networkx'])
