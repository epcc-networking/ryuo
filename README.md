# Introduction

A 2-layer control plane SDN controller based on
[Ryu](http://osrg.github.io/ryu/).

This project contains the framework and example two applications:

1. Topology Discovery

2. Keep Forwarding routing.
   (An implementation of [the Keep Forwarding algorithm](http://security.riit.tsinghua.edu.cn/share/YangBaohua-INFOCOM2014.pdf))

# Installation

Using Ubuntu as an example.

1. Config
   ```
   cp ryuo/config.py.example ryuo/config.py
   ```
   Edit `ryuo/config.py`.

2. Install dependencies
   ```
   sudo apt-get install python-pip python-dev
   ```

3. Install Ryuo
   ```
   cd path_to_repo
   sudo pip2 install -e . or sudo pip2 install .
   ```

# Running

1. Run a name server
   ```
   ryuo-ns
   ```

2. Run a Ryuo application on the control server.
   ```
   ryu-manager ryuo.kf_routing.app --observe-links 
   ```

3. Run Local Services on your switch. Edit config file if needed.
   ```
   ryu-manager ryuo.local.topology ryuo.local.routing
   ```

# Work with Mininet

1. You can find switch, controller, host class in `ryuo.mininet.node`

2. You can find a FatTree, and a topology that can use the GML files from
the [Topology Zoo Project](http://www.topology-zoo.org/index.html).

# Testing

## TopologyApp

1. Run a Ryuo name server.

2. Run tester app.
   ```
   sudo ryu-manager ryuo.topology.tests.topo_tester --observe-links
   ```


## Keep Forwarding App

1. Run a Ryuo name server.

2. Run tester app.
   ```
   sudo ryu-manager ryuo.kf_routing.tests.kf_tester --observe-links
   ```
