# Introduction

# Testing

## TopologyApp

1. Run a Ryuo name server.
   ```
   ryuo-ns
   ```

2. Run test app.
   ```
   sudo ryu-manager ryuo.topology.tests.topo_tester --observe-links
   ```