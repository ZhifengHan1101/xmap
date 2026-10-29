#!/bin/bash
# Remove the namespaces created by netns_up.sh (the veth pair goes with them).
ip netns del xm-scan 2>/dev/null; ip netns del xm-resp 2>/dev/null; exit 0
