#!/bin/bash
# Two namespaces joined by a veth pair.
#   xm-scan  va  10.77.0.1/24  (fd77::1/64 if the kernel has IPv6)   run xmap here
#   xm-resp  vb  10.77.0.2/24  (fd77::2/64 if the kernel has IPv6)
# Kernel-answered IPv4 targets: N addresses 10.88.0.1..10.88.0.250, 10.88.1.1.. on
# xm-resp lo, routed via vb (see v4_targets() in run_all.py).
# Kernel-answered IPv6 targets (only if the kernel has IPv6): fd88::1..N.
# Targets in 10.99.0.0/24 and fd99::/64 are routed to xm-resp but owned by
# nobody: answer them with responder.py (works without a kernel IPv6 stack,
# which is how the IPv6 module is tested on a host booted with ipv6.disable=1).
# usage: netns_up.sh [N_TARGETS=20]
set -euo pipefail
N=${1:-20}
SCAN=xm-scan; RESP=xm-resp
V6=0; [ -e /proc/net/if_inet6 ] && V6=1

"$(dirname "$0")/netns_down.sh" >/dev/null 2>&1 || true
ip netns add $SCAN; ip netns add $RESP
ip link add va type veth peer name vb
ip link set va netns $SCAN; ip link set vb netns $RESP
for ns in $SCAN $RESP; do ip -n $ns link set lo up; done
ip -n $SCAN addr add 10.77.0.1/24 dev va
ip -n $RESP addr add 10.77.0.2/24 dev vb
ip -n $SCAN link set va up; ip -n $RESP link set vb up
# the host may forward; a forwarding responder would emit real ICMP errors for
# the responder.py-only prefixes and pollute the exact-count checks
for ns in $SCAN $RESP; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=0; done
ip netns exec $SCAN ethtool -K va tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec $RESP ethtool -K vb tso off gso off gro off >/dev/null 2>&1 || true
ip -n $SCAN route add 10.88.0.0/16 via 10.77.0.2
ip -n $SCAN route add 10.99.0.0/16 via 10.77.0.2
ip -n $SCAN route add 10.96.0.0/12 via 10.77.0.2   # perf targets (responder.py)
for i in $(seq 0 $((N-1))); do ip -n $RESP addr add "10.88.$((i/250)).$((i%250+1))/32" dev lo; done
if [ $V6 = 1 ]; then
  ip -n $SCAN addr add fd77::1/64 dev va nodad; ip -n $RESP addr add fd77::2/64 dev vb nodad
  ip -n $SCAN -6 route add fd88::/64 via fd77::2
  for i in $(seq 1 "$N"); do ip -n $RESP addr add "fd88::$(printf %x "$i")/128" dev lo nodad; done
  # fd99:: is answered by responder.py only. Without a route the responder
  # kernel answers every probe with ICMPv6 "no route" (forwarding off or not),
  # which adds rows to the exact-count checks; a blackhole route drops silently.
  ip -n $RESP -6 route add blackhole fd99::/64
fi
sleep 1
echo "kernel_ipv6=$V6"
echo "scan_mac=$(ip -n $SCAN -br link show va | awk '{print $3}')"
echo "resp_mac=$(ip -n $RESP -br link show vb | awk '{print $3}')"
