# icmp_echo_time tests

Run as root on a Linux host with `ip`, `tc` (netem), `tcpdump`, `ethtool` and
Python 3 with `scapy` (scapy is only used to re-derive the checksums of the
captured probes independently of the C code).

```
tests/rtt/netns_up.sh 500                     # namespaces xm-scan / xm-resp, veth va<->vb
python3 tests/rtt/run_all.py \
    --xmap build/src/xmap \                   # build with icmp_echo_time
    --xmap-old /path/to/baseline/xmap \       # optional: pre-change build for the regression
    --out /tmp/rtt_run \
    --only delay,dup,reorder,tamper,regress   # perf is opt-in (~8 min)
tests/rtt/netns_down.sh
```

`responder.py` is an L2 echo responder (stdlib only) for the targets the
responder kernel does not own: `10.99/16`, `10.96/12`, `fd99::/64`. It works
without a kernel IPv6 stack (the reference host boots with `ipv6.disable=1`),
and implements the payload tampering (`--mode magic|tag|truncate:N|nopayload`)
and ICMP errors (`--err unreach|timex --err-quote N`).

Checks (every line prints PASS/FAIL; non-zero exit on any FAIL):

* `delay`: netem 20/50/100 ms, 1500 RTTs per case and family. Median within
  ±1 ms of the setting; each row is matched to the tcpdump capture: the send
  stamp to the request seen leaving `va`, the receive stamp to the reply
  seen arriving; request checksums are re-derived with scapy.
* `dup`: netem `duplicate 10%`. One `repeat=0` row per IP, duplicated
  `(saddr, probe_idx)` rows exist, dedup by earliest `recv_ts_ns` leaves
  exactly 3 per IP with the right RTT.
* `reorder`: netem `reorder 25% 50% loss 30%`. All rows paired with their own
  request/reply in the capture, loss rate as set, RTT either ~0 (reordered) or ~50 ms.
* `tamper`: echo payload with damaged magic / tag, truncated, absent; ICMP
  errors quoting the whole or the minimum of the probe. `success` unchanged;
  `rtt_valid`/`rtt_status` as documented.
* `regress`: `icmp_echo` (old build), `icmp_echo` (new build) and
  `icmp_echo_time` over the same 100 targets with `--seed`; sorted rows over
  the `icmp_echo` fields and the summary counters must be identical, for
  echo replies and for ICMP errors.
* `perf`: 100 000 targets, `-B 1M`, `--probes=3`, `icmp_echo` vs `icmp_echo_time`.
