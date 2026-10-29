# icmp_echo_time — implementation and validation report

Branch `feature/icmp-echo-time` (from master `5981c18`). Nothing pushed.

Commits:

```
core: optional nanosecond pcap timestamps + per-module metadata hook
icmp_echo_time: shared payload, tag and RTT logic        (+ validate_prf16)
icmp_echo_time: IPv4 probe module
icmp_echo_time: IPv6 probe module
tests/rtt: netns harness, L2 responder and checks
docs: ...
```

## 1. Findings from the source (section 2 of the brief)

**Version.** The scan host's `xmap` is not on this machine (`/usr/local/bin/xmap`
does not exist here), so `xmap --version` / install source could not be
checked. The repo has no tags; its version string is `DEVELOPMENT`. The fork is
based on the tip of `master` (`5981c18`, "Update CHANGELOG.md", 2026-03-10).
**Please confirm against the deployed binary** (`xmap --version`, and the source
tree or package it came from); if it was built from an older commit, rebase the
five source commits onto it (the core diff is small and touches only
`recv-pcap.c`, `recv.h`, `summary.c`, `validate.*`, `probe_modules.*`).

**Interfaces** (all verified in code):

* `make_packet(buf, &len, src, dst, port, ttl, probe_num, index, arg)`:
  `probe_num` **is** passed — the `--probes` loop index (`send.c`, `i`).
* `process_packet(packet, len, fs, struct timespec ts)`: the pcap header
  timestamp **is** already passed (`recv-pcap.c` converts `pkthdr.ts`). No
  interface change was needed. It was microsecond-only; `recv-pcap.c` now opens
  the capture with nanosecond precision for modules that set
  `pcap_tstamp_nano`; every other module keeps `pcap_open_live`.
* Sending: for each target, the `--probes` packets are made and sent one by
  one in the same loop (`make_packet` → `sendto`). `--batch` only changes how
  often the rate limiter sleeps; there is no `sendmmsg` and no deferred send,
  so a stamp written in `make_packet` is never stale by a batch.
* `icmp_echo` validation: id/seq = AES(`src ^ dst`) (`validate_gen`) — identical
  for all probes of a target. Echo replies are validated on the reply's
  src/dst; ICMP errors on the quoted inner src/dst. Payload is not examined.
  Default payload 8 zero bytes; `--probe-args=text:|hex:|file:` overrides it.
* `timestamp_str`/`_ts`/`_us`: `gettimeofday()` in the receive callback
  (`fs_add_system_fields`), not the pcap time.
* `repeat`: a **Bloom filter** (`xrecv.bf`, target FP 1e-5) keyed on the reply's
  source address, not a bitmap.
* PF_RING: exists (`WITH_PFRING`, `recv-pfring.c`, timestamps from the ZC
  buffer). `icmp_echo_time` refuses to start in that build (log error + non-zero
  exit from `global_init`). Not compiled here (no PF_RING library).
* Unit tests: none exist (`src/tests/` is empty, `xtest` commented out).

Probe spacing for the same target (measured, `sent_ts_ns` differences, IPv4,
`--probes=3`):

| `-B` | `--batch` | spacing |
|---|---|---|
| 100K | 1 | 7.0 ms |
| 1M | 1 | 0.68 ms |
| 10M | 1 | 34 µs |
| 1M | 10 | 3–4 µs |
| 10M | 100 | 4–5 µs |

The production form (`--batch=1`, `-B` 100K–1M) spaces probes by 0.7–7 ms. The
N RTTs are close in time and strongly correlated; they are not independent
samples.

## 2. Design choices

* Payload: as proposed in the brief (24 B v4 / 36 B v6), no changes in layout.
  Tag = 2-block CBC-MAC with the scan's AES validation key (`validate_prf16`
  added to `validate.c`), 32 bits.
* Send stamp written last in `make_packet`, right before the checksums.
* `rtt_status`: `ok, no_payload, bad_magic, bad_version, truncated, bad_tag,
  bad_addr, clock_anomaly, from_icmp_error`. `bad_addr` (payload destination
  ≠ replying address) was added to the brief's list. `rtt_valid` is 1 for `ok`
  and `from_icmp_error` only.
* Plausibility check: `recv < sent`, or `sent` earlier than the scan start
  (tighter than the brief's `scan duration + cooldown`).
* Error-message RTT (the brief's bonus item) is implemented for both families.
* Metadata: `icmp_echo_time` object with module, family, payload version and
  length, pcap precision, clock source, stamp point, batch, git describe at
  configure time.
* Not done: `probe_repeat` per-`(saddr, probe_idx)` flag (no reusable table;
  would need a new Bloom filter sized by targets×probes). Downstream dedup
  instead.
* Not added: `rtt_ns` (`recv_ts_ns - sent_ts_ns` is available).

**Deviation from `icmp_echo` (only on malformed packets).** The stock ICMPv6
module rejects (validation failure → no row, not counted as success) an echo
reply or an error whose payload is shorter than its own configured payload. In
`icmp_echo_time` the validation length checks cover headers only; otherwise a
cut-short payload would turn a success into a drop, which the brief forbids.
The IPv4 module has no such check in the stock code.

## 3. Verification

Environment: Linux 6.8, kernel booted with `ipv6.disable=1` (no kernel IPv6).
IPv4 targets were answered by the responder namespace's kernel; IPv6 (and the
tamper/error cases) by `tests/rtt/responder.py`, an AF_PACKET L2 echo responder,
so the IPv6 module was exercised with real frames over the veth, not a mock
(`ip netns` + veth + `tc netem`; no IPv6 stack is needed for that). IPv6 on the
real network could not be tested (no IPv6 locally).

**Build.** Clean build of the branch: success. Warnings: baseline 199, branch
201. The two extra are the pre-existing `packet.h: unused variable 'txid_t'`
header warning, printed once per translation unit that includes `packet.h` — the
two new module files. No other new warning; the new files and the core edits
are warning-free. No unit tests exist to run.

**Delay (netem on the responder's veth), 1500 RTTs per case**, `-B 1M`,
`--probes=3`, 500 targets, each row also matched against an independent
tcpdump capture (send stamp = request in the capture, receive stamp = reply in
the capture, request checksums re-derived with scapy; all 0 mismatches):

| family | netem | min µs | median µs | p99 µs |
|---|---|---|---|---|
| v4 | 20 ms | 20003 | 20004 | 20007 |
| v4 | 50 ms | 50003 | 50004 | 50009 |
| v4 | 100 ms | 100003 | 100004 | 100008 |
| v6 | 20 ms | 20029 | 20041 | 20058 |
| v6 | 50 ms | 50033 | 50040 | 50052 |
| v6 | 100 ms | 100037 | 100041 | 100051 |

All within ±1 ms (the largest error is 41 µs). The IPv6 +40 µs is the Python
responder's user-space turnaround, not the module; kernel-answered IPv4 is +4 µs.
An earlier v4 20 ms run showed p99 ≈ 30–35 ms: the first ~28 replies queued behind
an ARP exchange in the responder (which netem delays too). The test now warms
the neighbour caches first; this was a harness artifact, not the module.

**Duplicate 10%** (v4/v6): one `repeat=0` row per IP (300/300); duplicated
`(saddr, probe_idx)` rows exist (97 keys in the v6 run); dedup by earliest
`recv_ts_ns` leaves exactly 900 rows (3 per IP) with median 20004 / 20038 µs.

**Reorder 25% + loss 30%**: 70% of the replies arrived (1043/1500 v4,
1044/1500 v6); every row matches its own request and reply in the capture;
RTTs are either ≈0 (the reordered packets) or 50 ms; no other value.

**Tamper / errors** (50 targets × 3 probes, v4 and v6): with magic or tag
flipped, payload truncated to 10 or 3 bytes, or removed, `success` rows = 150,
unique IPs = 50, `success_unique` = 50 — identical to the undamaged case — and
`rtt_valid=0`, `rtt_status` = `bad_magic / bad_tag / truncated / truncated /
no_payload`, RTT fields empty. ICMP unreachable and time-exceeded quoting the
full probe: `success=0`, `rtt_status=from_icmp_error`, `rtt_valid=1`;
quoting the RFC 792 minimum: `truncated`, `rtt_valid=0`. (A first v4 run also
hit real ICMP errors generated by the responder kernel because `ip_forward`
was on; they were classified correctly, and the harness now turns forwarding off.)

**Regression** (100 targets, `--seed=7`, rows sorted, all `icmp_echo` fields
except `data`; echo replies and ICMP errors; v4 and v6): old build
`icmp_echo` (built from `5981c18`) = new build `icmp_echo` = `icmp_echo_time`
with `-f` restricted to the old fields, rows and summary counters identical.
(The baseline stands in for the deployed binary, which is not available here.)
`data` differs by design (payload). Not compared: `timestamp_*` (time).

**Real network, IPv4 only** (24 public DNS/anycast addresses, `-B 50K`,
`--probes=3`, `-S 101.6.21.134`; xmap picked the NIC's 169.254.x secondary
address by default and received nothing — the stock `icmp_echo` behaves the same
here, so it is an invocation matter for this host): 72 sent, 24/24 responded,
69/72 replies, all `rtt_status=ok`. Against `ping -c 5` (ms):

| group | xmap min / median | ping min / median |
|---|---|---|
| local network answers (8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9, 223.5.5.5, 223.6.6.6, 114.114.114.114, 119.29.29.29, 180.76.76.76) | 0.21–0.23 / 0.22–0.23 | 0.21–0.24 / 0.24–0.25 |
| 1.2.4.8 | 1.69 / 1.72 | 1.69 / 1.95 |
| 210.2.4.8 | 29.27 / 29.52 | 29.40 / 29.50 |
| 45.90.28.0 | 73.02 / 73.03 | 73.00 / 73.00 |
| 1.0.0.1, 77.88.8.8 | 247.2 / 247.5, 272.9 / 272.9 | 248 / 257, 260 / 264.5 |
| 4.2.2.2, 64.6.64.6, 185.228.168.9, 94.140.14.14 | 158–167 | 125–173 |

The sub-millisecond answers for public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 …
at 0.23 ms from both xmap and ping) mean the local network answers or
intercepts them, so they are not anycast RTTs. Stable paths agree with `ping`
within about 1 ms (ping prints three significant digits, so ≥100 ms values
are rounded to 1 ms). Differences on the others: jitter (208.67.220.220:
xmap 451–480 ms vs ping 186–199 ms, the probes in flight at different
moments), only 5 vs 3 samples, and xmap's three probes 7 ms apart (`-B 50K`).

**Performance** (v4, 100 000 targets, `-B 1M`, `--probes=3`, responder.py
answers): both modules sent 300 000 packets, 0 sendto failures, 0 pcap drops,
100 000 unique successes. Rate: `icmp_echo` 1554 pps (configured 1.56 Kpps),
`icmp_echo_time` 1456 pps (configured 1.46 Kpps). `-B` is a bit rate, and the
module's packets are larger (66 B vs 50 B), so at equal `-B` the new module
sends ~6% fewer packets per second — each hits the rate XMap derived for it.
The 300 000-packet scan therefore took 206 s vs 193 s. To keep the pps use a
higher `-B`.

## 4. Known limits and caveats

* Deployed version not verified (see §1).
* PF_RING not built or tested (the module is disabled there by design).
* IPv6 end-to-end tested in the lab only through an L2 responder; real IPv6
  networks untested.
* Bloom-filter `repeat` (false-positive rate ~1e-5) can mark a first reply
  `repeat=1`; unchanged core behaviour.
* The first-arrival `repeat=0` row is not the RTT of probe 0 (see
  `icmp_echo_time.md`).
* Host packages installed for building: `gengetopt libpcap-dev libjson-c-dev
  libunistring-dev libjudy-dev byacc` (apt). Nothing else on the host was
  changed; no `/opt/xmap-rtt` install was made.

## 5. Downstream suggestions (not applied)

Install the binary and sudoers line per `icmp_echo_time_install.md`.

`inflight-ip-probe/scripts/run_anycast_scan.sh` (same for the v6 call and for
`starlink-sync-probe/vscan/run_vscan.sh`, `run_fastscan.sh`,
`daily-scan-ops/.../run_daily_starlink_ipv6_scan.sh`, `run_starshield_discovery.sh`):

```diff
-  sudo xmap -4 -I "${V4_TARGETS}" -M icmp_echo \
+  sudo /opt/xmap-rtt/bin/xmap-rtt -4 -I "${V4_TARGETS}" -M icmp_echo_time \
     -B 1M --batch=1 --probes=3 --cooldown-secs=10 \
     --output-filter="success = 1 && repeat = 0" \
```

The anycast script passes no `-f`, and the default output is `saddr` only, so it
gets no RTT column unless `-f` is added (only `-M` and the binary change there).
The `vscan` scripts: add the new fields to `-f`:

```diff
-      -f saddr,hlim,clas,desc,type,code,timestamp_str \
+      -f saddr,hlim,clas,desc,type,code,timestamp_str,probe_idx,rtt_us,rtt_valid,rtt_status \
```

With `success = 1 && repeat = 0` this gives one row per IP with the RTT of the
first reply. To keep all N RTTs use `--output-filter='success = 1'` and
`-f ...,probe_idx,repeat,sent_ts_ns,recv_ts_ns,rtt_us,rtt_valid,rtt_status`.

`inflight-ip-probe/scripts/rollup_scans.py` (line 49 and the writers at 102,
293, 357–377): add the columns at the end so old readers keep working.

```diff
-RESP_FIELDS = ["scan_ts", "run_dir", "src", "saddr", "hoplimit", "clas", "desc", "type", "code", "timestamp_str"]
+RESP_FIELDS = ["scan_ts", "run_dir", "src", "saddr", "hoplimit", "clas", "desc", "type", "code", "timestamp_str",
+               "probe_idx", "rtt_us", "rtt_valid", "rtt_status"]
@@ iter_active (yield dict)
-                       "code": row.get("code", ""), "timestamp_str": row.get("timestamp_str", "")}
+                       "code": row.get("code", ""), "timestamp_str": row.get("timestamp_str", ""),
+                       "probe_idx": row.get("probe_idx", ""), "rtt_us": row.get("rtt_us", ""),
+                       "rtt_valid": row.get("rtt_valid", ""), "rtt_status": row.get("rtt_status", "")}
@@ archive_day (writer, line ~293)
-                                 r["clas"], r["desc"], r["type"], r["code"], r["timestamp_str"]])
+                                 r["clas"], r["desc"], r["type"], r["code"], r["timestamp_str"],
+                                 r["probe_idx"], r["rtt_us"], r["rtt_valid"], r["rtt_status"]])
```

`expand_day` (hdr table at 357) must then emit the same extra columns;
old archived rows have empty values there. In the all-RTT mode, deduplicate
before archiving: key `(saddr, probe_idx)`, keep the smallest `recv_ts_ns`.

Rollback: switch `-M`/binary/`-f` back; the production `xmap` was never changed.

## 6. Follow-up after the tky pilot (2026-10-29)

* **Gateway auto-detection hang (core, all modules).** `read_nl_sock` looked
  only at the first netlink message of each `recv`; when the kernel appends
  `NLMSG_DONE` to the last batch of a dump, the end was missed and xmap blocked
  in `recv` forever (reproduced on tky, Linux 6.17: stuck >30 s without `-G`).
  Every message is now examined; the netlink socket has a 2 s receive timeout;
  callers check the socket and free/close it; a neighbour entry without a
  link-layer address is no longer accepted; `/proc/net/arp` is a fallback when
  netlink finds no entry (from the local patch deployed on tky). On tky the
  fixed build found the gateway MAC in 168 ms without `-G`, equal to
  `ip neigh`; same result here.
* **netns harness.** With kernel IPv6 enabled, the responder namespace answered
  `fd99::` probes with ICMPv6 "no route", adding rows to the exact-count checks;
  `netns_up.sh` now installs a blackhole route for `fd99::/64`. The dup and
  reorder checks allow up to 1% of RTTs outside the netem window (user-space
  responder stalls) and the dup check also matches the deduplicated rows to the
  capture. On tky: 76 PASS, 0 FAIL, `--xmap-old` = deployed binary.
