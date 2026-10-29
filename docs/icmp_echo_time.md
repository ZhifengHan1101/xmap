# `icmp_echo_time` — ICMP / ICMPv6 echo probing with per-probe RTT

`icmp_echo_time` sends the same echo requests as `icmp_echo`, but each request
carries its own send time and probe number in the payload. The reply echoes the
payload back, so one scan yields both the liveness result and one RTT per
reply, with no extra ping round. It exists for `-4` and `-6`
(`module_icmp_echo_time_v4.c`, `module_icmp_echo_time_v6.c`; shared logic in
`module_icmp_echo_time.c`).

`icmp_echo` is unchanged. `-M icmp_echo_time` is a drop-in replacement for
`-M icmp_echo`: its output fields are a superset, and `success`, `repeat`,
validation, sending rate and cooldown are decided by the same code paths.

## Payload

Fixed length, network byte order. The payload is not configurable:
`--probe-args` is rejected.

| offset | len | field | note |
|---|---|---|---|
| 0 | 4 | magic | `0x584D5254` ("XMRT") |
| 4 | 1 | version | `1` |
| 5 | 1 | probe_idx | 0 .. `--probes`-1 (the `probe_num` XMap passes to `make_packet`) |
| 6 | 2 | reserved | 0 |
| 8 | 8 | sent_ts_ns | `clock_gettime(CLOCK_REALTIME)`, ns since epoch |
| 16 | 4 / 16 | dst_echo | probe destination (IPv4 4 B / IPv6 16 B) |
| 20 / 32 | 4 | tag | keyed MAC over (dst_echo, sent_ts_ns, probe_idx) |

Payload is 24 B (IPv4) / 36 B (IPv6). Packet on the wire: 66 B (IPv4) /
98 B (IPv6) including Ethernet. `icmp_echo` sends 8-byte payloads
(50 / 78 B), so at a given `-B` the packet *rate* is lower; see
[Rate and bandwidth](#rate-and-bandwidth).

**Tag.** `validate_prf16` (one AES-128 block under the scan's validation key,
the same key that makes the ICMP id/seq) is applied twice, CBC-MAC style:
`b1 = AES(dst || 0 .. || 0xA5)`, `b2 = AES(b1 ^ (sent_ts_ns || probe_idx))`,
`tag = first 4 bytes of b2`. The `0xA5` domain byte keeps the inputs disjoint
from the `src ^ dst` blocks whose output appears on the wire as id/seq, so
id/seq do not reveal tags. The tag is 32 bits: it stops corrupted or
mismatched payloads (and anything that does not hold the scan key) from
producing a believable RTT. It is not a defence against a network attacker who
can read the scan's replies and wants to inflate RTTs — they can see valid
payloads.

**Why this layout.** The upstream ZMap `icmp_echo_time` stores a bare
`gettimeofday` pair, IPv4 only, with no probe number. Here `probe_idx` is
needed because validation (id/seq) is identical for all probes of one target,
so nothing else tells replies apart. `dst_echo` is needed because ICMP errors
come from routers, and the quoted destination is what ties an error back to the
probe. Nanosecond `sent_ts_ns` costs the same 8 bytes as a `timeval`.

## Timestamps

* **Send:** written at the end of `make_packet`, after addresses and
  id/seq, immediately before the checksums and `sendto()`. The remaining gap
  is the checksum (tens of ns) plus the syscall entry. XMap's sender calls
  `make_packet` and `send_packet` back to back for each packet, so `--batch`
  does not delay the stamp: `--batch=N` only changes how often the rate limiter
  sleeps (see [Batch](#batch-and-probe-spacing)).
* **Receive:** the pcap header timestamp (`struct pcap_pkthdr.ts`), i.e. the
  kernel capture time, not a call to `gettimeofday` in the callback. XMap
  already hands it to `process_packet` as `struct timespec ts`.
* **Precision:** the capture is opened with
  `pcap_set_tstamp_precision(PCAP_TSTAMP_PRECISION_NANO)` (only for modules that
  ask for it; every other module still uses `pcap_open_live`). If libpcap or
  the interface refuses, microseconds are used, `recv_ts_ns` has `us` resolution
  and the metadata says `microsecond`.
* **Clock:** `CLOCK_REALTIME` on both sides; on Linux pcap timestamps are
  realtime.

`timestamp_str`, `timestamp_ts` and `timestamp_us` (core fields) are still taken
by `gettimeofday` in the receive callback, as for every module. They are the
processing time, not the arrival time; use `recv_ts_*` for the arrival time.

## Output fields

All `icmp_echo` fields, same names, types and meaning: `success`, `clas`,
`desc`, `type`, `code`, `icmp_id`, `seq`, `outersaddr`, `data`, plus the core
IP and system fields (`saddr`, `daddr`, `ipid`, `ttl`/`hlim`, `repeat`,
`cooldown`, `timestamp_*`). Added:

| field | type | meaning |
|---|---|---|
| `probe_idx` | int | probe number from the payload |
| `sent_ts_us`, `sent_ts_ns` | int | send time, µs / ns since epoch |
| `recv_ts_us`, `recv_ts_ns` | int | capture time of the response |
| `rtt_us` | int | `recv_ts_us - sent_ts_us` (both floored to µs) |
| `rtt_valid` | int | 1 if `rtt_us` is usable |
| `rtt_status` | string | see below |
| `probe_daddr` | string | destination echoed in the payload |

`rtt_ns` is not a field; use `recv_ts_ns - sent_ts_ns`. Fields that could not be
determined are empty in CSV.

### `rtt_status`

An RTT is computed only when the packet already passed the module's normal
validation, the payload is complete, magic, version and tag match, and
`dst_echo` equals the address being replied for (the reply's source for an echo
reply, the quoted destination for an error).

| status | `rtt_valid` | meaning | RTT fields |
|---|---|---|---|
| `ok` | 1 | echo reply, all checks passed | filled |
| `from_icmp_error` | 1 | RTT of the ICMP error carrying the quoted probe (success=0): time to the router that generated the error, not an echo RTT | filled |
| `no_payload` | 0 | echo reply with no payload | empty |
| `bad_magic` | 0 | payload does not start with the magic | empty |
| `truncated` | 0 | magic present but fewer than 24/36 bytes; also an error that quotes less than the whole payload | empty |
| `bad_version` | 0 | unknown payload version | empty |
| `bad_tag` | 0 | tag mismatch (corrupted or not ours) | empty |
| `bad_addr` | 0 | `dst_echo` does not match the replying address | empty |
| `clock_anomaly` | 0 | `recv < sent`, or `sent` is earlier than the scan start: the realtime clock was stepped | filled, `rtt_us` empty if negative |

**`success` is independent of all of this.** Payload damage never changes
`success`, `repeat`, or the validation counters; it only sets the RTT fields.
The one intentional difference from `icmp_echo` is on malformed packets: the
ICMPv6 module's length checks cover headers, not a fixed payload length, so a
reply with a cut-short payload is still a success here (the stock module
drops it as invalid).

ICMP errors are classified and reported like in `icmp_echo`
(`success = 0`, `saddr` rewritten to the probed host). RTT is computed when the
quoted probe contains the full payload. ICMPv6 errors normally do (they quote up
to 1280 bytes); IPv4 routers often quote only the IP header plus 8 bytes
(RFC 792), giving `truncated`.

## `repeat` and multiple probes (`--probes=N`)

* `repeat` is XMap's, unchanged: a Bloom filter keyed on the response's source
  address. For `--probes=3`, the first reply from an address has `repeat=0`,
  the rest `repeat=1`. (Bloom filter: false positives of about 1e-5 can make a
  first reply look like a repeat — core behaviour, not changed.)
* **`repeat = 0` rows carry the RTT of the first reply to arrive.** That is
  not necessarily `probe_idx = 0`. If the probes of a target were sent
  back-to-back it would be about the minimum of the N RTTs. Because the first
  arrival is selected, this is a biased (low) estimate of a typical RTT; if the
  path has jitter or reordering, it is *not* the RTT of probe 0.
* **To get every RTT**, use `--output-filter='success = 1'` and output
  `probe_idx` and `repeat`. Downstream, deduplicate by `(saddr, probe_idx)` and
  keep the earliest `recv_ts_ns`: a network duplicate (DUP) produces two rows
  with the same `(saddr, probe_idx)`, and the later one carries a later receive
  time against the same send time.
* A per-`(saddr, probe_idx)` first-seen flag in the module was not added: XMap
  has no reusable table for it, and it would need another Bloom filter or hash
  sized by `targets × probes`. Deduplicate downstream.

### Batch and probe spacing

XMap sends the `N` probes of one target consecutively through
`make_packet` → `sendto` in a single loop. The rate limiter sleeps once per
`--batch` packets, so with `--batch=1` consecutive probes are `1/rate` apart,
where `rate` is the global packet rate derived from `-B`. At `-B 100K` that is
several milliseconds; at higher `-B` or `--batch>1` they can be microseconds
apart.

Measured (`--probes=3`, IPv4, 300 targets, median of `sent_ts_ns` differences
between consecutive probes of the same target):

| `-B` | `--batch` | packet rate | spacing between probes of a target |
|---|---|---|---|
| 100K | 1 | 142 pps | 7.0 ms |
| 1M | 1 | 1.46 Kpps | 0.68 ms |
| 10M | 1 | 14.6 Kpps | 34 µs |
| 1M | 10 | 1.46 Kpps | 3-4 µs (back to back; a ~7 ms gap where a batch boundary falls between two probes) |
| 10M | 100 | 14.6 Kpps | 4-5 µs (idem) |

Probes spaced microseconds apart see the same queue and path state; their RTTs
are strongly correlated and should not be treated as `N` independent samples.
With `--batch=1` at a low `-B` (the current production form) they are
milliseconds apart, which is better but still far inside typical path
coherence times (queues, route flaps and rate limiters act over seconds).

`--batch>1`: XMap does not defer or batch `sendto()` (no `sendmmsg`), so the
timestamp is not stale by a batch; the sends are bursty, which can make the
kernel queue the later packets of the burst. That queueing is part of the
send path and is *included* in the measured RTT (the stamp precedes
`sendto()`); at normal rates it is negligible but is not measured here.

## Limitations

* **PF_RING / ZC:** not supported. Built with `WITH_PFRING`, the module refuses
  to start (its timestamps are not `CLOCK_REALTIME`). Only the default libpcap
  receive path is supported.
* **Clock steps:** NTP steps between send and receive are detected only if they
  push `recv < sent` or `sent` before the scan start (`clock_anomaly`). A small
  step inside a valid range is not detectable.
* **Slewing:** `CLOCK_REALTIME` may be slewed by NTP at up to 500 ppm;
  irrelevant for RTTs of seconds or less.
* **IPv4 error packets:** the quoted payload is usually cut off; those rows get
  `truncated`.
* **Payload size:** larger than `icmp_echo`'s default; some networks rate-limit
  or filter by size. The payload is fixed and cannot be customised.
* **Send timestamp** is written before the kernel/NIC queues the packet, so
  `rtt_us` includes local transmit queueing.
* `snaplen` assumes a plain Ethernet capture and IP headers without options.
* `-M icmp_echo_time` with `--probe-args` is an error.

## Examples

Compatible with the existing pipeline — one row per IP, RTT of the first reply:

```
xmap -6 -I targets.txt -M icmp_echo_time -O csv -B 100K \
  --batch=1 --probes=3 --cooldown-secs=10 \
  --output-filter='success = 1 && repeat = 0' \
  -f saddr,hlim,clas,desc,type,code,timestamp_str,rtt_us,rtt_valid,rtt_status \
  --metadata-file meta.json -o out.csv
```

All N RTTs — then deduplicate by `(saddr, probe_idx)`:

```
xmap -6 -I targets.txt -M icmp_echo_time -O csv -B 100K \
  --batch=1 --probes=3 --cooldown-secs=10 \
  --output-filter='success = 1' \
  -f saddr,probe_idx,repeat,sent_ts_ns,recv_ts_ns,rtt_us,rtt_valid,rtt_status \
  --metadata-file meta.json -o out_all.csv
```

```python
best = {}
for row in csv.DictReader(open("out_all.csv")):
    if row["rtt_valid"] != "1":
        continue
    k = (row["saddr"], row["probe_idx"])
    if k not in best or int(row["recv_ts_ns"]) < int(best[k]["recv_ts_ns"]):
        best[k] = row
```

For IPv4 use `-4` and `ttl` instead of `hlim`.

## Metadata

`--metadata-file` gets an `icmp_echo_time` object:

```json
"icmp_echo_time": {
  "module": "icmp_echo_time", "family": "ipv4", "payload_version": 1,
  "payload_len": 24, "pcap_tstamp_precision": "nanosecond",
  "clock_source": "CLOCK_REALTIME",
  "sent_ts_point": "end of make_packet, before sendto",
  "batch": 1, "git_commit": "<git describe at cmake configure time>"
}
```

`git_commit` is taken when `cmake` is run (re-run `cmake` after committing).

## Rate and bandwidth

`-B` is converted to a packet rate with the module's `packet_length`
(set statically to 66 / 98 B here). At the same `-B`, `icmp_echo_time` sends
fewer packets per second than the 50 / 78 B `icmp_echo` packets, with the same
bit rate. If the scan must keep the same packet rate as before, raise `-B` or
use `-r`.

## Tests

`tests/rtt/` — see `tests/rtt/README.md`.
