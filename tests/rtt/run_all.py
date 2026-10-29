#!/usr/bin/env python3
"""icmp_echo_time end-to-end checks inside the xm-scan / xm-resp namespaces.

Needs root, the namespaces from netns_up.sh, tc/tcpdump, and scapy (only for
the independent checksum/layout check of captured probes).

  run_all.py --xmap BUILD/src/xmap [--xmap-old OLD/src/xmap] \
             [--out DIR] [--only delay,dup,reorder,tamper,regress,perf]

IPv4 targets in 10.88.0.0/24 are answered by the responder kernel (set N in
netns_up.sh >= 500 for the delay test); IPv4 10.99/10.96 and IPv6 fd99:: are
answered by responder.py at L2, so IPv6 works on hosts without kernel IPv6.
"""
import argparse, csv, ipaddress, json, os, signal, statistics, struct
import subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
SCAN, RESP = "xm-scan", "xm-resp"
FAIL = []


def sh(cmd, ns=None, check=True, **kw):
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    return subprocess.run(cmd, check=check, text=True, capture_output=True, **kw)


def mac(ns, dev):
    return sh(["ip", "-br", "link", "show", dev], ns).stdout.split()[2]


def check(name, ok, detail=""):
    print(("  PASS " if ok else "  FAIL ") + name + (" " + detail if detail else ""))
    if not ok:
        FAIL.append(name)


def netem(spec):
    if spec is not None:
        # warm the neighbour caches first: otherwise the responder kernel queues
        # the first replies behind an ARP exchange that netem delays as well
        sh(["ping", "-c1", "-W1", "10.77.0.2"], SCAN, check=False)
    if spec is None:
        sh(["tc", "qdisc", "del", "dev", "vb", "root"], RESP, check=False)
    else:
        sh(["tc", "qdisc", "replace", "dev", "vb", "root", "netem"] + spec.split(), RESP)


class Responder:
    def __init__(self, *args):
        self.args = list(args)

    def __enter__(self):
        self.p = subprocess.Popen(
            ["ip", "netns", "exec", RESP, sys.executable,
             os.path.join(HERE, "responder.py"), "vb"] + self.args,
            stderr=subprocess.PIPE, text=True)
        self.p.stderr.readline()  # "responder ready"
        return self

    def __exit__(self, *a):
        self.p.send_signal(signal.SIGTERM)
        self.p.wait()


class Capture:
    """tcpdump on va with nanosecond timestamps (ground truth for pairing)."""
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.p = subprocess.Popen(
            ["ip", "netns", "exec", SCAN, "tcpdump", "-i", "va", "-nn", "--nano", "-U",
             "-s", "300", "-w", self.path, "icmp or icmp6"],
            stderr=subprocess.DEVNULL)
        time.sleep(0.7)
        return self

    def __exit__(self, *a):
        time.sleep(0.5)
        self.p.send_signal(signal.SIGINT)
        self.p.wait()


def read_pcap(path):
    with open(path, "rb") as f:
        d = f.read()
    magic = struct.unpack("<I", d[:4])[0]
    assert magic == 0xA1B23C4D, "expected nanosecond pcap"
    off = 24
    while off + 16 <= len(d):
        s, ns, cl, _ = struct.unpack("<IIII", d[off:off + 16])
        off += 16
        yield s * 10**9 + ns, d[off:off + cl]
        off += cl


def addr_str(fam, b):
    import socket
    return socket.inet_ntop(socket.AF_INET if fam == 4 else socket.AF_INET6, b)


def xmap(binary, fam, module, targets, out, rate="1M", extra=(), fields=None,
         flt="success = 1", probes=3, cooldown=2, scan_mac=None, resp_mac=None):
    fields = fields or ("saddr,probe_idx,repeat,success,sent_ts_ns,recv_ts_ns,"
                        "rtt_us,rtt_valid,rtt_status,probe_daddr")
    meta = out + ".meta.json"
    cmd = [binary, f"-{fam}", "-I", targets, "-M", module, "-i", "va",
           "-G", resp_mac, "-S", "10.77.0.1" if fam == 4 else "fd77::1",
           "-B", rate, f"--probes={probes}", f"--cooldown-secs={cooldown}",
           "-O", "csv", "-f", fields, "--output-filter=" + flt,
           "--metadata-file", meta, "-o", out, "--seed=7"] + list(extra)
    r = sh(cmd, SCAN, check=False)
    if r.returncode:
        print(r.stderr[-800:])
    with open(out) as f:
        rows = list(csv.DictReader(f))
    with open(meta) as f:
        return rows, json.load(f)


def targets(fam, prefix, n, path):
    """n targets: v4 prefix 'a.b.' + 250 hosts per /24 (as netns_up.sh), v6 prefix::i."""
    with open(path, "w") as f:
        for i in range(n):
            if fam == 4:
                f.write(f"{prefix}{i // 250}.{i % 250 + 1}\n")
            else:
                f.write(f"{prefix}{i + 1:x}\n")
    return path


def pct(v, p):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100 * (len(v) - 1))))]


def ints(rows, col):
    return [int(r[col]) for r in rows if r[col] != ""]


# ---------------------------------------------------------------------------
# independent ground truth from the capture

def ground_truth(rows, pcap, fam, scan_mac, nsample=60):
    """Match xmap rows to the tcpdump capture. Returns (bad_sent, bad_recv, bad_csum, n)."""
    from scapy.all import Ether, IP, IPv6, ICMP, ICMPv6EchoRequest
    reqs, reps = {}, {}
    bad_csum = checked = 0
    for ts, fr in read_pcap(pcap):
        out = fr[6:12] == bytes.fromhex(scan_mac.replace(":", ""))
        ip = fr[14:]
        if fam == 4:
            if fr[12:14] != b"\x08\x00":
                continue
            ihl = (ip[0] & 15) * 4
            typ, pl = ip[ihl], ip[ihl + 8:]
            peer = addr_str(4, ip[16:20] if out else ip[12:16])
        else:
            if fr[12:14] != b"\x86\xdd":
                continue
            typ, pl = ip[40], ip[48:]
            peer = addr_str(6, ip[24:40] if out else ip[8:24])
        if len(pl) < 6 or pl[:4] != b"XMRT":
            continue
        if out and typ in (8, 128):
            reqs[(peer, pl[5])] = (ts, struct.unpack(">Q", pl[8:16])[0])
            if checked < nsample:  # scapy recomputes IP and ICMP(v6) checksums
                checked += 1
                p = Ether(fr)
                if fam == 4:
                    want_ip, want_ic = p[IP].chksum, p[ICMP].chksum
                    del p[IP].chksum, p[ICMP].chksum
                    q = Ether(bytes(p))
                    ok = (q[IP].chksum, q[ICMP].chksum) == (want_ip, want_ic)
                else:
                    want = p[ICMPv6EchoRequest].cksum
                    del p[ICMPv6EchoRequest].cksum
                    q = Ether(bytes(p))
                    ok = q[ICMPv6EchoRequest].cksum == want
                bad_csum += not ok
        elif not out and typ in (0, 129):
            reps.setdefault((peer, pl[5]), []).append(ts)
    bad_sent = bad_recv = n = 0
    for r in rows:
        if r["rtt_status"] != "ok":
            continue
        n += 1
        k = (r["probe_daddr"], int(r["probe_idx"]))
        rq = reqs.get(k)
        if rq is None or abs(int(r["sent_ts_ns"]) - rq[0]) > 500_000 \
                or int(r["sent_ts_ns"]) != rq[1]:
            bad_sent += 1
        if not any(abs(int(r["recv_ts_ns"]) - t) <= 5_000 for t in reps.get(k, [])):
            bad_recv += 1
    return bad_sent, bad_recv, bad_csum, n


# ---------------------------------------------------------------------------

def ctx_tmp(args, name):
    return os.path.join(args.out, name)


def t_delay(a):
    print("== delay: rtt_us vs netem delay (median within +-1 ms)")
    out = {}
    for fam in (4, 6):
        if fam == 4:
            t = targets(4, "10.88.", 500, ctx_tmp(a, "t4k.txt"))
            r = None
        else:
            t = targets(6, "fd99::", 500, ctx_tmp(a, "t6.txt"))
            r = Responder("--prefix", "fd99::")
        try:
            if r: r.__enter__()
            for d in (20, 50, 100):
                netem(f"delay {d}ms")
                try:
                    pc = ctx_tmp(a, f"delay_v{fam}_{d}.pcap")
                    with Capture(pc):
                        rows, meta = xmap(a.xmap, fam, "icmp_echo_time", t,
                                          ctx_tmp(a, f"delay_v{fam}_{d}.csv"),
                                          cooldown=d // 1000 + 2, scan_mac=a.scan_mac,
                                          resp_mac=a.resp_mac)
                finally:
                    netem(None)
                v = ints(rows, "rtt_us")
                med = statistics.median(v)
                out[f"v{fam}_{d}ms"] = dict(n=len(v), min=min(v), median=med, p99=pct(v, 99))
                print(f"  v{fam} {d:>3} ms: n={len(v)} min={min(v)} median={med:.0f} "
                      f"p99={pct(v, 99)} us  status={sorted(set(x['rtt_status'] for x in rows))}")
                check(f"v{fam} delay {d}ms median", abs(med - d * 1000) <= 1000,
                      f"(median {med:.0f} us)")
                bs, br, bc, n = ground_truth(rows, pc, fam, a.scan_mac)
                check(f"v{fam} delay {d}ms capture cross-check", bs == br == bc == 0 and n > 0,
                      f"(rows={n} bad_sent={bs} bad_recv={br} bad_checksum={bc})")
        finally:
            if r: r.__exit__()
    return out


def t_dup(a):
    print("== dup: netem delay 20ms duplicate 10%")
    out = {}
    for fam in (4, 6):
        t = targets(fam, "10.88." if fam == 4 else "fd99::", 300,
                    ctx_tmp(a, f"tdup{fam}.txt"))
        r = Responder("--prefix", "fd99::") if fam == 6 else None
        try:
            if r: r.__enter__()
            netem("delay 20ms duplicate 10%")
            pc = ctx_tmp(a, f"dup_v{fam}.pcap")
            with Capture(pc):
                allrows, meta = xmap(a.xmap, fam, "icmp_echo_time", t,
                                     ctx_tmp(a, f"dup_v{fam}.csv"), scan_mac=a.scan_mac,
                                     resp_mac=a.resp_mac)
        finally:
            netem(None)
            if r: r.__exit__()
        first = [x for x in allrows if x["repeat"] == "0"]
        per_ip = {}
        for x in first:
            per_ip[x["saddr"]] = per_ip.get(x["saddr"], 0) + 1
        keys = {}
        for x in allrows:
            keys.setdefault((x["saddr"], x["probe_idx"]), []).append(x)
        dups = {k: v for k, v in keys.items() if len(v) > 1}
        dedup = [min(v, key=lambda x: int(x["recv_ts_ns"])) for v in keys.values()]
        rtts = ints(dedup, "rtt_us")
        print(f"  v{fam}: rows={len(allrows)} repeat=0 rows={len(first)} "
              f"(saddr,probe_idx) with duplicates={len(dups)} after-dedup={len(dedup)}")
        check(f"v{fam} one repeat=0 row per IP", set(per_ip.values()) == {1} and len(per_ip) == 300)
        check(f"v{fam} DUP produced repeated (saddr,probe_idx)", len(dups) > 0)
        check(f"v{fam} dedup leaves 3 probes per IP", len(dedup) == 900)
        check(f"v{fam} RTT stays 20 ms after dedup",
              abs(statistics.median(rtts) - 20000) <= 1000 and max(rtts) < 21500,
              f"(median {statistics.median(rtts):.0f} max {max(rtts)})")
        out[f"v{fam}"] = dict(rows=len(allrows), dup_keys=len(dups))
    return out


def t_reorder(a):
    print("== reorder + loss: netem delay 50ms reorder 25% 50% loss 30%")
    out = {}
    for fam in (4, 6):
        t = targets(fam, "10.88." if fam == 4 else "fd99::", 500,
                    ctx_tmp(a, f"tro{fam}.txt"))
        r = Responder("--prefix", "fd99::") if fam == 6 else None
        try:
            if r: r.__enter__()
            netem("delay 50ms reorder 25% 50% loss 30%")
            pc = ctx_tmp(a, f"ro_v{fam}.pcap")
            with Capture(pc):
                rows, meta = xmap(a.xmap, fam, "icmp_echo_time", t,
                                  ctx_tmp(a, f"ro_v{fam}.csv"), cooldown=3,
                                  scan_mac=a.scan_mac, resp_mac=a.resp_mac)
        finally:
            netem(None)
            if r: r.__exit__()
        bs, br, bc, n = ground_truth(rows, pc, fam, a.scan_mac)
        v = ints(rows, "rtt_us")
        fast = sum(x < 10000 for x in v)
        slow = sum(abs(x - 50000) < 1500 for x in v)
        got = len(rows) / 1500
        print(f"  v{fam}: replies={len(rows)}/1500 ({got:.0%}) rtt~0 (reordered)={fast} "
              f"rtt~50ms={slow} other={len(v) - fast - slow}")
        check(f"v{fam} every row paired with its own request/reply in the capture",
              bs == br == bc == 0 and n == len(rows), f"(bad_sent={bs} bad_recv={br} bad_csum={bc})")
        check(f"v{fam} loss ~30%", 0.6 <= got <= 0.8)
        check(f"v{fam} rtt is either reordered (~0) or delayed (50 ms)",
              len(v) - fast - slow == 0)
        out[f"v{fam}"] = dict(replies=len(rows), reordered=fast, delayed=slow)
    return out


def t_tamper(a):
    print("== tamper: damaged echo payloads must not change success")
    exp = {"ok": "ok", "magic": "bad_magic", "tag": "bad_tag",
           "truncate:10": "truncated", "truncate:3": "truncated",
           "nopayload": "no_payload"}
    out = {}
    for fam in (4, 6):
        pref = "10.99." if fam == 4 else "fd99::"
        t = targets(fam, pref, 50, ctx_tmp(a, f"tt{fam}.txt"))
        for mode, status in exp.items():
            with Responder("--prefix", pref, "--mode", mode):
                rows, meta = xmap(a.xmap, fam, "icmp_echo_time", t,
                                  ctx_tmp(a, f"tamper_v{fam}_{mode.replace(':', '_')}.csv"),
                                  flt="", scan_mac=a.scan_mac, resp_mac=a.resp_mac)
            succ = [x for x in rows if x["success"] == "1"]
            uniq = {x["saddr"] for x in succ}
            sts = {x["rtt_status"] for x in rows}
            valid = {x["rtt_valid"] for x in rows}
            empty = all(x["rtt_us"] == "" for x in rows) if mode != "ok" else True
            print(f"  v{fam} {mode:<12}: success rows={len(succ)} ips={len(uniq)} "
                  f"status={sts} valid={valid} rtt_us empty={empty}")
            check(f"v{fam} {mode}: success unchanged (150 replies, 50 IPs)",
                  len(succ) == 150 and len(uniq) == 50 and meta["success_unique"] == 50)
            check(f"v{fam} {mode}: rtt_status={status} rtt_valid={'1' if mode == 'ok' else '0'}",
                  sts == {status} and valid == {"1" if mode == "ok" else "0"} and empty)
            out[f"v{fam}_{mode}"] = sorted(sts)
        # ICMP errors quoting the probe
        for q, status, val in ((10**6, "from_icmp_error", "1"), (0, "truncated", "0")):
            for err in ("unreach", "timex"):
                with Responder("--prefix", pref, "--err", err, "--err-quote", str(q)):
                    rows, meta = xmap(a.xmap, fam, "icmp_echo_time", t,
                                      ctx_tmp(a, f"err_v{fam}_{err}_{q}.csv"), flt="",
                                      scan_mac=a.scan_mac, resp_mac=a.resp_mac)
                sts = {x["rtt_status"] for x in rows}
                ok = rows and {x["success"] for x in rows} == {"0"} and {x["rtt_valid"] for x in rows} == {val} \
                    and sts == {status}
                v = ints(rows, "rtt_us")
                print(f"  v{fam} error {err:<7} quote={'full' if q else 'min ':<4}: rows={len(rows)} "
                      f"status={sts} valid={ {x['rtt_valid'] for x in rows} } "
                      f"rtt_us median={statistics.median(v) if v else '-'}")
                check(f"v{fam} {err} error quote={'full' if q else 'min'} -> {status}", ok)
    return out


FIELDS_OLD = "saddr,daddr,ttl,clas,desc,type,code,icmp_id,seq,outersaddr,success,repeat"


def t_regress(a):
    print("== regression: icmp_echo (old build / new build) vs icmp_echo_time on old fields")
    out = {}
    for fam in (4, 6):
        pref = "10.99." if fam == 4 else "fd99::"
        t = targets(fam, pref, 100, ctx_tmp(a, f"trg{fam}.txt"))
        # hlim/ttl is fixed by the responder (64); ipid is left out (kernel/responder-set)
        f = FIELDS_OLD.replace("daddr,", "daddr,") .replace(",ttl", ",ttl" if fam == 4 else ",hlim")
        res = {}
        for label, binary, module in (("old icmp_echo", a.xmap_old, "icmp_echo"),
                                      ("new icmp_echo", a.xmap, "icmp_echo"),
                                      ("new icmp_echo_time", a.xmap, "icmp_echo_time")):
            if not binary:
                continue
            for kind, extra in (("echo", ()), ("unreach", ("err",))):
                args = ["--prefix", pref if fam == 6 else "10.99."] + (["--err", "unreach", "--err-quote", "40"] if extra else [])
                with Responder(*args):
                    rows, meta = xmap(binary, fam, module, t,
                                      ctx_tmp(a, f"reg_v{fam}_{label.replace(' ', '_')}_{kind}.csv"),
                                      fields=f, flt="", scan_mac=a.scan_mac, resp_mac=a.resp_mac)
                res[(label, kind)] = sorted(tuple(r.values()) for r in rows)
                res[(label, kind, "m")] = {k: meta[k] for k in
                    ("packets_sent", "hosts_scanned", "success_total", "success_unique",
                     "failure_total", "validation_passed", "validation_failed")}
        for kind in ("echo", "unreach"):
            base = res.get(("new icmp_echo", kind))
            for label in ("old icmp_echo", "new icmp_echo_time"):
                if (label, kind) in res:
                    same = res[(label, kind)] == base
                    check(f"v{fam} {kind}: {label} rows == new icmp_echo rows ({len(base)} rows)", same)
                    mm = res[(label, kind, "m")] == res[("new icmp_echo", kind, "m")]
                    check(f"v{fam} {kind}: {label} counters == new icmp_echo", mm,
                          "" if mm else str((res[(label, kind, 'm')], res[('new icmp_echo', kind, 'm')])))
        out[f"v{fam}"] = {f"{k[0]}/{k[1]}": len(v) for k, v in res.items() if len(k) == 2}
    return out


def t_perf(a):
    print("== perf: 100k targets, -B 1M, --probes=3 (IPv4, responder.py answers)")
    tp = ctx_tmp(a, "tperf.txt")
    with open(tp, "w") as f:
        base = int(ipaddress.IPv4Address("10.96.0.1"))
        for i in range(100_000):
            f.write(str(ipaddress.IPv4Address(base + i)) + "\n")
    out = {}
    for module in ("icmp_echo", "icmp_echo_time"):
        with Responder("--prefix", "10.96.", "--prefix", "10.97."):
            t0 = time.time()
            rows, meta = xmap(a.xmap, 4, module, tp, ctx_tmp(a, f"perf_{module}.csv"),
                              fields="saddr,repeat", flt="success = 1 && repeat = 0",
                              cooldown=8, scan_mac=a.scan_mac, resp_mac=a.resp_mac)
            wall = time.time() - t0
        import datetime as dt
        p = lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z").timestamp()
        send_s = max(p(meta["send_end_time"]) - p(meta["send_start_time"]), 1)
        num, unit = meta["rate"].split()
        cfg_pps = float(num) * {"pps": 1, "Kpps": 1e3, "Mpps": 1e6}[unit]
        out[module] = dict(cfg_rate=meta["rate"], cfg_pps=cfg_pps, packets_sent=meta["packets_sent"], send_secs=send_s,
                           send_pps=meta["packets_sent"] / send_s,
                           send_to_failures=meta["send_to_failures"],
                           success_unique=meta["success_unique"], rows=len(rows),
                           pcap_recv=meta["pcap_recv"], pcap_drop=meta["pcap_drop"],
                           pcap_ifdrop=meta["pcap_ifdrop"], wall=wall)
        print(f"  {module:<15}", json.dumps(out[module]))
    o, n = out["icmp_echo"], out["icmp_echo_time"]
    check("perf: same packets_sent", o["packets_sent"] == n["packets_sent"] == 300000)
    # -B fixes the bit rate, so the packet rate differs with the packet size
    # (50 B vs 66 B + the 24 B framing allowance in monitor/send); each module
    # must hit the packet rate XMap derived for it.
    for m, v in out.items():
        check(f"perf: {m} achieved rate within 5% of configured ({v['cfg_rate']})",
              abs(v["send_pps"] / v["cfg_pps"] - 1) < 0.05,
              f"({v['send_pps']:.0f} pps vs {v['cfg_pps']:.0f})")
    check("perf: no pcap drops, same unique successes",
          n["pcap_drop"] == o["pcap_drop"] == 0 and n["success_unique"] == o["success_unique"])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--xmap", required=True)
    ap.add_argument("--xmap-old")
    ap.add_argument("--out", default=tempfile.mkdtemp(prefix="rtt_"))
    ap.add_argument("--only", default="delay,dup,reorder,tamper,regress")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    a.scan_mac, a.resp_mac = mac(SCAN, "va"), mac(RESP, "vb")
    res = {}
    for name in a.only.split(","):
        res[name] = globals()["t_" + name](a)
        with open(os.path.join(a.out, "results.json"), "w") as f:
            json.dump(res, f, indent=1, default=str)
    print(f"\nresults in {a.out}")
    print("FAILED: " + ", ".join(FAIL) if FAIL else "ALL CHECKS PASSED")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
