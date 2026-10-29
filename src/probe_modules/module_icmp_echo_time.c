/*
 * XMap icmp_echo_time: payload, tag and RTT logic shared by the IPv4 and IPv6
 * modules. See module_icmp_echo_time.h.
 */

#include "module_icmp_echo_time.h"

#include <arpa/inet.h>
#include <json.h>
#include <string.h>

#include "../recv.h"
#include "../state.h"
#include "../validate.h"

#include "../../lib/logger.h"
#include "../../lib/xalloc.h"

#ifndef XMAP_RTT_GIT_COMMIT
#define XMAP_RTT_GIT_COMMIT "unknown"
#endif

static uint64_t scan_start_ns;

static const char *const status_str[RTT_STATUS_COUNT] = {
    "ok",       "no_payload", "bad_magic",     "bad_version",
    "truncated", "bad_tag",   "bad_addr",      "clock_anomaly",
    "from_icmp_error",
};

static uint64_t realtime_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    return (uint64_t) t.tv_sec * 1000000000ull + (uint64_t) t.tv_nsec;
}

int rtt_global_init(void) {
#ifdef PFRING
    log_error("icmp_echo_time",
              "not supported with PF_RING receive: packet timestamps are not "
              "CLOCK_REALTIME. Build without WITH_PFRING.");
    return EXIT_FAILURE;
#endif
    scan_start_ns = realtime_ns();
    return EXIT_SUCCESS;
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = v >> 24, p[1] = v >> 16, p[2] = v >> 8, p[3] = v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    put_be32(p, (uint32_t) (v >> 32));
    put_be32(p + 4, (uint32_t) v);
}

static uint32_t get_be32(const uint8_t *p) {
    return (uint32_t) p[0] << 24 | (uint32_t) p[1] << 16 | (uint32_t) p[2] << 8 |
           p[3];
}

static uint64_t get_be64(const uint8_t *p) {
    return (uint64_t) get_be32(p) << 32 | get_be32(p + 4);
}

// CBC-MAC over two AES blocks under the scan's validation key:
//   b1 = AES(dst || 0.. || domain)   b2 = AES(b1 ^ (sent_ts_ns || probe_idx))
// The domain byte keeps the input space disjoint from validate_gen's
// (src ^ dst) blocks, whose output is visible on the wire as ICMP id/seq.
static uint32_t make_tag(const uint8_t *dst, int addr_len, uint8_t probe_idx,
                         uint64_t sent_ns) {
    uint8_t blk[VALIDATE_BYTES] = {0}, b1[VALIDATE_BYTES], b2[VALIDATE_BYTES];
    memcpy(blk, dst, addr_len);
    blk[VALIDATE_BYTES - 1] = 0xA5;
    validate_prf16(blk, b1);

    memset(blk, 0, sizeof(blk));
    put_be64(blk, sent_ns);
    blk[8] = probe_idx;
    for (int i = 0; i < VALIDATE_BYTES; i++)
        blk[i] ^= b1[i];
    validate_prf16(blk, b2);
    return get_be32(b2);
}

uint64_t rtt_payload_write(uint8_t *payload, const uint8_t *dst, int addr_len,
                           uint8_t probe_idx) {
    uint64_t sent_ns = realtime_ns();
    put_be32(payload, RTT_MAGIC);
    payload[4] = RTT_VERSION;
    payload[5] = probe_idx;
    payload[6] = payload[7] = 0;
    put_be64(payload + 8, sent_ns);
    memcpy(payload + RTT_HDR_LEN, dst, addr_len);
    put_be32(payload + RTT_HDR_LEN + addr_len,
             make_tag(dst, addr_len, probe_idx, sent_ns));
    return sent_ns;
}

void rtt_analyze(const uint8_t *p, size_t avail, const uint8_t *expect_dst,
                 int addr_len, int from_error, struct timespec recv_ts,
                 rtt_result_t *r) {
    memset(r, 0, sizeof(*r));
    if (avail == 0) {
        // errors usually quote only the first 8 bytes of the original
        r->status = from_error ? RTT_TRUNCATED : RTT_NO_PAYLOAD;
        return;
    }
    if (avail >= 4 && get_be32(p) != RTT_MAGIC) {
        r->status = RTT_BAD_MAGIC;
        return;
    }
    if (avail < (size_t) RTT_PAYLOAD_LEN(addr_len)) {
        r->status = RTT_TRUNCATED;
        return;
    }
    if (p[4] != RTT_VERSION) {
        r->status = RTT_BAD_VERSION;
        return;
    }
    uint8_t  idx     = p[5];
    uint64_t sent_ns = get_be64(p + 8);
    if (get_be32(p + RTT_HDR_LEN + addr_len) !=
        make_tag(p + RTT_HDR_LEN, addr_len, idx, sent_ns)) {
        r->status = RTT_BAD_TAG;
        return;
    }
    if (memcmp(p + RTT_HDR_LEN, expect_dst, addr_len) != 0) {
        r->status = RTT_BAD_ADDR;
        return;
    }

    r->have_times = 1;
    r->probe_idx  = idx;
    r->sent_ns    = sent_ns;
    r->recv_ns    = (uint64_t) recv_ts.tv_sec * 1000000000ull +
                 (uint64_t) recv_ts.tv_nsec;
    memcpy(r->dst, p + RTT_HDR_LEN, addr_len);

    // The probe cannot have left before the scan started, nor arrive before it
    // was sent. Either means the realtime clock was stepped in between.
    if (r->recv_ns < sent_ns || sent_ns < scan_start_ns) {
        r->status = RTT_CLOCK_ANOMALY;
    } else {
        r->status = from_error ? RTT_FROM_ICMP_ERROR : RTT_OK;
    }
}

void rtt_fs_add(fieldset_t *fs, const rtt_result_t *r, int ipv6) {
    int usable = r->have_times;
    int valid  = r->status == RTT_OK || r->status == RTT_FROM_ICMP_ERROR;

    if (usable) {
        fs_add_uint64(fs, "probe_idx", r->probe_idx);
        // sent/recv are floored to us; rtt_us is their difference, so it is
        // consistent with the printed columns (and may differ by 1 from
        // floor(rtt_ns / 1000)).
        fs_add_uint64(fs, "sent_ts_us", r->sent_ns / 1000);
        fs_add_uint64(fs, "recv_ts_us", r->recv_ns / 1000);
        fs_add_uint64(fs, "sent_ts_ns", r->sent_ns);
        fs_add_uint64(fs, "recv_ts_ns", r->recv_ns);
        if (r->recv_ns >= r->sent_ns) {
            fs_add_uint64(fs, "rtt_us", r->recv_ns / 1000 - r->sent_ns / 1000);
        } else {
            fs_add_null(fs, "rtt_us"); // unsigned field cannot hold negatives
        }
    } else {
        fs_add_null(fs, "probe_idx");
        fs_add_null(fs, "sent_ts_us");
        fs_add_null(fs, "recv_ts_us");
        fs_add_null(fs, "sent_ts_ns");
        fs_add_null(fs, "recv_ts_ns");
        fs_add_null(fs, "rtt_us");
    }
    fs_add_uint64(fs, "rtt_valid", valid);
    fs_add_constchar(fs, "rtt_status", status_str[r->status]);

    if (usable) {
        char *s = xmalloc(INET6_ADDRSTRLEN);
        inet_ntop(ipv6 ? AF_INET6 : AF_INET, r->dst, s, INET6_ADDRSTRLEN);
        fs_add_string(fs, "probe_daddr", s, 1);
    } else {
        fs_add_null(fs, "probe_daddr");
    }
}

void rtt_metadata(void *json_obj, const char *family, int addr_len) {
    json_object *o = json_object_new_object();
    json_object_object_add(o, "module", json_object_new_string("icmp_echo_time"));
    json_object_object_add(o, "family", json_object_new_string(family));
    json_object_object_add(o, "payload_version", json_object_new_int(RTT_VERSION));
    json_object_object_add(o, "payload_len",
                           json_object_new_int(RTT_PAYLOAD_LEN(addr_len)));
    json_object_object_add(o, "pcap_tstamp_precision",
                           json_object_new_string(recv_pcap_tstamp_nano
                                                      ? "nanosecond"
                                                      : "microsecond"));
    json_object_object_add(o, "clock_source",
                           json_object_new_string("CLOCK_REALTIME"));
    json_object_object_add(o, "sent_ts_point",
                           json_object_new_string("end of make_packet, before sendto"));
    json_object_object_add(o, "batch", json_object_new_int(xconf.batch));
    json_object_object_add(o, "git_commit",
                           json_object_new_string(XMAP_RTT_GIT_COMMIT));
    json_object_object_add((json_object *) json_obj, "icmp_echo_time", o);
}
