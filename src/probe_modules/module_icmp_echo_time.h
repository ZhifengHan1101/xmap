/*
 * XMap icmp_echo_time: ICMP echo probes that carry their own send timestamp.
 *
 * Shared by the IPv4 and IPv6 modules. Payload layout (network byte order,
 * fixed length):
 *
 *   off  len  field
 *     0    4  magic       0x584D5254 "XMRT"
 *     4    1  version     1
 *     5    1  probe_idx   0..probes-1
 *     6    2  reserved    0
 *     8    8  sent_ts_ns  CLOCK_REALTIME, ns since epoch
 *    16  4|16 dst_echo    probe destination (IPv4 4B / IPv6 16B)
 *  20|32    4  tag        keyed over (dst_echo, sent_ts_ns, probe_idx)
 *
 * See docs/icmp_echo_time.md.
 */

#ifndef XMAP_MODULE_ICMP_ECHO_TIME_H
#define XMAP_MODULE_ICMP_ECHO_TIME_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "../fieldset.h"

#define RTT_MAGIC 0x584D5254u
#define RTT_VERSION 1
#define RTT_HDR_LEN 16 // magic .. sent_ts_ns
#define RTT_TAG_LEN 4

#define RTT_PAYLOAD_LEN(addr_len) (RTT_HDR_LEN + (addr_len) + RTT_TAG_LEN)

typedef enum {
    RTT_OK = 0,
    RTT_NO_PAYLOAD,
    RTT_BAD_MAGIC,
    RTT_BAD_VERSION,
    RTT_TRUNCATED,
    RTT_BAD_TAG,
    RTT_BAD_ADDR,
    RTT_CLOCK_ANOMALY,
    RTT_FROM_ICMP_ERROR,
    RTT_STATUS_COUNT,
} rtt_status_t;

typedef struct {
    rtt_status_t status;
    int          have_times;  // probe_idx/sent/recv/rtt/daddr are trustworthy
    uint8_t      probe_idx;
    uint64_t     sent_ns;
    uint64_t     recv_ns;
    uint8_t      dst[16];
} rtt_result_t;

// Fields appended after the icmp_echo fields; same order as rtt_fs_add.
#define RTT_FIELDDEFS                                                          \
    {.name = "probe_idx",                                                      \
     .type = "int",                                                            \
     .desc = "probe number (0..probes-1) read from the echoed payload"},       \
        {.name = "sent_ts_us",                                                 \
         .type = "int",                                                        \
         .desc = "send time, microseconds since epoch (CLOCK_REALTIME)"},      \
        {.name = "recv_ts_us",                                                 \
         .type = "int",                                                        \
         .desc = "capture time of the response (pcap header), microseconds "   \
                 "since epoch"},                                               \
        {.name = "sent_ts_ns",                                                 \
         .type = "int",                                                        \
         .desc = "send time, nanoseconds since epoch"},                        \
        {.name = "recv_ts_ns",                                                 \
         .type = "int",                                                        \
         .desc = "capture time, nanoseconds since epoch (microsecond "         \
                 "resolution if pcap has no nano timestamps)"},                \
        {.name = "rtt_us",                                                     \
         .type = "int",                                                        \
         .desc = "recv_ts_us - sent_ts_us; empty unless computed"},            \
        {.name = "rtt_valid", .type = "int", .desc = "1 if rtt_us is usable"}, \
        {.name = "rtt_status",                                                 \
         .type = "string",                                                     \
         .desc = "ok, no_payload, bad_magic, bad_version, truncated, "         \
                 "bad_tag, bad_addr, clock_anomaly, from_icmp_error"},         \
        {.name = "probe_daddr",                                                \
         .type = "string",                                                     \
         .desc = "probe destination address echoed in the payload"},

#define RTT_NUMFIELDS 9

// Called from global_init: records the scan start (for the plausibility check),
// refuses to run on the PF_RING receive path.
int rtt_global_init(void);

// Payload for one probe. `payload` must have RTT_PAYLOAD_LEN(addr_len) bytes.
// Returns the timestamp that was written.
uint64_t rtt_payload_write(uint8_t *payload, const uint8_t *dst, int addr_len,
                           uint8_t probe_idx);

// Examine up to `avail` bytes of echoed payload. `expect_dst` is the address
// the probe must have been sent to. Fills `r` (status, and times if trusted).
void rtt_analyze(const uint8_t *payload, size_t avail, const uint8_t *expect_dst,
                 int addr_len, int from_error, struct timespec recv_ts,
                 rtt_result_t *r);

// Append the RTT_FIELDDEFS columns. ipv6 selects address formatting.
void rtt_fs_add(fieldset_t *fs, const rtt_result_t *r, int ipv6);

// --metadata-file entries (probe_module_t.metadata).
void rtt_metadata(void *json_obj, const char *family, int addr_len);

#endif // XMAP_MODULE_ICMP_ECHO_TIME_H
