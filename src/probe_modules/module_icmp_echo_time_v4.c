/*
 * XMap icmp_echo_time (IPv4): ICMP echo scan that records per-probe RTT.
 *
 * Superset of module_icmp_echo.c: same validation, success and repeat logic,
 * same leading output fields; the echo payload is a fixed-length record
 * (module_icmp_echo_time.h) instead of --probe-args bytes.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "module_icmp_echo_time.h"
#include "packet.h"
#include "packet_icmp.h"
#include "probe_modules.h"

#include "../../lib/includes.h"
#include "../../lib/logger.h"
#include "../../lib/types.h"
#include "../../lib/xalloc.h"
#include "../fieldset.h"
#include "../validate.h"

#define ICMP_SMALLEST_SIZE 5
#define ICMP_TIMXCEED_UNREACH_HEADER_SIZE 8
#define RTT4_PAYLOAD_LEN RTT_PAYLOAD_LEN(4)

probe_module_t module_icmp_echo_time;

static int icmp_echo_time_global_init(UNUSED struct state_conf *conf) {
    if (conf->probe_args && strlen(conf->probe_args) > 0) {
        log_error("icmp_echo_time",
                  "--probe-args is not supported: the payload is a fixed "
                  "timestamp record");
        return EXIT_FAILURE;
    }
    return rtt_global_init();
}

static int icmp_echo_time_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                                      UNUSED void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth_header(eth_header, src, gw);

    struct ip *ip_header = (struct ip *) (&eth_header[1]);
    uint16_t   ip_len    = sizeof(struct ip) + ICMP_MINLEN + RTT4_PAYLOAD_LEN;
    make_ip_header(ip_header, IPPROTO_ICMP, ip_len);

    struct icmp *icmp_header = (struct icmp *) (&ip_header[1]);
    make_icmp_header(icmp_header);

    return EXIT_SUCCESS;
}

static int icmp_echo_time_make_packet(void *buf, UNUSED size_t *buf_len,
                                      ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                                      UNUSED port_h_t dst_port, uint8_t ttl,
                                      int probe_num, UNUSED index_h_t index,
                                      UNUSED void *arg) {
    struct ether_header *eth_header  = (struct ether_header *) buf;
    struct ip           *ip_header   = (struct ip *) (&eth_header[1]);
    struct icmp         *icmp_header = (struct icmp *) (&ip_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, 0, validation);

    ip_header->ip_src.s_addr = *(uint32_t *) src_ip;
    ip_header->ip_dst.s_addr = *(uint32_t *) dst_ip;
    ip_header->ip_ttl        = ttl;

    icmp_header->icmp_id  = get_icmp_idnum(validation);
    icmp_header->icmp_seq = get_icmp_seqnum(validation);

    // The timestamp goes in last so that it is as close to sendto() as the
    // module interface allows; the checksums only cover the final bytes.
    rtt_payload_write((uint8_t *) icmp_header + ICMP_MINLEN, dst_ip, 4,
                      (uint8_t) probe_num);

    icmp_header->icmp_cksum = 0;
    icmp_header->icmp_cksum = icmp_checksum(icmp_header, RTT4_PAYLOAD_LEN);

    ip_header->ip_sum = 0;
    ip_header->ip_sum = ip_checksum_((unsigned short *) ip_header);

    return EXIT_SUCCESS;
}

static void icmp_echo_time_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header  = (struct ether_header *) packet;
    struct ip           *ip_header   = (struct ip *) &eth_header[1];
    struct icmp         *icmp_header = (struct icmp *) (&ip_header[1]);

    fprintf_eth_header(fp, eth_header);
    fprintf_ip_header(fp, ip_header);
    fprintf(fp,
            "ICMP\n"
            "\tType(1B)\t\t: %u\n"
            "\tCode(1B)\t\t: %u\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tIdentifier(2B)\t\t: n:%d (0x%04x) h:%d (0x%04x)\n"
            "\tSequence number(2B)\t: n:%d (0x%04x) h:%d (0x%04x)\n",
            icmp_header->icmp_type, icmp_header->icmp_code,
            icmp_header->icmp_cksum, icmp_header->icmp_id, icmp_header->icmp_id,
            ntohs(icmp_header->icmp_id), ntohs(icmp_header->icmp_id),
            icmp_header->icmp_seq, icmp_header->icmp_seq,
            ntohs(icmp_header->icmp_seq), ntohs(icmp_header->icmp_seq));
    fprintf(fp, "------------------------------------------------------\n");
}

// Same decision as icmp_echo: the id/seq check and the saddr bloom filter. The
// payload is never consulted, so a damaged payload cannot change `success` or
// `repeat`.
static int icmp_echo_time_validate_packet(const struct ip *ip_hdr, uint32_t len,
                                          UNUSED int *is_repeat,
                                          UNUSED void *buf,
                                          UNUSED size_t *buf_len,
                                          UNUSED uint8_t ttl) {
    if (ip_hdr->ip_p != IPPROTO_ICMP) {
        return 0;
    }
    if (((uint32_t) 4 * ip_hdr->ip_hl + ICMP_SMALLEST_SIZE) > len) {
        return 0;
    }

    struct icmp *icmp_header =
        (struct icmp *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
    uint16_t icmp_idnum  = icmp_header->icmp_id;
    uint16_t icmp_seqnum = icmp_header->icmp_seq;

    uint8_t validation[VALIDATE_BYTES];
    if (icmp_header->icmp_type == ICMP_TIMXCEED ||
        icmp_header->icmp_type == ICMP_UNREACH ||
        icmp_header->icmp_type == ICMP_PARAMPROB) {

        if ((4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
             sizeof(struct ip)) > len) {
            return 0;
        }

        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header +
                           ICMP_TIMXCEED_UNREACH_HEADER_SIZE);
        if (((uint32_t) 4 * ip_hdr->ip_hl + ICMP_TIMXCEED_UNREACH_HEADER_SIZE +
             4 * ip_inner_header->ip_hl + 8 /*1st 8 bytes of original*/) >
            len) {
            return 0;
        }

        struct icmp *icmp_inner_header =
            (struct icmp *) ((char *) ip_inner_header + 4 * ip_hdr->ip_hl);
        icmp_idnum  = icmp_inner_header->icmp_id;
        icmp_seqnum = icmp_inner_header->icmp_seq;

        validate_gen((uint8_t *) &(ip_inner_header->ip_src.s_addr),
                     (uint8_t *) &(ip_inner_header->ip_dst.s_addr), 0,
                     validation);
    } else if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
        validate_gen((uint8_t *) &(ip_hdr->ip_dst.s_addr),
                     (uint8_t *) &(ip_hdr->ip_src.s_addr), 0, validation);
    }

    if (icmp_idnum != get_icmp_idnum(validation)) {
        return 0;
    }
    if (icmp_seqnum != get_icmp_seqnum(validation)) {
        return 0;
    }

    char ip_port_str[16]; // ipv46_bytes <= 16
    memcpy(ip_port_str, (char *) &(ip_hdr->ip_src.s_addr), xconf.ipv46_bytes);
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_port_str,
                                  xconf.ipv46_bytes) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_port_str,
                                xconf.ipv46_bytes);
        *is_repeat = 0;
    }

    return 1;
}

static void icmp_echo_time_process_packet(const u_char *packet, uint32_t len,
                                          fieldset_t           *fs,
                                          struct timespec ts) {
    struct ip   *ip_header = (struct ip *) &packet[sizeof(struct ether_header)];
    struct icmp *icmp_header =
        (struct icmp *) ((char *) ip_header + 4 * ip_header->ip_hl);
    uint32_t hdrlen = sizeof(struct ether_header) + 4 * ip_header->ip_hl +
                      4; // after checksum

    // Bytes of the packet that really exist, per capture and per IP length.
    uint32_t ip_end = sizeof(struct ether_header) + ntohs(ip_header->ip_len);
    uint32_t end    = len < ip_end ? len : ip_end;

    rtt_result_t rtt;
    if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
        fs_add_uint64(fs, "success", 1);
        fs_add_string(fs, "clas", (char *) "echoreply", 0);
        fs_add_string(fs, "desc", (char *) "no code", 0);

        uint32_t off = (uint32_t) ((u_char *) icmp_header - packet) + ICMP_MINLEN;
        rtt_analyze(&packet[off], end > off ? end - off : 0,
                    (uint8_t *) &ip_header->ip_src.s_addr, 4, 0, ts, &rtt);
    } else {
        struct ip *ip_inner_header =
            (struct ip *) ((char *) icmp_header +
                           ICMP_TIMXCEED_UNREACH_HEADER_SIZE);
        fs_modify_string(fs, "saddr",
                         make_ip_str(ip_inner_header->ip_dst.s_addr), 1);

        fs_add_bool(fs, "success", 0);
        fs_add_string(fs, "clas",
                      (char *) get_icmp_type_str(icmp_header->icmp_type), 0);
        fs_add_string(fs, "desc",
                      (char *) get_icmp_type_code_str(icmp_header->icmp_type,
                                                      icmp_header->icmp_code),
                      0);

        // RFC 792 only guarantees 8 bytes of the original datagram, so the
        // embedded payload is usually cut off; rtt_analyze reports that as
        // truncated.
        uint32_t inner_hl = 4 * ip_inner_header->ip_hl;
        uint32_t off      = (uint32_t) ((u_char *) ip_inner_header - packet) +
                       inner_hl + ICMP_MINLEN;
        if (ip_inner_header->ip_p == IPPROTO_ICMP && off <= end) {
            rtt_analyze(&packet[off], end - off,
                        (uint8_t *) &ip_inner_header->ip_dst.s_addr, 4, 1, ts,
                        &rtt);
        } else {
            rtt_analyze(NULL, 0, NULL, 4, 1, ts, &rtt);
        }
    }

    fs_add_uint64(fs, "type", icmp_header->icmp_type);
    fs_add_uint64(fs, "code", icmp_header->icmp_code);
    fs_add_uint64(fs, "icmp_id", ntohs(icmp_header->icmp_id));
    fs_add_uint64(fs, "seq", ntohs(icmp_header->icmp_seq));
    fs_add_string(fs, "outersaddr", make_ip_str(ip_header->ip_src.s_addr), 1);

    int datalen = len - hdrlen;

    if (datalen > 0) {
        const uint8_t *data = (uint8_t *) &packet[hdrlen];
        fs_add_binary(fs, "data", (size_t) datalen, (void *) data, 0);
    } else {
        fs_add_null(fs, "data");
    }

    rtt_fs_add(fs, &rtt, 0);
}

static void icmp_echo_time_metadata(void *json_obj) {
    rtt_metadata(json_obj, "ipv4", 4);
}

static fielddef_t fields[] = {
    {.name = "success",
     .type = "bool",
     .desc = "did probe module classify response as success"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification (type str):\n"
             "\t\t\te.g., `echoreply', `other'\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "desc",
     .type = "string",
     .desc = "ICMP message detail(code str):\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "type", .type = "int", .desc = "ICMP message type"},
    {.name = "code", .type = "int", .desc = "ICMP message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "ICMP id number"},
    {.name = "seq", .type = "int", .desc = "ICMP sequence number"},
    {.name = "outersaddr",
     .type = "string",
     .desc = "outer src address of icmp reply packet"},
    {.name = "data", .type = "binary", .desc = "ICMP payload"},
    RTT_FIELDDEFS};

probe_module_t module_icmp_echo_time = {
    .ipv46_flag    = 4,
    .name          = "icmp_echo_time",
    .packet_length = 14 + 20 + 8 + RTT4_PAYLOAD_LEN,
    .pcap_filter   = "icmp and icmp[0]!=8",
    .pcap_snaplen  = 14 + 2 * (20 + 8) + RTT4_PAYLOAD_LEN,
    .port_args     = 0,
    .global_init   = &icmp_echo_time_global_init,
    .thread_init   = &icmp_echo_time_thread_init,
    .make_packet   = &icmp_echo_time_make_packet,
    .print_packet  = &icmp_echo_time_print_packet,
    .process_packet  = &icmp_echo_time_process_packet,
    .validate_packet = &icmp_echo_time_validate_packet,
    .output_type     = OUTPUT_TYPE_STATIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext = "Probe module that sends ICMP echo requests whose payload\n"
                "carries the send time and probe number, and reports the RTT\n"
                "of each response (receive time from the pcap header).\n"
                "Output fields: those of icmp_echo plus probe_idx, sent_ts_us,\n"
                "recv_ts_us, sent_ts_ns, recv_ts_ns, rtt_us, rtt_valid,\n"
                "rtt_status, probe_daddr. See docs/icmp_echo_time.md.",
    .pcap_tstamp_nano = 1,
    .metadata         = &icmp_echo_time_metadata,
};
