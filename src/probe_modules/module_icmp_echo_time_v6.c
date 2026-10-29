/*
 * XMap icmp_echo_time (IPv6): ICMPv6 echo scan that records per-probe RTT.
 *
 * Superset of module_icmp6_echo.c: same validation, success and repeat logic,
 * same leading output fields; the echo payload is a fixed-length record
 * (module_icmp_echo_time.h) instead of --probe-args bytes.
 */

#include "module_icmp6.h"
#include "module_icmp_echo_time.h"

#define RTT6_PAYLOAD_LEN RTT_PAYLOAD_LEN(16)

probe_module_t module_icmp6_echo_time;

static int icmp6_echo_time_global_init(struct state_conf *conf) {
    if (conf->probe_args && strlen(conf->probe_args) > 0) {
        log_error("icmp_echo_time",
                  "--probe-args is not supported: the payload is a fixed "
                  "timestamp record");
        return EXIT_FAILURE;
    }
    return rtt_global_init();
}

static int icmp6_echo_time_thread_init(void *buf, macaddr_t *src, macaddr_t *gw,
                                       UNUSED void **arg_ptr) {
    memset(buf, 0, MAX_PACKET_SIZE);

    struct ether_header *eth_header = (struct ether_header *) buf;
    make_eth6_header(eth_header, src, gw);

    struct ip6_hdr *ip6_header  = (struct ip6_hdr *) (&eth_header[1]);
    uint16_t        payload_len = sizeof(struct icmp6_hdr) + RTT6_PAYLOAD_LEN;
    make_ip6_header(ip6_header, IPPROTO_ICMPV6, payload_len);

    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    make_icmp6_header(icmp6_header);

    return EXIT_SUCCESS;
}

static int icmp6_echo_time_make_packet(void *buf, UNUSED size_t *buf_len,
                                       ipaddr_n_t *src_ip, ipaddr_n_t *dst_ip,
                                       UNUSED port_h_t dst_port, uint8_t ttl,
                                       int probe_num, UNUSED index_h_t index,
                                       UNUSED void *arg) {
    struct ether_header *eth_header   = (struct ether_header *) buf;
    struct ip6_hdr      *ip6_header   = (struct ip6_hdr *) (&eth_header[1]);
    struct icmp6_hdr    *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);

    uint8_t validation[VALIDATE_BYTES];
    validate_gen(src_ip, dst_ip, 0, validation);

    uint8_t *ip6_src = (uint8_t *) &(ip6_header->ip6_src);
    uint8_t *ip6_dst = (uint8_t *) &(ip6_header->ip6_dst);
    for (int i = 0; i < 16; i++) {
        ip6_src[i] = src_ip[i];
        ip6_dst[i] = dst_ip[i];
    }
    ip6_header->ip6_hlim = ttl;

    icmp6_header->icmp6_id  = get_icmp_idnum(validation);
    icmp6_header->icmp6_seq = get_icmp_seqnum(validation);

    // The timestamp goes in last so that it is as close to sendto() as the
    // module interface allows; the checksum only covers the final bytes.
    rtt_payload_write((uint8_t *) icmp6_header + ICMP6_MINLEN, dst_ip, 16,
                      (uint8_t) probe_num);

    icmp6_header->icmp6_cksum = 0;
    icmp6_header->icmp6_cksum =
        (uint16_t) icmp6_checksum((struct in6_addr *) &(ip6_header->ip6_src),
                                  (struct in6_addr *) &(ip6_header->ip6_dst),
                                  icmp6_header, RTT6_PAYLOAD_LEN);

    return EXIT_SUCCESS;
}

static void icmp6_echo_time_print_packet(FILE *fp, void *packet) {
    struct ether_header *eth_header   = (struct ether_header *) packet;
    struct ip6_hdr      *ip6_header   = (struct ip6_hdr *) &eth_header[1];
    struct icmp6_hdr    *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);

    fprintf_eth_header(fp, eth_header);
    fprintf_ip6_header(fp, ip6_header);
    fprintf(fp,
            "ICMPv6\n"
            "\tType(1B)\t\t: %u\n"
            "\tCode(1B)\t\t: %u\n"
            "\tChecksum(2B)\t\t: 0x%04x\n"
            "\tIdentifier(2B)\t\t: n:%d (0x%04x) h:%d (0x%04x)\n"
            "\tSequence number(2B)\t: n:%d (0x%04x) h:%d (0x%04x)\n",
            icmp6_header->icmp6_type, icmp6_header->icmp6_code,
            icmp6_header->icmp6_cksum, icmp6_header->icmp6_id,
            icmp6_header->icmp6_id, ntohs(icmp6_header->icmp6_id),
            ntohs(icmp6_header->icmp6_id), icmp6_header->icmp6_seq,
            icmp6_header->icmp6_seq, ntohs(icmp6_header->icmp6_seq),
            ntohs(icmp6_header->icmp6_seq));
    fprintf(fp, "------------------------------------------------------\n");
}

// Same decision as icmp_echo: the id/seq check and the saddr bloom filter. The
// payload is never consulted (so the length checks cover headers only), and a
// damaged payload cannot change `success` or `repeat`.
static int icmp6_echo_time_validate_packet(const struct ip *ip_hdr,
                                           uint32_t len, UNUSED int *is_repeat,
                                           UNUSED void *buf,
                                           UNUSED size_t *buf_len,
                                           UNUSED uint8_t ttl) {
    struct ip6_hdr *ip6_header = (struct ip6_hdr *) ip_hdr;

    if (ip6_header->ip6_nxt != IPPROTO_ICMPV6) {
        return 0;
    }

    if ((sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) > len) {
        return 0;
    }

    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    uint16_t          icmp6_idnum  = icmp6_header->icmp6_id;
    uint16_t          icmp6_seqnum = icmp6_header->icmp6_seq;

    uint8_t validation[VALIDATE_BYTES];
    if (icmp6_header->icmp6_type == ICMP6_TIME_EXCEEDED ||
        icmp6_header->icmp6_type == ICMP6_DST_UNREACH ||
        icmp6_header->icmp6_type == ICMP6_PACKET_TOO_BIG ||
        icmp6_header->icmp6_type == ICMP6_PARAM_PROB) {

        if (2 * sizeof(struct ip6_hdr) + 2 * sizeof(struct icmp6_hdr) > len) {
            return 0;
        }

        struct ip6_hdr *ip6_inner_header = (struct ip6_hdr *) &icmp6_header[1];
        struct icmp6_hdr *icmp6_inner_header =
            (struct icmp6_hdr *) &ip6_inner_header[1];

        icmp6_idnum  = icmp6_inner_header->icmp6_id;
        icmp6_seqnum = icmp6_inner_header->icmp6_seq;

        validate_gen((const uint8_t *) &(ip6_inner_header->ip6_src),
                     (const uint8_t *) &(ip6_inner_header->ip6_dst), 0,
                     validation);
    } else if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {
        validate_gen((const uint8_t *) &(ip6_header->ip6_dst),
                     (const uint8_t *) &(ip6_header->ip6_src), 0, validation);
    }

    if (icmp6_idnum != get_icmp_idnum(validation)) {
        return 0;
    }
    if (icmp6_seqnum != get_icmp_seqnum(validation)) {
        return 0;
    }

    char ip_port_str[16]; // ipv46_bytes <= 16
    memcpy(ip_port_str, (char *) &(ip6_header->ip6_src), xconf.ipv46_bytes);
    if (bloom_filter_check_string(&xrecv.bf, (const char *) ip_port_str,
                                  xconf.ipv46_bytes) == BLOOM_FAILURE) {
        bloom_filter_add_string(&xrecv.bf, (const char *) ip_port_str,
                                xconf.ipv46_bytes);
        *is_repeat = 0;
    }

    return 1;
}

static void icmp6_echo_time_process_packet(const u_char *packet, uint32_t len,
                                           fieldset_t     *fs,
                                           struct timespec ts) {
    struct ip6_hdr *ip6_header =
        (struct ip6_hdr *) &packet[sizeof(struct ether_header)];
    struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *) (&ip6_header[1]);
    uint32_t hdrlen = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
                      4; // after checksum

    // Bytes of the packet that really exist, per capture and per IPv6 length.
    uint32_t ip_end = sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
                      ntohs(ip6_header->ip6_plen);
    uint32_t end = len < ip_end ? len : ip_end;

    rtt_result_t rtt;
    if (icmp6_header->icmp6_type == ICMP6_ECHO_REPLY) {
        fs_add_uint64(fs, "success", 1);
        fs_add_string(fs, "clas", (char *) "echoreply", 0);
        fs_add_string(fs, "desc", (char *) "no code", 0);

        uint32_t off = hdrlen - 4 + ICMP6_MINLEN; // after the 8-byte ICMPv6 header
        rtt_analyze(&packet[off], end > off ? end - off : 0,
                    (uint8_t *) &ip6_header->ip6_src, 16, 0, ts, &rtt);
    } else {
        struct ip6_hdr *ip6_inner_header = (struct ip6_hdr *) &icmp6_header[1];
        fs_modify_string(
            fs, "saddr",
            make_ipv6_str((struct in6_addr *) &(ip6_inner_header->ip6_dst)), 1);

        fs_add_uint64(fs, "success", 0);
        fs_add_string(fs, "clas",
                      (char *) get_icmp6_type_str(icmp6_header->icmp6_type), 0);
        fs_add_string(fs, "desc",
                      (char *) get_icmp6_type_code_str(
                          icmp6_header->icmp6_type, icmp6_header->icmp6_code),
                      0);

        // ICMPv6 errors quote as much of the original as fits in 1280 bytes,
        // so the embedded payload is normally complete.
        uint32_t off = (uint32_t) ((u_char *) &ip6_inner_header[1] - packet) +
                       ICMP6_MINLEN;
        if (ip6_inner_header->ip6_nxt == IPPROTO_ICMPV6 && off <= end) {
            rtt_analyze(&packet[off], end - off,
                        (uint8_t *) &ip6_inner_header->ip6_dst, 16, 1, ts,
                        &rtt);
        } else {
            rtt_analyze(NULL, 0, NULL, 16, 1, ts, &rtt);
        }
    }

    fs_add_uint64(fs, "type", icmp6_header->icmp6_type);
    fs_add_uint64(fs, "code", icmp6_header->icmp6_code);
    fs_add_uint64(fs, "icmp_id", ntohs(icmp6_header->icmp6_id));
    fs_add_uint64(fs, "seq", ntohs(icmp6_header->icmp6_seq));
    fs_add_string(fs, "outersaddr",
                  make_ipv6_str((struct in6_addr *) &(ip6_header->ip6_src)), 1);

    int datalen = len - hdrlen;

    if (datalen > 0) {
        const uint8_t *data = (uint8_t *) &packet[hdrlen];
        fs_add_binary(fs, "data", (size_t) datalen, (void *) data, 0);
    } else {
        fs_add_null(fs, "data");
    }

    rtt_fs_add(fs, &rtt, 1);
}

static void icmp6_echo_time_metadata(void *json_obj) {
    rtt_metadata(json_obj, "ipv6", 16);
}

static fielddef_t fields[] = {
    {.name = "success",
     .type = "int",
     .desc = "did probe module classify response as success"},
    {.name = "clas",
     .type = "string",
     .desc = "packet classification(type str):\n"
             "\t\t\t`e.g., echoreply', `other'\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "desc",
     .type = "string",
     .desc = "ICMPv6 message detail(code str):\n"
             "\t\t\tuse `--probe-args=icmp-type-code-str' to list"},
    {.name = "type", .type = "int", .desc = "ICMPv6 message type"},
    {.name = "code", .type = "int", .desc = "ICMPv6 message sub type code"},
    {.name = "icmp_id", .type = "int", .desc = "ICMPv6 id number"},
    {.name = "seq", .type = "int", .desc = "ICMPv6 sequence number"},
    {.name = "outersaddr",
     .type = "string",
     .desc = "outer src address of ICMPv6 reply packet"},
    {.name = "data", .type = "binary", .desc = "ICMPv6 payload"},
    RTT_FIELDDEFS};

probe_module_t module_icmp6_echo_time = {
    .ipv46_flag    = 6,
    .name          = "icmp_echo_time",
    .packet_length = 14 + 40 + 8 + RTT6_PAYLOAD_LEN,
    .pcap_filter   = "icmp6 && (ip6[40] == 129 || ip6[40] == 3 || ip6[40] == 1 "
                     "|| ip6[40] == 2 || ip6[40] == 4)",
    .pcap_snaplen  = 14 + 2 * (40 + 8) + RTT6_PAYLOAD_LEN,
    .port_args     = 0,
    .global_init   = &icmp6_echo_time_global_init,
    .thread_init   = &icmp6_echo_time_thread_init,
    .make_packet   = &icmp6_echo_time_make_packet,
    .print_packet  = &icmp6_echo_time_print_packet,
    .process_packet  = &icmp6_echo_time_process_packet,
    .validate_packet = &icmp6_echo_time_validate_packet,
    .output_type     = OUTPUT_TYPE_STATIC,
    .fields          = fields,
    .numfields       = sizeof(fields) / sizeof(fields[0]),
    .helptext = "Probe module that sends ICMPv6 echo requests whose payload\n"
                "carries the send time and probe number, and reports the RTT\n"
                "of each response (receive time from the pcap header).\n"
                "Output fields: those of icmp_echo plus probe_idx, sent_ts_us,\n"
                "recv_ts_us, sent_ts_ns, recv_ts_ns, rtt_us, rtt_valid,\n"
                "rtt_status, probe_daddr. See docs/icmp_echo_time.md.",
    .pcap_tstamp_nano = 1,
    .metadata         = &icmp6_echo_time_metadata,
};
