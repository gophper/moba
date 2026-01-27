#ifndef TCP_TRACKER_H
#define TCP_TRACKER_H

// Don't include standard headers when using vmlinux.h in BPF programs
// Types are already defined in vmlinux.h

// TCP connection states (from linux/tcp.h)
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

struct ipv4_key_t {
    __u32 saddr;
    __u32 daddr;
    __u16 dport;
    __u16 sport;
    __u32 pid;
    __u32 ns;
    __u32 pid_ns;
    char comm[16];
    char hook[32];
};

struct proc_bytes {
    __u64 in_bytes;
    __u64 out_bytes;
};

struct conn_stats {
    __u64 attempts;
    __u64 failures;
    __u64 latency_sum_ns;
    __u64 latency_count;
};

// Helper function declarations
static __always_inline void format_ip_port(__u32 ip, __u16 port, char *buf);
static __always_inline void copy_ipv4_key(struct ipv4_key_t *src, struct ipv4_key_t *dst);
static __always_inline int connect_is_ok(int ret);

// Implementation of helper functions
static __always_inline void format_ip_port(__u32 ip, __u16 port, char *buf) {
    // Simple IP formatting - just format as hex for now
    __builtin_memset(buf, 0, 22);
    // Format as hex to avoid complex formatting
    __u8 a = (ip >> 24) & 0xFF;
    __u8 b = (ip >> 16) & 0xFF;
    __u8 c = (ip >> 8) & 0xFF;
    __u8 d = ip & 0xFF;
    
    // Simple string formatting
    buf[0] = '0' + (a / 100);
    buf[1] = '0' + ((a / 10) % 10);
    buf[2] = '0' + (a % 10);
    buf[3] = '.';
    buf[4] = '0' + (b / 100);
    buf[5] = '0' + ((b / 10) % 10);
    buf[6] = '0' + (b % 10);
    buf[7] = '.';
    buf[8] = '0' + (c / 100);
    buf[9] = '0' + ((c / 10) % 10);
    buf[10] = '0' + (c % 10);
    buf[11] = '.';
    buf[12] = '0' + (d / 100);
    buf[13] = '0' + ((d / 10) % 10);
    buf[14] = '0' + (d % 10);
    buf[15] = ':';
    
    if (port > 0) {
        __u16 p = port;
        buf[16] = '0' + (p / 10000);
        buf[17] = '0' + ((p / 1000) % 10);
        buf[18] = '0' + ((p / 100) % 10);
        buf[19] = '0' + ((p / 10) % 10);
        buf[20] = '0' + (p % 10);
    }
}

static __always_inline void copy_ipv4_key(struct ipv4_key_t *src, struct ipv4_key_t *dst) {
    if (!src || !dst) return;
    dst->saddr = src->saddr;
    dst->daddr = src->daddr;
    dst->dport = src->dport;
    dst->sport = src->sport;
    dst->pid = src->pid;
    dst->ns = src->ns;
    dst->pid_ns = src->pid_ns;
    __builtin_memcpy(dst->comm, src->comm, sizeof(dst->comm));
    __builtin_memcpy(dst->hook, src->hook, sizeof(dst->hook));
}

static __always_inline int connect_is_ok(int ret) {
    // 0 means success
    // -EINPROGRESS (-115) is also considered OK for non-blocking sockets
    return (ret == 0 || ret == -115) ? 0 : -1;
}

// Hook name setters
static __always_inline void set_hook_tcp_sendmsg(char *h) {
    __builtin_memcpy(h, "tcp_sendmsg", 12);
}

static __always_inline void set_hook_udp_sendmsg(char *h) {
    __builtin_memcpy(h, "udp_sendmsg", 12);
}

static __always_inline void set_hook_tcp_recvmsg(char *h) {
    __builtin_memcpy(h, "tcp_recvmsg", 12);
}

static __always_inline void set_hook_udp_recvmsg(char *h) {
    __builtin_memcpy(h, "udp_recvmsg", 12);
}

static __always_inline void set_hook_tcp_v4_rcv(char *h) {
    __builtin_memcpy(h, "tcp_v4_rcv", 11);
}

static __always_inline void set_hook_connect(char *h) {
    __builtin_memcpy(h, "connect", 8);
}

static __always_inline void set_hook_inet_sock_set_state(char *h) {
    __builtin_memcpy(h, "inet_sock_set_state", 20);
}

#endif // TCP_TRACKER_H
