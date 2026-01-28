#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_tracker.h"

#define KERNEL_NEW 1

/* Forward declarations for helper routines that set hook name into key.hook.
 * They are defined in tcp_tracker.h */

// 定义连接状态
enum connect_status {
    CONNECT_PENDING = 0,      // 进行中(EINPROGRESS)
    CONNECT_SUCCEEDED = 1,    // 成功
    CONNECT_FAILED = 2,       // 失败
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, struct ipv4_key_t);
    __type(value, struct proc_bytes);
} ipv4_recv_bytes SEC(".maps");

/* map to hold sampling rate (single-entry array: key=0 -> value=sample_rate) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} sample_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64); // pid_tgid
    __type(value, struct ipv4_key_t);
} tmp_addrs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64); // pid_tgid
    __type(value, __u64); // start timestamp ns
} conn_start_map SEC(".maps");

/* Map to track connection start time by socket address */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, void*); // socket address
    __type(value, __u64); // start timestamp ns
} sock_start_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct conn_stats);
} conn_global_stats SEC(".maps");

/* per-pair connection stats keyed by ipv4_key_t */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ipv4_key_t);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);         // pid_tgid
    __type(value, struct ipv4_key_t);
} pending_connects SEC(".maps");

static __always_inline void add_bytes_to_map(struct ipv4_key_t *k, unsigned int len, bool is_out) {
    /* Read sampling rate from sample_rate_map (key=0). If missing or zero, use default 100. */
    __u32 key0 = 0;
    __u32 *pr = bpf_map_lookup_elem(&sample_rate_map, &key0);
    __u32 sample_rate = pr && *pr > 0 ? *pr : 100U;

    /* decide sampling */
    __u32 r = bpf_get_prandom_u32();
    if ((r % sample_rate) != 0) {
        /* not sampled: drop */
        //return;
    }

    struct proc_bytes *valp;
    struct proc_bytes newv = {0, 0};

    valp = bpf_map_lookup_elem(&ipv4_recv_bytes, k);
    if (valp) {
        newv = *valp;
    }
    if (is_out) {
        newv.out_bytes += len;
    } else {
        newv.in_bytes += len;
    }

    bpf_map_update_elem(&ipv4_recv_bytes, k, &newv, BPF_ANY);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg_entry) {
    void *skp = (void *) PT_REGS_PARM1(ctx);
    size_t size = (size_t) PT_REGS_PARM3(ctx);
    if (!skp) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // read sk->__sk_common.skc_daddr and sk->__sk_common.skc_rcv_saddr (network byte order)
    __u32 daddr = 0, saddr = 0;
    bpf_core_read(&daddr, sizeof(daddr), &((struct sock *)skp)->__sk_common.skc_daddr);
    bpf_core_read(&saddr, sizeof(saddr), &((struct sock *)skp)->__sk_common.skc_rcv_saddr);

    // build key and ensure it exists so IPs are recorded even if bytes not yet seen
    struct ipv4_key_t key = {};
    key.pid = (u32) (pid_tgid >> 32);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    key.ns = (u32) netns;
    // pid namespace id
    u64 pidns = 0;
    pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.pid_ns = (u32) pidns;
    key.saddr = bpf_ntohl(saddr);
    key.daddr = bpf_ntohl(daddr);
    // read remote port skc_dport (network order) and sport skc_num if available
    __u16 dport_be = 0;
    __u16 sport = 0;
    bpf_core_read(&dport_be, sizeof(dport_be), &((struct sock *)skp)->__sk_common.skc_dport);
    bpf_core_read(&sport, sizeof(sport), &((struct sock *)skp)->__sk_common.skc_num);
    key.dport = bpf_ntohs(dport_be);
    key.sport = sport; // already host-order small value
    /* store hook name */
    set_hook_tcp_sendmsg(key.hook);

    if (size > 0) {
        add_bytes_to_map(&key, (unsigned int) size, true);
    }
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_entry) {
    void *skp = (void *) PT_REGS_PARM1(ctx);
    size_t size = (size_t) PT_REGS_PARM3(ctx);
    if (!skp) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 daddr = 0, saddr = 0;
    bpf_core_read(&daddr, sizeof(daddr), &((struct sock *)skp)->__sk_common.skc_daddr);
    bpf_core_read(&saddr, sizeof(saddr), &((struct sock *)skp)->__sk_common.skc_rcv_saddr);

    struct ipv4_key_t key = {};
    key.pid = (u32) (pid_tgid >> 32);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    key.ns = (u32) netns;
    // pid namespace id
    u64 pidns = 0;
    pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.pid_ns = (u32) pidns;
    key.saddr =  bpf_ntohl(saddr);
    key.daddr = bpf_ntohl(daddr);
    // for UDP we can read remote port and local port similarly
    __u16 udp_dport_be = 0;
    __u16 udp_sport = 0;
    bpf_core_read(&udp_dport_be, sizeof(udp_dport_be), &((struct sock *)skp)->__sk_common.skc_dport);
    bpf_core_read(&udp_sport, sizeof(udp_sport), &((struct sock *)skp)->__sk_common.skc_num);
    key.dport = bpf_ntohs(udp_dport_be);
    key.sport = udp_sport;
    set_hook_udp_sendmsg(key.hook);

    if (size > 0) {
        add_bytes_to_map(&key, (unsigned int) size, true);
    }

    return 0;
}

// kprobe entry for tcp_recvmsg: capture sk addresses for receive path
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(tcp_recvmsg_entry) {
    void *skp = (void *) PT_REGS_PARM1(ctx);
    size_t size = (size_t) PT_REGS_PARM3(ctx);
    if (!skp) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 daddr = 0, saddr = 0;
    bpf_core_read(&daddr, sizeof(daddr), &((struct sock *)skp)->__sk_common.skc_daddr);
    bpf_core_read(&saddr, sizeof(saddr), &((struct sock *)skp)->__sk_common.skc_rcv_saddr);
    struct ipv4_key_t key = {};
    key.pid = (u32) (pid_tgid >> 32);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    key.ns = (u32) netns;
    // pid namespace id
    u64 pidns = 0;
    pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.pid_ns = (u32) pidns;
    key.saddr = bpf_ntohl(saddr);
    key.daddr = bpf_ntohl(daddr);
    // read remote/local ports
    __u16 rport_be = 0;
    __u16 lport = 0;
    bpf_core_read(&rport_be, sizeof(rport_be), &((struct sock *)skp)->__sk_common.skc_dport);
    bpf_core_read(&lport, sizeof(lport), &((struct sock *)skp)->__sk_common.skc_num);
    key.dport = bpf_ntohs(rport_be);
    key.sport = lport;
    set_hook_tcp_recvmsg(key.hook);

    if (size > 0) {
        add_bytes_to_map(&key, (unsigned int) size, false);
    }
    return 0;
}

// kprobe entry for udp_recvmsg: capture sk addresses for receive path
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg_entry) {
    void *skp = (void *) PT_REGS_PARM1(ctx);
    size_t size = (size_t) PT_REGS_PARM3(ctx);
    if (!skp) return 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 daddr = 0, saddr = 0;
    bpf_core_read(&daddr, sizeof(daddr), &((struct sock *)skp)->__sk_common.skc_daddr);
    bpf_core_read(&saddr, sizeof(saddr), &((struct sock *)skp)->__sk_common.skc_rcv_saddr);
    struct ipv4_key_t key = {};
    key.pid = (u32) (pid_tgid >> 32);
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    key.ns = (u32) netns;
    // pid namespace id
    u64 pidns = 0;
    pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.pid_ns = (u32) pidns;
    key.saddr = bpf_ntohl(saddr);
    key.daddr = bpf_ntohl(daddr);
    __u16 udp_rport_be = 0;
    __u16 udp_lport = 0;
    bpf_core_read(&udp_rport_be, sizeof(udp_rport_be), &((struct sock *)skp)->__sk_common.skc_dport);
    bpf_core_read(&udp_lport, sizeof(udp_lport), &((struct sock *)skp)->__sk_common.skc_num);
    key.dport = bpf_ntohs(udp_rport_be);
    key.sport = udp_lport;
    set_hook_udp_recvmsg(key.hook);

    if (size > 0) {
        add_bytes_to_map(&key, (unsigned int) size, false);
    }
    return 0;
}

// Helper function to check if PID is a kernel process
static __always_inline bool is_kernel_pid(__u32 pid) {
    // PID 0 is the idle/swapper process (kernel)
    // PIDs 1-2 are typically init and kthreadd
    // For eBPF purposes, we filter out PID 0 as it's definitely kernel
    // We could also filter PID <= 2, but let's be conservative
    if (pid == 0) {
        return true;
    }
    
    // Additional check: kernel threads typically have mm == NULL
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    void *mm = BPF_CORE_READ(task, mm);
    if (mm == NULL) {
        return true; // kernel thread
    }
    
    return false;
}

static __always_inline u32 get_sock_netns_id(void *skaddr) {
    struct sock *sk = (struct sock *)skaddr;
    u32 netns_id = 0;

    // 方法1：通过sk->__sk_common.skc_net->ns.inum（适用于较新内核）
    // 方法2：通过sk->sk_net->ns.inum（不同内核版本可能不同）

    // 使用BPF CO-RE安全读取
#ifdef KERNEL_NEW
    // 新内核：sk->__sk_common.skc_net->ns.inum
    struct net *skc_net = NULL;
    bpf_core_read(&skc_net, sizeof(skc_net), &sk->__sk_common.skc_net);
    if (skc_net) {
        bpf_core_read(&netns_id, sizeof(netns_id), &skc_net->ns.inum);
    }
#else
    // 旧内核或兼容方式：尝试多种读取方式
    // 先尝试sk_net
    struct net *sk_net = NULL;
    bpf_core_read(&sk_net, sizeof(sk_net), &sk->sk_net);
    if (sk_net) {
        bpf_core_read(&netns_id, sizeof(netns_id), &sk_net->ns.inum);
    } else {
        // 再尝试__sk_common.skc_net
        struct net *skc_net = NULL;
        bpf_core_read(&skc_net, sizeof(skc_net), &sk->__sk_common.skc_net);
        if (skc_net) {
            bpf_core_read(&netns_id, sizeof(netns_id), &skc_net->ns.inum);
        }
    }
#endif

    return netns_id;
}

// Helper to assemble IPv4 address from byte array in network order
static __always_inline __u32 make_ipv4(__u8 *bytes) {
    return ((__u32)bytes[0] << 24) | ((__u32)bytes[1] << 16) | 
           ((__u32)bytes[2] << 8) | ((__u32)bytes[3]);
}

// Note: trace_event_raw_inet_sock_set_state is already defined in vmlinux.h
// We use it directly from there

/*
 * Main tracepoint: sock:inet_sock_set_state
 * This hook is called whenever a TCP socket changes state.
 * We use it to track connection attempts, successes, and failures for both
 * client and server sides.
 *
 * Client-side important transitions:
 * - CLOSE -> SYN_SENT: Connection attempt started
 * - SYN_SENT -> ESTABLISHED: Connection succeeded
 * - SYN_SENT -> CLOSE: Connection failed
 *
 * Server-side important transitions:
 * - LISTEN -> SYN_RECV: Incoming connection attempt
 * - SYN_RECV -> ESTABLISHED: Connection accepted
 * - SYN_RECV -> CLOSE: Connection attempt rejected/failed
 */
SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint__sock__inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    /* Use fields provided by the tracepoint struct */
    int oldstate = (int)ctx->oldstate;
    int newstate = (int)ctx->newstate;
    
    /* only IPv4 supported here; family: AF_INET == 2 */
    if ((int)ctx->family != 2) {
        return 0;
    }
    
    /* only TCP protocol; IPPROTO_TCP == 6 */
    if ((int)ctx->protocol != 6) {
        return 0;
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    
    // Filter out kernel processes
    if (is_kernel_pid(pid)) {
        return 0;
    }

    u32 netns_id = get_sock_netns_id((void *)ctx->skaddr);
    
    /* assemble 4-byte IPv4 addresses from the byte arrays in the tracepoint context
     * ctx->saddr and ctx->daddr are arrays of 4 bytes in network (big-endian) order.
     */
    __u32 saddr_be = make_ipv4(ctx->saddr);
    __u32 daddr_be = make_ipv4(ctx->daddr);
    
    /* Ports are already in host byte order in the tracepoint context */
    __u16 sport = ctx->sport;
    __u16 dport = ctx->dport;
    
    /* Fallback: If sport is 0, read directly from socket structure.
     * This can happen during early connection phases like SYN_SENT where
     * the tracepoint context may not have the source port populated yet.
     */
    if (sport == 0) {
        struct sock *sk = (struct sock *)ctx->skaddr;
        bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    }
    
    /* Build key structure */
    struct ipv4_key_t key = {};
    key.pid = pid;
    bpf_get_current_comm(key.comm, sizeof(key.comm));
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u64 pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key.pid_ns = (u32)pidns;
    key.ns = netns_id;
    
    key.saddr = saddr_be;
    key.daddr = daddr_be;
    key.sport = sport;
    key.dport = dport;
    
    set_hook_inet_sock_set_state(key.hook);
    
    /* Track connection statistics based on state transitions */
    
    // Client-side: Connection attempt started
    if (oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT) {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&sock_start_map, &ctx->skaddr, &ts, BPF_ANY);
        
        // Initialize connection stats for this pair if not exists
        struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!st) {
            struct conn_stats zero = {};
            bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
            st = bpf_map_lookup_elem(&conn_stats_map, &key);
        }
        if (st) {
            struct conn_stats new = *st;
            new.attempts += 1;
            bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
        }
    }
    
    // Client-side: Connection succeeded
    if (oldstate == TCP_SYN_SENT && newstate == TCP_ESTABLISHED) {
        u64 *tsp = bpf_map_lookup_elem(&sock_start_map, &ctx->skaddr);
        if (tsp) {
            u64 delta = bpf_ktime_get_ns() - *tsp;
            bpf_map_delete_elem(&sock_start_map, &ctx->skaddr);
            
            struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
            if (st) {
                struct conn_stats new = *st;
                new.latency_sum_ns += delta;
                new.latency_count += 1;
                bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
            }
        }
    }
    
    // Client-side: Connection failed
    if (oldstate == TCP_SYN_SENT && newstate == TCP_CLOSE) {
        u64 *tsp = bpf_map_lookup_elem(&sock_start_map, &ctx->skaddr);
        if (tsp) {
            bpf_map_delete_elem(&sock_start_map, &ctx->skaddr);
        }
        
        struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (st) {
            struct conn_stats new = *st;
            new.failures += 1;
            bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
        }
    }
    
    // Server-side: Incoming connection attempt
    if (oldstate == TCP_LISTEN && newstate == TCP_SYN_RECV) {
        u64 ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&sock_start_map, &ctx->skaddr, &ts, BPF_ANY);
        
        // Initialize connection stats for this pair if not exists
        struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (!st) {
            struct conn_stats zero = {};
            bpf_map_update_elem(&conn_stats_map, &key, &zero, BPF_NOEXIST);
            st = bpf_map_lookup_elem(&conn_stats_map, &key);
        }
        if (st) {
            struct conn_stats new = *st;
            new.attempts += 1;
            bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
        }
    }
    
    // Server-side: Connection accepted
    if (oldstate == TCP_SYN_RECV && newstate == TCP_ESTABLISHED) {
        u64 *tsp = bpf_map_lookup_elem(&sock_start_map, &ctx->skaddr);
        if (tsp) {
            u64 delta = bpf_ktime_get_ns() - *tsp;
            bpf_map_delete_elem(&sock_start_map, &ctx->skaddr);
            
            struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
            if (st) {
                struct conn_stats new = *st;
                new.latency_sum_ns += delta;
                new.latency_count += 1;
                bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
            }
        }
    }
    
    // Server-side: Connection rejected/failed
    if (oldstate == TCP_SYN_RECV && newstate == TCP_CLOSE) {
        u64 *tsp = bpf_map_lookup_elem(&sock_start_map, &ctx->skaddr);
        if (tsp) {
            bpf_map_delete_elem(&sock_start_map, &ctx->skaddr);
        }
        
        struct conn_stats *st = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (st) {
            struct conn_stats new = *st;
            new.failures += 1;
            bpf_map_update_elem(&conn_stats_map, &key, &new, BPF_ANY);
        }
    }
    
    // Additional transitions to track connection closure and errors
    // FIN_WAIT1/FIN_WAIT2 -> CLOSE: Normal connection closure
    // Any state -> CLOSE (with previous != CLOSE): Could indicate error/reset
    
    // Clean up start time if transitioning to CLOSE from other states
    if (newstate == TCP_CLOSE && oldstate != TCP_CLOSE) {
        bpf_map_delete_elem(&sock_start_map, &ctx->skaddr);
    }
    
    return 0;
}

char _license[] SEC("license") = "GPL";
