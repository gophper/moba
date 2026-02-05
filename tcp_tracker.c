#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "tcp_tracker.h"

#define KERNEL_NEW 1

/* Forward declarations for helper routines that set hook name into key.hook.
 * They are defined later in the file but must be declared before use to avoid
 * implicit function declarations (which produce errors under -std=c99). */
static __always_inline void set_hook_tcp_sendmsg(char *h);
static __always_inline void set_hook_udp_sendmsg(char *h);
static __always_inline void set_hook_tcp_recvmsg(char *h);
static __always_inline void set_hook_udp_recvmsg(char *h);
static __always_inline void set_hook_tcp_v4_rcv(char *h);
static __always_inline void set_hook_connect(char *h);

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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct conn_stats);
} conn_global_stats SEC(".maps");


/* per-tuple connection stats keyed by conn4_tuple (used by inet_sock_set_state) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn4_tuple);
    __type(value, struct conn_stats);
} conn4_stats_map SEC(".maps");




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
    //key.sport = sport; // already host-order small value
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
    //key.sport = udp_sport;
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
   // key.sport = lport;
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
    //key.sport = udp_lport;
    set_hook_udp_recvmsg(key.hook);

    if (size > 0) {
        add_bytes_to_map(&key, (unsigned int) size, false);
    }
    return 0;
}

// 辅助函数：通过fd获取socket信息
static __always_inline struct sock *get_sock_from_fd(struct task_struct *task, int fd) {
    // 1. 获取files_struct
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files) return NULL;

    // 2. 获取fdt
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt) return NULL;

    // 3. 获取file指针数组
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array) return NULL;

    // 4. 检查fd是否在有效范围内
    unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
    if (fd < 0 || (unsigned int)fd >= max_fds) {
        return NULL;
    }

    // 5. 获取file指针
    struct file *filp;
    bpf_core_read(&filp, sizeof(filp), &fd_array[fd]);
    if (!filp) return NULL;

    // 6. 获取private_data（通常是socket指针）
    void *private_data = BPF_CORE_READ(filp, private_data);
    if (!private_data) return NULL;

    // 7. 对于socket，private_data是struct socket*
    struct socket *sock = (struct socket *)private_data;
    if (!sock) return NULL;

    // 8. 获取struct sock*
    struct sock *sk = BPF_CORE_READ(sock, sk);
    return sk;
}


// print ipv4_key 
// 修改print_ipv4_key函数声明和定义
static __always_inline void print_ipv4_key(struct ipv4_key_t *key) {
    char fmt[] = "pid=%u saddr=%s daddr=%s\n";
    char src[22];
    format_ip_port(key->saddr, 0, src);
    char dst[22];
    format_ip_port(key->daddr, key->dport, dst);
    bpf_trace_printk(fmt, sizeof(fmt), key->pid, src, dst);
}



char _license[] SEC("license") = "GPL";


void fill_ipv4_key(u64 pid_tgid, __u32 saddr_be, __u32 daddr_be, __u16 dport_be, struct ipv4_key_t *key) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    u64 pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    key->pid_ns = (u32) pidns;
    key->saddr = saddr_be;
    key->daddr = daddr_be;
    key->dport = dport_be;
    key->pid = (u32)(pid_tgid >> 32);
    bpf_get_current_comm(key->comm, sizeof(key->comm));
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


/* handshake context is defined in tcp_tracker.h */

/* start context keyed by tuple */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn4_tuple);
    __type(value, struct handshake_ctx);
} conn_start_map SEC(".maps");


/* best-effort owner info (captured at SYN_* and overwritten at accept()) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct conn4_tuple);
    __type(value, struct proc_ident);
} owner_map SEC(".maps");


static __always_inline __u32 bytes_to_ipv4_be(const __u8 a[4])
{
    return ((__u32)a[0] << 24) | ((__u32)a[1] << 16) | ((__u32)a[2] << 8) | (__u32)a[3];
}

static __always_inline __u32 bytes_to_ipv4_be_from_ctx(const void *ctx, __u32 byte_off)
{
    /*
     * Tracepoint context is special: the verifier doesn't allow dereferencing a
     * pointer derived from ctx via arithmetic ("modified ctx ptr").
     *
     * Read 4 bytes via bpf_probe_read_kernel() and assemble.
     */
    __u8 a[4] = {0, 0, 0, 0};
    const void *p = (const void *)((const char *)ctx + byte_off);
    bpf_probe_read_kernel(&a, sizeof(a), p);
    return ((__u32)a[0] << 24) | ((__u32)a[1] << 16) | ((__u32)a[2] << 8) | (__u32)a[3];
}

static __always_inline __u32 get_netns_inum_from_sock(const struct sock *sk)
{
    __u32 inum = 0;
    struct net *netp = NULL;

    bpf_core_read(&netp, sizeof(netp), &sk->__sk_common.skc_net);
    if (netp)
        bpf_core_read(&inum, sizeof(inum), &netp->ns.inum);

    return inum;
}


static __always_inline bool is_kernel_thread_or_idle(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    unsigned long flags = 0;
    bpf_core_read(&flags, sizeof(flags), &task->flags);

#ifdef PF_KTHREAD
    if (flags & PF_KTHREAD)
        return true;
#endif

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = pid_tgid >> 32;
    __u32 pid = (u32)pid_tgid;
    if (tgid == 0 || pid == 0)
        return true;

    return false;
}

static __always_inline struct conn_stats *get_or_init_stats(struct conn4_tuple *t)
{
    struct conn_stats *st = bpf_map_lookup_elem(&conn4_stats_map, t);
    if (st)
        return st;

    struct conn_stats zero = {};
    bpf_map_update_elem(&conn4_stats_map, t, &zero, BPF_NOEXIST);
    return bpf_map_lookup_elem(&conn4_stats_map, t);
}

static __always_inline struct conn_stats *get_global_stats(void)
{
    __u32 k0 = 0;
    return bpf_map_lookup_elem(&conn_global_stats, &k0);
}

/* 3 seconds */
static __always_inline bool is_timeoutish(__u64 delta_ns)
{
    return delta_ns >= 3000000000ULL;
}

/* Read tuple from a struct sock*, IPv4 only.
 * Returns 0 on success, <0 on failure/not-IPv4.
 */
static __always_inline int tuple_from_sock_v4(const struct sock *sk, struct conn4_tuple *t)
{
    /* family check */
    __u16 family = 0;
    bpf_core_read(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != 2 /* AF_INET */)
        return -1;

    __u32 saddr_be = 0, daddr_be = 0;
    __u16 dport_be = 0;
    __u16 sport_host = 0;

    /* Addresses in network order in skc_rcv_saddr / skc_daddr */
    bpf_core_read(&saddr_be, sizeof(saddr_be), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&daddr_be, sizeof(daddr_be), &sk->__sk_common.skc_daddr);

    /* dport stored in network order in skc_dport */
    bpf_core_read(&dport_be, sizeof(dport_be), &sk->__sk_common.skc_dport);

    /* local port in host order: skc_num */
    bpf_core_read(&sport_host, sizeof(sport_host), &sk->__sk_common.skc_num);

    t->saddr = bpf_ntohl(saddr_be);
    t->daddr = bpf_ntohl(daddr_be);
    t->sport = 0;
    t->dport = bpf_ntohs(dport_be);
    t->netns = get_netns_inum_from_sock(sk);

    return 0;
}

/* ---- Main state-machine hook ---- */
SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint__sock__inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    // if (is_kernel_thread_or_idle())
    //     return 0;

    /* only IPv4/TCP */
    if (ctx->family != 2 /* AF_INET */)
        return 0;
    if (ctx->protocol != 6 /* IPPROTO_TCP */)
        return 0;

    int oldstate = ctx->oldstate;
    int newstate = ctx->newstate;

    // /* Avoid ctx-pointer arithmetic deref (verifier restriction). */
    //__u32 saddr_be = bytes_to_ipv4_be_from_ctx(ctx, __builtin_offsetof(struct trace_event_raw_inet_sock_set_state, saddr));
    // __u32 daddr_be = bytes_to_ipv4_be_from_ctx(ctx, __builtin_offsetof(struct trace_event_raw_inet_sock_set_state, daddr));

    /* assemble 4-byte IPv4 addresses from the byte arrays in the tracepoint context
    * ctx->saddr and ctx->daddr are arrays of 4 bytes in network (big-endian) order.
    */
    __u32 saddr_be = 0, daddr_be = 0;
    saddr_be = ((__u32)ctx->saddr[0] << 24) | ((__u32)ctx->saddr[1] << 16) | ((__u32)ctx->saddr[2] << 8) | ((__u32)ctx->saddr[3]);
    daddr_be = ((__u32)ctx->daddr[0] << 24) | ((__u32)ctx->daddr[1] << 16) | ((__u32)ctx->daddr[2] << 8) | ((__u32)ctx->daddr[3]);

    __u16 sport = ( __u16 ) ctx->sport; /* tracepoint provides sport/dport */
    __u16 dport_be = ( __u16 ) ctx->dport; /* may be network order */

    /* Fallback: If sport is 0, read directly from socket structure.
 * This can happen during early connection phases like SYN_SENT where
 * the tracepoint context may not have the source port populated yet.
 */



    struct conn4_tuple t = {};
    t.saddr = (saddr_be);
    t.daddr = (daddr_be);
    t.sport = (0);
    t.dport = (dport_be);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32) (pid_tgid >> 32);

    if (!ctx->skaddr) {
        char fmt1[] = "inet_sock_set_state0: not sk pid_tgid=%llu saddr=%d daddr=%d";
        bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
        return 0;
    }
    const struct sock *sk = (const struct sock *)ctx->skaddr;
    t.netns = get_netns_inum_from_sock(sk);

    if (sport == 0) {
        bpf_core_read(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    }
    t.netns = get_netns_inum_from_sock(sk);


    // char fmt1[] = "inet_sock_set_state1: pid_tgid=%llu saddr=%d daddr=%d";
    // bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
    /* bpf_trace_printk supports up to 3 numeric args after fmt in many kernels; keep to 3 */
    char fmt[] = "inet_sock_set_state2: pid_tgid=%llu saddr=%s daddr=%s";
    char src[22];
    format_ip_port(t.saddr,t.sport, src);
    char dst[22];
    format_ip_port(t.daddr,t.dport, dst);
    bpf_trace_printk(fmt, sizeof(fmt),pid,src,dst);


    char fmt2[] = "inet_sock_set_state3:netns=%d oldstate:%s => newstate:%s";
    char statebuf[22];
    tcp_state_to_str(newstate, statebuf);
    char oldstatebuf[22];
    tcp_state_to_str(oldstate, oldstatebuf);
    bpf_trace_printk(fmt2, sizeof(fmt2),t.netns,oldstatebuf,statebuf);


    /* Start points: client SYN_SENT, server SYN_RECV */
    if (newstate == TCP_SYN_SENT || newstate == TCP_SYN_RECV) {
        struct handshake_ctx hs = {};
        hs.start_ns = bpf_ktime_get_ns();
        hs.start_state = (__u8)newstate;
        hs.last_state = (__u8)newstate;
        hs.saw_non_syn = 0;
        bpf_map_update_elem(&conn_start_map, &t, &hs, BPF_ANY);

        /* best-effort owner at SYN_* */
        struct proc_ident pi = {};
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        pi.pid_ns = (u32)BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);

        __u64 pid_tgid = bpf_get_current_pid_tgid();
        pi.tgid = (__u32)(pid_tgid >> 32);
        bpf_get_current_comm(&pi.comm, sizeof(pi.comm));
        if (pi.tgid != 0) {
            bpf_map_update_elem(&owner_map, &t, &pi, BPF_ANY);
        }

        struct conn_stats *st = get_or_init_stats(&t);
        if (st) __sync_fetch_and_add(&st->attempts, 1);

        struct conn_stats *gst = get_global_stats();
        if (gst) __sync_fetch_and_add(&gst->attempts, 1);

        return 0;
    }

    /* If we're tracking this tuple, update handshake context */
    struct handshake_ctx *hsp = bpf_map_lookup_elem(&conn_start_map, &t);
    if (hsp) {
        hsp->last_state = (__u8)newstate;
        if (newstate != TCP_SYN_SENT && newstate != TCP_SYN_RECV && newstate != TCP_ESTABLISHED)
            hsp->saw_non_syn = 1;
    }

    /* Success: ESTABLISHED */
    if (newstate == TCP_ESTABLISHED) {
        if (hsp) {
            char fmt1[] = "TCP_ESTABLISHED :hsp pid_tgid=%llu saddr=%d daddr=%d";
            bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
            __u64 delta = bpf_ktime_get_ns() - hsp->start_ns;
            bpf_map_delete_elem(&conn_start_map, &t);

            struct conn_stats *st = get_or_init_stats(&t);
            if (st) {
                __sync_fetch_and_add(&st->latency_sum_ns, delta);
                __sync_fetch_and_add(&st->latency_count, 1);
            }
            struct conn_stats *gst = get_global_stats();
            if (gst) {
                __sync_fetch_and_add(&gst->latency_sum_ns, delta);
                __sync_fetch_and_add(&gst->latency_count, 1);
            }
        }else {
            char fmt1[] = "TCP_ESTABLISHED:hsp not found,pid_tgid=%llu saddr=%d daddr=%d";
            bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
        }
        return 0;
    }

    /* Failure end: CLOSE while handshake is still pending */
    if (newstate == TCP_CLOSE) {
        if (hsp) {
            char fmt1[] = "TCP_CLOSE :hsp pid_tgid=%llu saddr=%d daddr=%d";
            bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
            __u64 delta = bpf_ktime_get_ns() - hsp->start_ns;

            struct conn_stats *st = get_or_init_stats(&t);
            struct conn_stats *gst = get_global_stats();

            if (st) __sync_fetch_and_add(&st->failures, 1);
            if (gst) __sync_fetch_and_add(&gst->failures, 1);

            if (is_timeoutish(delta)) {
                if (st) __sync_fetch_and_add(&st->timeout_failures, 1);
                if (gst) __sync_fetch_and_add(&gst->timeout_failures, 1);
            } else if (oldstate == TCP_SYN_SENT || oldstate == TCP_SYN_RECV || hsp->saw_non_syn == 0) {
                if (st) __sync_fetch_and_add(&st->rst_failures, 1);
                if (gst) __sync_fetch_and_add(&gst->rst_failures, 1);
            } else {
                if (st) __sync_fetch_and_add(&st->other_failures, 1);
                if (gst) __sync_fetch_and_add(&gst->other_failures, 1);
            }

            bpf_map_delete_elem(&conn_start_map, &t);
        }else {
            char fmt1[] = "TCP_CLOSE :no hsp pid_tgid=%llu saddr=%d daddr=%d";
            bpf_trace_printk(fmt1, sizeof(fmt1),pid,saddr_be,daddr_be);
        }
        return 0;
    }

    return 0;
}

/* ---- Service-side owner attribution: accept() context ----
 * When inet_csk_accept returns a new socket, current is the accept thread,
 * so comm/tgid is reliable for server attribution.
 */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(ret_inet_csk_accept)
{
    if (is_kernel_thread_or_idle())
        return 0;

    struct sock *newsk = (struct sock *)PT_REGS_RC(ctx);
    if (!newsk)
        return 0;

    struct conn4_tuple t = {};
    if (tuple_from_sock_v4(newsk, &t) != 0)
        return 0;

    struct proc_ident pi = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pi.tgid = (__u32)(pid_tgid >> 32);
    bpf_get_current_comm(&pi.comm, sizeof(pi.comm));

    if (pi.tgid != 0) {
        /* overwrite/update owner info with accept thread identity */
        bpf_map_update_elem(&owner_map, &t, &pi, BPF_ANY);
    }

    return 0;
}
