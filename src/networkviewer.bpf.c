#if MY_LINUX_VERSION_CODE >= NETDATA_EBPF_KERNEL_5_19_0
#include "vmlinux_519.h"
#else
#include "vmlinux_508.h"
#endif

#include "bpf_tracing.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include "netdata_core.h"
#include "netdata_socket.h"

// Copied from https://elixir.bootlin.com/linux/v5.15.5/source/include/linux/socket.h#L175
#define AF_UNSPEC	0
#define AF_INET		2
#define AF_INET6	10

const volatile bool collect_everything = false;

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_nv_idx_t);
    __type(value, netdata_nv_data_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_nv_socket SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} nv_ctrl SEC(".maps");

/***********************************************************************************
 *
 *                                SOCKET COMMON
 *
 ***********************************************************************************/

static __always_inline __u16 set_nv_idx_value(netdata_nv_idx_t *nvi, struct sock *sk)
{
    struct inet_sock *is = (struct inet_sock *)sk;
    __u16 family;

    // Read Family
    bpf_probe_read(&family, sizeof(u16), &is->sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        // bpf_probe_read(&nvi->saddr.addr32[0], sizeof(u32), &is->inet_rcv_saddr); // bind to local address
        BPF_CORE_READ_INTO(&nvi->saddr.ipv4, is, inet_saddr );
        BPF_CORE_READ_INTO(&nvi->daddr.ipv4, is, sk.__sk_common.skc_daddr );
        if (nvi->saddr.ipv4 == 0 || nvi->daddr.ipv4 == 0) // Zero
            return AF_UNSPEC;
    }
    // Check necessary according https://elixir.bootlin.com/linux/v5.6.14/source/include/net/sock.h#L199
    else if ( family == AF_INET6 ) {
#if defined(NETDATA_CONFIG_IPV6)
        BPF_CORE_READ_INTO(&nvi->ipv6.addr8, is, sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 );
        BPF_CORE_READ_INTO(&nvi->ipv6.addr8, is, sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8 );

        if (((nvi->saddr.ipv6.addr64[0] == 0) && (nvi->saddr.ipv6.addr64[1] == 0)) ||
            ((nvi->daddr.ipv6.addr64[0] == 0) && (nvi->daddr.ipv6.addr64[1] == 0))) // Zero addr
            return AF_UNSPEC;
#endif
    }
    else {
        return AF_UNSPEC;
    }

    //Read destination port
    BPF_CORE_READ_INTO(&nvi->dport, is, sk.__sk_common.skc_dport);
    BPF_CORE_READ_INTO(&nvi->sport, is, inet_saddr);

    // Socket for nowhere or system looking for port
    // This can be an attack vector that needs to be addressed in another opportunity
    if (nvi->sport == 0 || nvi->dport == 0)
        return AF_UNSPEC;

    return family;
}

static __always_inline __s32 am_i_monitoring_protocol(struct sock *sk)
{
    if (!sk)
        return 0;

    u16 protocol = 0;
    bpf_probe_read(&protocol, sizeof(u16), &sk->sk_protocol);

    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    return 1;
} 

static __always_inline void set_common_tcp_nv_data(netdata_nv_data_t *data,
                                               struct sock *sk,
                                               __u16 family,
                                               int state)
{
    const struct inet_sock *is = (struct inet_sock *)sk;
    const struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    __u8 icsk_pending;
    int rx_queue;
    struct timer_list tl;

    bpf_probe_read(&icsk_pending, sizeof(u8), &icsk->icsk_pending);
    bpf_probe_read(&tl, sizeof(struct timer_list), &sk->sk_timer);

// Copied from https://elixir.bootlin.com/linux/latest/source/include/net/inet_connection_sock.h#L144
#define ICSK_TIME_RETRANS	1	/* Retransmit timer */
#define ICSK_TIME_DACK		2	/* Delayed ack timer */
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */
#define ICSK_TIME_LOSS_PROBE	5	/* Tail loss probe timer */
#define ICSK_TIME_REO_TIMEOUT	6	/* Reordering timer */

    if (icsk_pending == ICSK_TIME_RETRANS ||
        icsk_pending == ICSK_TIME_REO_TIMEOUT ||
        icsk_pending == ICSK_TIME_LOSS_PROBE) {
        data->wqueue = 1;
    } else if (icsk_pending == ICSK_TIME_PROBE0) {
        data->wqueue = 4;
    } /* else if (timer_pending(&tl)) {
        data->wqueue = 2;
    } */ else {
        data->wqueue = 0;
    }
    
    if (state == TCP_LISTEN)
        bpf_probe_read(&rx_queue, sizeof(rx_queue), &sk->sk_ack_backlog);
    else {
        u32 rcv_nxt, copied_seq;
        const struct tcp_sock *tp = (struct tcp_sock *)sk;
        bpf_probe_read(&rcv_nxt, sizeof(u32), &tp->rcv_nxt);
        bpf_probe_read(&copied_seq, sizeof(u32), &tp->copied_seq);
        rx_queue = rcv_nxt - copied_seq;
        rx_queue =  (rx_queue > 0) ? rx_queue : 0;
    }

    bpf_get_current_comm(&data->name, TASK_COMM_LEN);

    data->pid = bpf_get_current_pid_tgid() >> 32;
    data->uid = bpf_get_current_uid_gid();
    data->timer = 0;
    bpf_probe_read(&data->retransmits, sizeof(data->retransmits), &icsk->icsk_retransmits);
    data->expires = 0;
    data->rqueue = rx_queue;

    data->family = family;
    data->protocol = IPPROTO_TCP;
}

static __always_inline void set_common_udp_nv_data(netdata_nv_data_t *data,
                                                   struct sock *sk,
                                                   __u16 family) {
    data->protocol = IPPROTO_UDP;
    data->family = family;
    BPF_CORE_READ_INTO(&data->state, sk, __sk_common.skc_state);
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(netdata_nv_inet_csk_accept_kretprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_RC(ctx);
    if (!am_i_monitoring_protocol(sk))
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KRETPROBE(netdata_nv_tcp_v4_connect_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KRETPROBE(netdata_nv_tcp_v6_connect_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(netdata_nv_tcp_retransmit_skb_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(netdata_nv_tcp_cleanup_rbuf_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(netdata_nv_tcp_set_state_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

    if (!sk || sk == (void *)1)
        return 0;

    int state = (int)PT_REGS_PARM2(ctx);
    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, state);
        val->state = state;
        return 0;
    }

    if (!collect_everything)
        return 0;


    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(netdata_nv_tcp_sendmsg_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(netdata_nv_udp_sendmsg_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_udp_nv_data(val, sk, family);
        BPF_CORE_READ_INTO(&val->state, sk, __sk_common.skc_state);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_udp_nv_data(&data, sk, family);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(netdata_nv_udp_recvmsg_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_udp_nv_data(val, sk, family);
        BPF_CORE_READ_INTO(&val->state, sk, __sk_common.skc_state);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_udp_nv_data(&data, sk, family);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(tracepoint)
 *
 ***********************************************************************************/

SEC("fexit/inet_csk_accept")
int BPF_PROG(netdata_nv_inet_csk_accept_fexit, struct sock *sk)
{
    if (!am_i_monitoring_protocol(sk))
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(netdata_nv_tcp_v4_connect_fentry, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(netdata_nv_tcp_v6_connect_fentry, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(netdata_nv_tcp_retransmit_skb_fentry, struct sock *sk)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(netdata_nv_tcp_cleanup_rbuf_fentry, struct sock *sk, int copied)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(netdata_nv_tcp_set_state_fentry, struct sock *sk, int state)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, state);
        val->state = state;
        return 0;
    }

    if (!collect_everything)
        return 0;


    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(netdata_nv_tcp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (!sk || sk == (void *)1)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_tcp_nv_data(val, sk, family, 0);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_tcp_nv_data(&data, sk, family, 0);

    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(netdata_nv_udp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_udp_nv_data(val, sk, family);
        BPF_CORE_READ_INTO(&val->state, sk, __sk_common.skc_state);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_udp_nv_data(&data, sk, family);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("fentry/udp_recvmsg")
int BPF_PROG(netdata_nv_udp_recvmsg_fentry, struct sock *sk)
{
    if (!sk)
        return 0;

    netdata_nv_idx_t idx;
    __u16 family = set_nv_idx_value(&idx, sk);
    netdata_nv_data_t *val = (netdata_nv_data_t *) bpf_map_lookup_elem(&tbl_nv_socket, &idx);
    if (val) {
        set_common_udp_nv_data(val, sk, family);
        BPF_CORE_READ_INTO(&val->state, sk, __sk_common.skc_state);
        return 0;
    }

    if (!collect_everything)
        return 0;

    netdata_nv_data_t data = { };
    set_common_udp_nv_data(&data, sk, family);

    bpf_map_update_elem(&tbl_nv_socket, &idx, &data, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";

