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


/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SOCKET_COUNTER);
} tbl_global_sock SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_socket_idx_t);
    __type(value, netdata_socket_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_nd_socket SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u64);
    __type(value, void *);
    __uint(max_entries, 8192);
} tbl_nv_udp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, netdata_passive_connection_idx_t);
    __type(value, netdata_passive_connection_t);
    __uint(max_entries, 1024);
} tbl_lports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} socket_ctrl SEC(".maps");

/***********************************************************************************
 *
 *                                SOCKET COMMON
 *
 ***********************************************************************************/

static __always_inline short unsigned int set_idx_value(netdata_socket_idx_t *nsi, struct inet_sock *is)
{
    // Read Family
    short unsigned int family;
    BPF_CORE_READ_INTO(&family, is, sk.__sk_common.skc_family);
    // Read source and destination IPs
    if ( family == AF_INET ) { //AF_INET
        //BPF_CORE_READ_INTO(&nsi->saddr.addr32[0], is, sk.__sk_common.skc_rcv_saddr ); //bind to local address
        BPF_CORE_READ_INTO(&nsi->saddr.addr32[0], is, inet_saddr );
        BPF_CORE_READ_INTO(&nsi->daddr.addr32[0], is, sk.__sk_common.skc_daddr );

        if ((nsi->saddr.addr32[0] == 0 || nsi->daddr.addr32[0] == 0) || // Zero addr
           nsi->saddr.addr32[0] == 16777343 || nsi->daddr.addr32[0] == 16777343) // Loopback
            return AF_UNSPEC;
    } else if ( family == AF_INET6 ) {
#if defined(NETDATA_CONFIG_IPV6)
        BPF_CORE_READ_INTO(&nsi->saddr.addr8, is, sk.__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 );
        BPF_CORE_READ_INTO(&nsi->daddr.addr8, is, sk.__sk_common.skc_v6_daddr.in6_u.u6_addr8 );

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 72057594037927936)) ||  // Loopback
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 72057594037927936)))
            return AF_UNSPEC;

        if (((nsi->saddr.addr64[0] == 0) && (nsi->saddr.addr64[1] == 0)) ||
            ((nsi->daddr.addr64[0] == 0) && (nsi->daddr.addr64[1] == 0))) // Zero addr
            return AF_UNSPEC;
#endif
    } else {
        return AF_UNSPEC;
    }

    //Read ports
    BPF_CORE_READ_INTO(&nsi->dport, is, sk.__sk_common.skc_dport);
    //BPF_CORE_READ_INTO(&nsi->sport, is, sk.__sk_common.skc_num);

    nsi->dport = nsi->dport;
   // nsi->sport = nsi->sport;

    // Socket for nowhere or system looking for port
    // This can be an attack vector that needs to be addressed in another opportunity
    // if (nsi->sport == 0 || nsi->dport == 0)
    if (nsi->dport == 0)
        return AF_UNSPEC;

    nsi->pid = netdata_get_pid(&socket_ctrl);

    return family;
}

static __always_inline void update_socket_common(netdata_socket_t *data, __u16 protocol, __u16 family)
{
    data->ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(&data->name, TASK_COMM_LEN);
#else
    data->name[0] = '\0';
#endif

    data->first = bpf_ktime_get_ns();
    data->ct = data->first;
    data->protocol = protocol;
    data->family = family;
}

static __always_inline void update_socket_stats(netdata_socket_t *ptr,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol)
{
    ptr->ct = bpf_ktime_get_ns();

    if (sent) {
        if (protocol == IPPROTO_TCP) {
            libnetdata_update_u32(&ptr->tcp.call_tcp_sent, 1);
            libnetdata_update_u64(&ptr->tcp.tcp_bytes_sent, sent);

            libnetdata_update_u32(&ptr->tcp.retransmit, retransmitted);
        } else {
            libnetdata_update_u32(&ptr->udp.call_udp_sent, 1);
            libnetdata_update_u64(&ptr->udp.udp_bytes_sent, sent);
        }
    }

    if (received) {
        if (protocol == IPPROTO_TCP) {
            libnetdata_update_u32(&ptr->tcp.call_tcp_received, 1);
            libnetdata_update_u64(&ptr->tcp.tcp_bytes_received, received);
        } else {
            libnetdata_update_u32(&ptr->udp.call_udp_received, 1);
            libnetdata_update_u64(&ptr->udp.udp_bytes_received, received);
        }
    }
}

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
static __always_inline void update_socket_table(struct inet_sock *is,
                                                __u64 sent,
                                                __u64 received,
                                                __u32 retransmitted,
                                                __u16 protocol)
{
    netdata_socket_idx_t idx = { };

    __u16 family = set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return;

    netdata_socket_t *val;
    netdata_socket_t data = { };

    val = (netdata_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (val) {
        update_socket_stats(val, sent, received, retransmitted, protocol);
    } else {
        // This will be present while we do not have network viewer.
        update_socket_common(&data, protocol, family);
        update_socket_stats(&data, sent, received, retransmitted, protocol);

        libnetdata_update_global(&socket_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);

        bpf_map_update_elem(&tbl_nd_socket, &idx, &data, BPF_ANY);
    }
}

static __always_inline void update_pid_connection(struct inet_sock *is)
{
    netdata_socket_idx_t idx = { };

    netdata_socket_t *stored;
    netdata_socket_t data = { };

    __u16 family = set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return;

    stored = (netdata_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (stored) {
        stored->ct = bpf_ktime_get_ns();

        if (family == AF_INET)
            libnetdata_update_u32(&stored->tcp.ipv4_connect, 1);
        else
            libnetdata_update_u32(&stored->tcp.ipv6_connect, 1);
    } else {
        update_socket_common(&data, IPPROTO_TCP, family);
        if (family == AF_INET6)
            data.tcp.ipv4_connect = 1;
        else
            data.tcp.ipv6_connect = 1;

        bpf_map_update_elem(&tbl_nd_socket, &idx, &data, BPF_ANY);

        libnetdata_update_global(&socket_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }
}

static __always_inline int common_tcp_send_message(struct inet_sock *is, size_t sent, int ret)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_SENDMSG, 1);

    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_SENDMSG, 1);
        return 0;
    }

    update_socket_table(is, sent, 0, 0, IPPROTO_TCP);
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_SENDMSG, sent);

    return 0;
}

static __always_inline int common_udp_send_message(struct inet_sock *is, size_t sent, int ret)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_SENDMSG, 1);

    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_UDP_SENDMSG, 1);
        return 0;
    }

    update_socket_table(is, sent, 0, 0, IPPROTO_UDP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_SENDMSG, (__u64) sent);

    return 0;
}

static __always_inline int netdata_common_inet_csk_accept(struct sock *sk)
{
    if (!sk)
        return 0;

    netdata_passive_connection_t data = { };
    netdata_passive_connection_idx_t idx = { };

    __u16 protocol = BPF_CORE_READ(sk, sk_protocol);
    if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
        return 0;

    idx.port = BPF_CORE_READ(sk, __sk_common.skc_num);
    idx.protocol = protocol;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    netdata_passive_connection_t *value = (netdata_passive_connection_t *)bpf_map_lookup_elem(&tbl_lports, &idx);
    if (value) {
        // Update PID, because process can die.
        value->tgid = tgid;
        value->pid = pid;
        libnetdata_update_u64(&value->counter, 1);
    } else {
        data.tgid = tgid;
        data.pid = pid;
        data.counter = 1;
        bpf_map_update_elem(&tbl_lports, &idx, &data, BPF_ANY);

        libnetdata_update_global(&socket_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    struct inet_sock *is = (struct inet_sock *)sk;
    netdata_socket_idx_t nv_idx = { };
    __u16 family = set_idx_value(&nv_idx, is);
    if (family == AF_UNSPEC)
        return 0;

    netdata_socket_t *val;
    netdata_socket_t nv_data = { };

    val = (netdata_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &nv_idx);
    if (val) {
        libnetdata_update_u32(&val->external_origin, 1);
    } else {
        update_socket_common(&nv_data, protocol, family);
        nv_data.external_origin = 1;

        bpf_map_update_elem(&tbl_nd_socket, &nv_idx, &nv_data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_tcp_retransmit(struct inet_sock *is)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_TCP_RETRANSMIT, 1);

    update_socket_table(is, 0, 0, 1, IPPROTO_TCP);

    return 0;
}

static __always_inline int netdata_common_tcp_cleanup_rbuf(int copied, struct inet_sock *is, __u64 received)
{
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLEANUP_RBUF, 1);

    if (copied < 0) {
        libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_ERROR_TCP_CLEANUP_RBUF, 1);
        return 0;
    }

    update_socket_table(is, 0, (__u64)copied, 1, IPPROTO_TCP);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_TCP_CLEANUP_RBUF, received);

    return 0;
}

static __always_inline int netdata_common_tcp_close(struct inet_sock *is)
{
    netdata_socket_t *val;
    __u16 family;
    netdata_socket_idx_t idx = { };

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_TCP_CLOSE, 1);

    family =  set_idx_value(&idx, is);
    if (family == AF_UNSPEC)
        return 0;

    val = (netdata_socket_t *) bpf_map_lookup_elem(&tbl_nd_socket, &idx);
    if (val) {
        libnetdata_update_u32(&val->tcp.close, 1);
    }

    return 0;
}

static inline int netdata_common_udp_recvmsg(struct sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_CALLS_UDP_RECVMSG, 1);

    bpf_map_update_elem(&tbl_nv_udp, &pid_tgid, &sk, BPF_ANY);

    return 0;
}

static __always_inline int netdata_common_udp_recvmsg_return(struct inet_sock *is, __u64 received)
{
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct sock **skpp = bpf_map_lookup_elem(&tbl_nv_udp, &pid_tgid);
    if (skpp == 0) {
        return 0;
    }

    bpf_map_delete_elem(&tbl_nv_udp, &pid_tgid);

    libnetdata_update_global(&tbl_global_sock, NETDATA_KEY_BYTES_UDP_RECVMSG, received);

    update_socket_table(is, 0, received, 0, IPPROTO_UDP);

    return 0;
}

static __always_inline int netdata_common_tcp_connect(struct inet_sock *is, int ret,
                                                      enum socket_counters success,
                                                      enum socket_counters err)
{
    libnetdata_update_global(&tbl_global_sock, success, 1);

    if (ret < 0) {
        libnetdata_update_global(&tbl_global_sock, err, 1);
        return 0;
    }

    update_pid_connection(is);

    return 0;
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(netdata_inet_csk_accept_kretprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_RC(ctx);

    return netdata_common_inet_csk_accept(sk);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KRETPROBE(netdata_tcp_v4_connect_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return netdata_common_tcp_connect(is, 0, NETDATA_KEY_CALLS_TCP_CONNECT_IPV4,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV4);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(netdata_tcp_v4_connect_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return netdata_common_tcp_connect(is, ret, NETDATA_KEY_CALLS_TCP_CONNECT_IPV4,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV4);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KRETPROBE(netdata_tcp_v6_connect_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return netdata_common_tcp_connect(is, 0, NETDATA_KEY_CALLS_TCP_CONNECT_IPV6,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV6);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(netdata_tcp_v6_connect_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);

    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return netdata_common_tcp_connect(is, ret, NETDATA_KEY_CALLS_TCP_CONNECT_IPV6,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV6);
}

SEC("kprobe/tcp_retransmit_skb")
int BPF_KPROBE(netdata_tcp_retransmit_skb_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return netdata_common_tcp_retransmit(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(netdata_tcp_cleanup_rbuf_kprobe)
{
    int copied = (int)PT_REGS_PARM2(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    __u64 received = (__u64) copied;

    return netdata_common_tcp_cleanup_rbuf(copied, is, received);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(netdata_tcp_close_kprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return netdata_common_tcp_close(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(netdata_udp_recvmsg_kprobe)
{
    struct sock *sk = (struct sock*)PT_REGS_PARM1(ctx);

    return netdata_common_udp_recvmsg(sk);
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(netdata_udp_recvmsg_kretprobe)
{
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    __u64 received = (__u64) PT_REGS_RC(ctx);

    return netdata_common_udp_recvmsg_return(is, received);
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(netdata_tcp_sendmsg_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    size_t sent = (ret > 0 )?(size_t) ret : 0;

    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));
    return common_tcp_send_message(is, sent, ret);
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(netdata_tcp_sendmsg_kprobe)
{
    size_t sent = (size_t) PT_REGS_PARM3(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_tcp_send_message(is, sent, 0);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(netdata_udp_sendmsg_kretprobe)
{
    int ret = (int)PT_REGS_RC(ctx);
    size_t sent = (ret > 0 )?(size_t)ret : 0;
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_udp_send_message(is, sent, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(netdata_udp_sendmsg_kprobe)
{
    size_t sent = (size_t)PT_REGS_PARM3(ctx);
    struct inet_sock *is = (struct inet_sock *)((struct sock *)PT_REGS_PARM1(ctx));

    return common_udp_send_message(is, sent, 0);
}

/***********************************************************************************
 *
 *                             SOCKET SECTION(tracepoint)
 *
 ***********************************************************************************/

SEC("fexit/inet_csk_accept")
int BPF_PROG(netdata_inet_csk_accept_fexit, struct sock *sk)
{
    if (!sk)
        return 0;

    return netdata_common_inet_csk_accept(sk);
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(netdata_tcp_v4_connect_fentry, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return netdata_common_tcp_connect(is, 0, NETDATA_KEY_CALLS_TCP_CONNECT_IPV4,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV4);
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(netdata_tcp_v4_connect_fexit, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return netdata_common_tcp_connect(is, ret, NETDATA_KEY_CALLS_TCP_CONNECT_IPV4,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV4);
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(netdata_tcp_v6_connect_fentry, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return netdata_common_tcp_connect(is, 0, NETDATA_KEY_CALLS_TCP_CONNECT_IPV6,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV6);
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(netdata_tcp_v6_connect_fexit, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return netdata_common_tcp_connect(is, ret, NETDATA_KEY_CALLS_TCP_CONNECT_IPV6,
                                      NETDATA_KEY_ERROR_TCP_CONNECT_IPV6);
}

SEC("fentry/tcp_retransmit_skb")
int BPF_PROG(netdata_tcp_retransmit_skb_fentry, struct sock *sk)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;

    return netdata_common_tcp_retransmit(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/tcp.c#L1528
SEC("fentry/tcp_cleanup_rbuf")
int BPF_PROG(netdata_tcp_cleanup_rbuf_fentry, struct sock *sk, int copied)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    __u64 received = (__u64) copied;

    return netdata_common_tcp_cleanup_rbuf(copied, is, received);
}

SEC("fentry/tcp_close")
int BPF_PROG(netdata_tcp_close_fentry, struct sock *sk)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;

    return netdata_common_tcp_close(is);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L1726
SEC("fentry/udp_recvmsg")
int BPF_PROG(netdata_udp_recvmsg_fentry, struct sock *sk)
{
    if (!sk)
        return 0;

    return netdata_common_udp_recvmsg(sk);
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(netdata_udp_recvmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)(sk);

    return netdata_common_udp_recvmsg_return(is, (__u64)len);
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(netdata_tcp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;

    return common_tcp_send_message(is, size, 0);
}

SEC("fexit/tcp_sendmsg")
int BPF_PROG(netdata_tcp_sendmsg_fexit, struct sock *sk, struct msghdr *msg, size_t size, int ret)
{
    if (!sk)
        return 0;

    size_t sent = (ret > 0 )?(size_t) ret : 0;

    struct inet_sock *is = (struct inet_sock *)sk;
    return common_tcp_send_message(is, sent, ret);
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(netdata_udp_sendmsg_fentry, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    struct inet_sock *is = (struct inet_sock *)sk;

    return common_udp_send_message(is, len, 0);
}

// https://elixir.bootlin.com/linux/v5.6.14/source/net/ipv4/udp.c#L965
SEC("fexit/udp_sendmsg")
int BPF_PROG(netdata_udp_sendmsg_fexit, struct sock *sk, struct msghdr *msg, size_t len, int ret)
{
    if (!sk)
        return 0;

    size_t sent = (ret > 0 )?(size_t)ret : 0;
    struct inet_sock *is = (struct inet_sock *)sk;

    return common_udp_send_message(is, sent, ret);
}

char _license[] SEC("license") = "GPL";

