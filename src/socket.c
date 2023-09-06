#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <sys/wait.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"
#include "netdata_socket.h"

#include "socket.skel.h"

// Socket functions
char *function_list[] = { "inet_csk_accept",
                          "tcp_retransmit_skb",
                          "tcp_cleanup_rbuf",
                          "tcp_close",
                          "udp_recvmsg",
                          "tcp_sendmsg",
                          "udp_sendmsg",
                          "tcp_v4_connect",
                          "tcp_v6_connect"};

#define NETDATA_IPV4 4
#define NETDATA_IPV6 6

static int ebpf_attach_probes(struct socket_bpf *obj)
{
    obj->links.netdata_inet_csk_accept_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_inet_csk_accept_kretprobe,
                                                                              true, function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);
    int ret = libbpf_get_error(obj->links.netdata_inet_csk_accept_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_v4_connect_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_v4_connect_kprobe,
                                                                             false, function_list[NETDATA_FCNT_TCP_V4_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_v4_connect_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_v4_connect_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_v4_connect_kretprobe,
                                                                             true, function_list[NETDATA_FCNT_TCP_V4_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_v4_connect_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_v6_connect_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_v6_connect_kprobe,
                                                                          false, function_list[NETDATA_FCNT_TCP_V6_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_v6_connect_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_v6_connect_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_v6_connect_kretprobe,
                                                                             true, function_list[NETDATA_FCNT_TCP_V6_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_v6_connect_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_retransmit_skb_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_retransmit_skb_kprobe,
                                                                              false, function_list[NETDATA_FCNT_TCP_RETRANSMIT]);
    ret = libbpf_get_error(obj->links.netdata_tcp_retransmit_skb_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_cleanup_rbuf_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_cleanup_rbuf_kprobe,
                                                                            false, function_list[NETDATA_FCNT_CLEANUP_RBUF]);
    ret = libbpf_get_error(obj->links.netdata_tcp_cleanup_rbuf_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_close_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_close_kprobe,
                                                                     false, function_list[NETDATA_FCNT_TCP_CLOSE]);
    ret = libbpf_get_error(obj->links.netdata_tcp_close_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_recvmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_recvmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_RECEVMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_recvmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_recvmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_recvmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_UDP_RECEVMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_recvmsg_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_TCP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_tcp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_tcp_sendmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_tcp_sendmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_TCP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_tcp_sendmsg_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_udp_sendmsg_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_udp_sendmsg_kretprobe,
                                                                          true, function_list[NETDATA_FCNT_UDP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_udp_sendmsg_kretprobe);
    if (ret)
        return -1;

    return 0;
}

static void ebpf_disable_probes(struct socket_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_inet_csk_accept_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v4_connect_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v4_connect_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v6_connect_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v6_connect_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_retransmit_skb_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_cleanup_rbuf_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_close_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_recvmsg_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_recvmsg_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_kprobe, false);
}

static void ebpf_disable_trampoline(struct socket_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_inet_csk_accept_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v4_connect_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v4_connect_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v6_connect_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_v6_connect_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_retransmit_skb_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_cleanup_rbuf_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_close_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_recvmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_recvmsg_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_tcp_sendmsg_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_udp_sendmsg_fexit, false);
}

static void ebpf_set_trampoline_target(struct socket_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_inet_csk_accept_fexit, 0,
                                   function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_v4_connect_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_V4_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_v4_connect_fexit, 0,
                                   function_list[NETDATA_FCNT_TCP_V4_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_v6_connect_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_V6_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_v6_connect_fexit, 0,
                                   function_list[NETDATA_FCNT_TCP_V6_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_retransmit_skb_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_RETRANSMIT]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_cleanup_rbuf_fentry, 0,
                                   function_list[NETDATA_FCNT_CLEANUP_RBUF]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_close_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_CLOSE]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_recvmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_RECEVMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_recvmsg_fexit, 0,
                                   function_list[NETDATA_FCNT_UDP_RECEVMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_tcp_sendmsg_fexit, 0,
                                   function_list[NETDATA_FCNT_TCP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_udp_sendmsg_fexit, 0,
                                   function_list[NETDATA_FCNT_UDP_SENDMSG]);
}

static inline int ebpf_load_and_attach(struct socket_bpf *obj, int selector)
{
    // Adjust memory
    int ret;
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    ret = socket_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    if (!selector) {
        ret = socket_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "Socket loaded with success\n");
    }

    return ret;
}

static inline pid_t update_global(struct socket_bpf *obj)
{
    int fd = bpf_map__fd(obj->maps.tbl_global_sock);
    return ebpf_fill_global(fd);
}

static inline int update_socket_tables(int fd, netdata_socket_idx_t *idx, netdata_socket_t *values)
{
    int ret = bpf_map_update_elem(fd, idx, values, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to socket table.\n");

    return ret;
}

static inline int update_local_ports(struct socket_bpf *obj)
{
    netdata_passive_connection_idx_t idx = { .protocol = 6, .port = 44444 };
    netdata_passive_connection_t value = { .tgid = 1, .pid = 1, .counter = 1 };
    int fd = bpf_map__fd(obj->maps.tbl_lports);
    int ret = bpf_map_update_elem(fd, &idx, &value, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to local port table.\n");

    return ret;
}

pid_t ebpf_update_tables(struct socket_bpf *obj, netdata_socket_idx_t *idx, netdata_socket_t *values)
{
    pid_t my_pid = update_global(obj);

    int fd = bpf_map__fd(obj->maps.tbl_nd_socket);
    int has_error = update_socket_tables(fd, idx, values);

    has_error += update_local_ports(obj);

    if (!has_error)
        fprintf(stdout, "Tables updated with success!\n");

    return my_pid;
}

static int netdata_read_socket(netdata_socket_idx_t *idx, struct socket_bpf *obj, int ebpf_nprocs)
{
    netdata_socket_t stored[ebpf_nprocs];

    uint64_t counter = 0;
    int fd = bpf_map__fd(obj->maps.tbl_nd_socket);
    netdata_socket_idx_t key =  { };
    netdata_socket_idx_t next_key = { };
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, idx, stored)) {
            counter++;
        }

        key = next_key;
    }

    if (counter) {
        fprintf(stdout, "Socket data stored with success. It collected %lu sockets\n", counter);
        return 0;
    }

    fprintf(stdout, "Cannot read socket data.\n");

    return 2;
}

static int netdata_read_local_ports(struct socket_bpf *obj)
{
    netdata_passive_connection_idx_t idx = { .protocol = 6, .port = 44444 };
    netdata_passive_connection_t value = { .tgid = 0, .pid = 0, .counter = 0 };
    int fd = bpf_map__fd(obj->maps.tbl_lports);
    if (!bpf_map_lookup_elem(fd, &idx, &value)) {
        if (value.counter)
            return 0;
    }

    fprintf(stdout, "Cannot read local ports data.\n");

    return 2;
}

int ebpf_socket_tests(int selector, enum netdata_apps_level map_level)
{
    struct socket_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = NETDATA_CORE_PROCESS_NUMBER;

    obj = socket_bpf__open();
    if (!obj) {
        goto load_error;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != NETDATA_MODE_PROBE) {
        socket_bpf__destroy(obj);

        obj = socket_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = NETDATA_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        int fd = bpf_map__fd(obj->maps.socket_ctrl);
        ebpf_core_fill_ctrl(obj->maps.socket_ctrl, map_level);

        //netdata_socket_idx_t common_idx = { .saddr.addr64 = { 1, 1 }, .sport = 1, .daddr.addr64 = {1 , 1}, .dport = 1, .pid = 1 };
        netdata_socket_idx_t common_idx = { .saddr.addr64 = { 1, 1 }, .daddr.addr64 = {1 , 1}, .dport = 1, .pid = 1 };
        netdata_socket_t values = { .tcp.call_tcp_sent = 1, .tcp.call_tcp_received = 1, .tcp.tcp_bytes_sent = 1, .tcp.tcp_bytes_received = 1,
                                    .udp.udp_bytes_sent = 1, .udp.udp_bytes_received = 1,
                                    .first = 123456789, .ct = 123456790, .tcp.retransmit = 1, .protocol = 6}; 
        ebpf_update_tables(obj, &common_idx, &values);

        sleep(60);

        // Separator between load and result
        fprintf(stdout, "\n=================  READ DATA =================\n\n");
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, NETDATA_SOCKET_COUNTER);
        if (!ret) {

            ret += netdata_read_socket(&common_idx, obj, ebpf_nprocs);

            ret += netdata_read_local_ports(obj);

            if (!ret)
                fprintf(stdout, "All stored data were retrieved with success!\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }

    socket_bpf__destroy(obj);

    return ret;
load_error:
    fprintf(stderr, "Cannot open or load BPF object\n");
    return 2;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  0 },
        {"probe",       no_argument,    0,  0 },
        {"tracepoint",  no_argument,    0,  0 },
        {"trampoline",  no_argument,    0,  0 },
        {"pid",         required_argument,    0,  0 },
        {0,             no_argument, 0, 0}
    };

    int selector = NETDATA_MODE_TRAMPOLINE;
    int option_index = 0;
    enum netdata_apps_level map_level = NETDATA_APPS_LEVEL_REAL_PARENT;
    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case NETDATA_EBPF_CORE_IDX_HELP: {
                          ebpf_core_print_help(argv[0], "socket", 1, 1);
                          exit(0);
                      }
            case NETDATA_EBPF_CORE_IDX_PROBE: {
                          selector = NETDATA_MODE_PROBE;
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_TRACEPOINT: {
                          selector = NETDATA_MODE_PROBE;
                          fprintf(stdout, "This specific software does not have tracepoint, using kprobe instead\n");
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_TRAMPOLINE: {
                          selector = NETDATA_MODE_TRAMPOLINE;
                          break;
                      }
            case NETDATA_EBPF_CORE_IDX_PID: {
                          int user_input = (int)strtol(optarg, NULL, 10);
                          map_level = ebpf_check_map_level(user_input);
                          break;
                      }
            default: {
                         break;
                     }
        }
    }

    // Adjust memory
    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_print(netdata_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    int stop_software = 0;
    while (stop_software < 2) {
        if (ebpf_socket_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    return 0;
}

