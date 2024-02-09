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

#include "networkviewer.skel.h"

// Socket functions
char *function_list[] = { "inet_csk_accept",
                          "tcp_retransmit_skb",
                          "tcp_cleanup_rbuf",
                          "tcp_close",
                          "udp_recvmsg",
                          "tcp_sendmsg",
                          "udp_sendmsg",
                          "tcp_v4_connect",
                          "tcp_v6_connect",
                          "tcp_set_state"};

#define NETDATA_IPV4 4
#define NETDATA_IPV6 6

static int ebpf_attach_probes(struct networkviewer_bpf *obj)
{
    obj->links.netdata_nv_inet_csk_accept_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_inet_csk_accept_kretprobe,
                                                                              true, function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);
    int ret = libbpf_get_error(obj->links.netdata_nv_inet_csk_accept_kretprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_v4_connect_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_v4_connect_kprobe,
                                                                             false, function_list[NETDATA_FCNT_TCP_V4_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_v4_connect_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_v6_connect_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_v6_connect_kprobe,
                                                                          false, function_list[NETDATA_FCNT_TCP_V6_CONNECT]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_v6_connect_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_retransmit_skb_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_retransmit_skb_kprobe,
                                                                              false, function_list[NETDATA_FCNT_TCP_RETRANSMIT]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_retransmit_skb_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_cleanup_rbuf_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_cleanup_rbuf_kprobe,
                                                                            false, function_list[NETDATA_FCNT_CLEANUP_RBUF]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_cleanup_rbuf_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_udp_recvmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_udp_recvmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_RECEVMSG]);
    ret = libbpf_get_error(obj->links.netdata_nv_udp_recvmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_TCP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_udp_sendmsg_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_udp_sendmsg_kprobe,
                                                                       false, function_list[NETDATA_FCNT_UDP_SENDMSG]);
    ret = libbpf_get_error(obj->links.netdata_nv_udp_sendmsg_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_nv_tcp_set_state_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_nv_tcp_set_state_kprobe,
                                                                          true, function_list[NETDATA_FCNT_TCP_SET_STATE]);
    ret = libbpf_get_error(obj->links.netdata_nv_tcp_set_state_kprobe);
    if (ret)
        return -1;

    return 0;
}

static void ebpf_disable_probes(struct networkviewer_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_nv_inet_csk_accept_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_v4_connect_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_v6_connect_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_retransmit_skb_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_cleanup_rbuf_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_udp_recvmsg_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_sendmsg_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_udp_sendmsg_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_set_state_kprobe, false);
}

static void ebpf_disable_trampoline(struct networkviewer_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_nv_inet_csk_accept_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_v4_connect_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_v6_connect_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_retransmit_skb_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_cleanup_rbuf_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_udp_recvmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_udp_sendmsg_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_nv_tcp_set_state_fentry, false);
}

static void ebpf_set_trampoline_target(struct networkviewer_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_nv_inet_csk_accept_fexit, 0,
                                   function_list[NETDATA_FCNT_INET_CSK_ACCEPT]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_v4_connect_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_V4_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_v6_connect_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_V6_CONNECT]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_retransmit_skb_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_RETRANSMIT]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_cleanup_rbuf_fentry, 0,
                                   function_list[NETDATA_FCNT_CLEANUP_RBUF]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_udp_recvmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_RECEVMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_udp_sendmsg_fentry, 0,
                                   function_list[NETDATA_FCNT_UDP_SENDMSG]);

    bpf_program__set_attach_target(obj->progs.netdata_nv_tcp_set_state_fentry, 0,
                                   function_list[NETDATA_FCNT_TCP_SET_STATE]);
}

static inline int ebpf_load_and_attach(struct networkviewer_bpf *obj, int selector)
{
    // Adjust memory
    int ret;
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);
    }

    ret = networkviewer_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    if (!selector) {
        ret = networkviewer_bpf__attach(obj);
    } else {
        ret = ebpf_attach_probes(obj);
    }
    
    if (!ret) {
        fprintf(stdout, "Socket loaded with success\n");
    }

    return ret;
}

static int netdata_read_socket(struct networkviewer_bpf *obj, int ebpf_nprocs)
{
    netdata_socket_t stored[ebpf_nprocs];

    uint64_t counter = 0;
    int fd = bpf_map__fd(obj->maps.tbl_nv_socket);
    netdata_nv_idx_t key =  { };
    netdata_nv_idx_t next_key = { };
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
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


int ebpf_networkviewer_tests(int selector, enum netdata_apps_level map_level)
{
    struct networkviewer_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = NETDATA_CORE_PROCESS_NUMBER;

    obj = networkviewer_bpf__open();
    if (!obj) {
        goto load_error;
    }

    obj->rodata->collect_everything = true;

    int ret = ebpf_load_and_attach(obj, selector);
    if (ret && selector != NETDATA_MODE_PROBE) {
        networkviewer_bpf__destroy(obj);

        obj = networkviewer_bpf__open();
        if (!obj) {
            goto load_error;
        }

        selector = NETDATA_MODE_PROBE;
        ret = ebpf_load_and_attach(obj, selector);
    }

    if (!ret) {
        ebpf_core_fill_ctrl(obj->maps.nv_ctrl, map_level);

        sleep(60);

        // Separator between load and result
        fprintf(stdout, "\n=================  READ DATA =================\n\n");
        if (!ret) {

            ret += netdata_read_socket(obj, ebpf_nprocs);

            if (!ret)
                fprintf(stdout, "All stored data were retrieved with success!\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }


    networkviewer_bpf__destroy(obj);

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
                          ebpf_core_print_help(argv[0], "networkviewer", 1, 1);
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
        if (ebpf_networkviewer_tests(selector, map_level) && !stop_software) {
            selector = 1;
            stop_software++;
        } else
            stop_software = 2;
    }

    return 0;
}

