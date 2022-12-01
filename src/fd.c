#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#include <linux/version.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"
#include "netdata_fd.h"

#include "fd.skel.h"

// Alma Linux modified internal name, this structure was brought for it.
static ebpf_specify_name_t close_names[] = { {.program_name = "netdata_close_fd_kretprobe",
                                              .function_to_attach = "close_fd",
                                              .length = 8,
                                              .optional = NULL,
                                              .retprobe = 0},
                                             {.program_name = "netdata___close_fd_kretprobe",
                                              .function_to_attach = "__close_fd",
                                              .length = 10,
                                              .optional = NULL,
                                              .retprobe = 0},
                                             {.program_name = NULL}};

static ebpf_specify_name_t open_names[] = { {.program_name = "netdata_sys_open_kprobe",
                                              .function_to_attach = "do_sys_openat2",
                                              .length = 14,
                                              .optional = NULL,
                                              .retprobe = 0},
                                             {.program_name = "netdata_sys_open_kprobe",
                                              .function_to_attach = "do_sys_open",
                                              .length = 11,
                                              .optional = NULL,
                                              .retprobe = 0},
                                             {.program_name = NULL}};

char *function_list[] = { NULL,
                          NULL,
                          "release_task"
                        };
// This preprocessor is defined here, because it is not useful in kernel-colector
#define NETDATA_FD_RELEASE_TASK 2

static inline void ebpf_disable_probes(struct fd_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_sys_open_kprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_sys_open_kretprobe, false);
    bpf_program__set_autoload(obj->progs.netdata_release_task_fd_kprobe, false);
    if (close_names[0].optional) {
        bpf_program__set_autoload(obj->progs.netdata___close_fd_kretprobe, false);
        bpf_program__set_autoload(obj->progs.netdata___close_fd_kprobe, false);
        bpf_program__set_autoload(obj->progs.netdata_close_fd_kprobe, false);
    } else {
        bpf_program__set_autoload(obj->progs.netdata___close_fd_kprobe, false);
        bpf_program__set_autoload(obj->progs.netdata_close_fd_kretprobe, false);
        bpf_program__set_autoload(obj->progs.netdata_close_fd_kprobe, false);
    }
}

static inline void ebpf_disable_specific_probes(struct fd_bpf *obj)
{
    if (close_names[0].optional) {
        bpf_program__set_autoload(obj->progs.netdata___close_fd_kretprobe, false);
        bpf_program__set_autoload(obj->progs.netdata___close_fd_kprobe, false);
    } else {
        bpf_program__set_autoload(obj->progs.netdata_close_fd_kretprobe, false);
        bpf_program__set_autoload(obj->progs.netdata_close_fd_kprobe, false);
    }
}

static inline void ebpf_disable_trampoline(struct fd_bpf *obj)
{
    bpf_program__set_autoload(obj->progs.netdata_sys_open_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_sys_open_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_close_fd_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata_close_fd_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata___close_fd_fentry, false);
    bpf_program__set_autoload(obj->progs.netdata___close_fd_fexit, false);
    bpf_program__set_autoload(obj->progs.netdata_release_task_fd_fentry, false);
}

static inline void ebpf_disable_specific_trampoline(struct fd_bpf *obj)
{
    if (close_names[0].optional) {
        bpf_program__set_autoload(obj->progs.netdata___close_fd_fentry, false);
        bpf_program__set_autoload(obj->progs.netdata___close_fd_fexit, false);
    } else {
        bpf_program__set_autoload(obj->progs.netdata_close_fd_fentry, false);
        bpf_program__set_autoload(obj->progs.netdata_close_fd_fexit, false);
    }
}

static void ebpf_set_trampoline_target(struct fd_bpf *obj)
{
    bpf_program__set_attach_target(obj->progs.netdata_sys_open_fentry, 0,
                                   function_list[NETDATA_FD_OPEN]);

    bpf_program__set_attach_target(obj->progs.netdata_sys_open_fexit, 0,
                                   function_list[NETDATA_FD_OPEN]);

    bpf_program__set_attach_target(obj->progs.netdata_release_task_fd_fentry, 0,
                                   function_list[NETDATA_FD_RELEASE_TASK]);

    if (close_names[0].optional) {
        bpf_program__set_attach_target(obj->progs.netdata_close_fd_fentry, 0,
                                       function_list[NETDATA_FD_CLOSE]);
        bpf_program__set_attach_target(obj->progs.netdata_close_fd_fexit, 0,
                                       function_list[NETDATA_FD_CLOSE]);
    } else {
        bpf_program__set_attach_target(obj->progs.netdata___close_fd_fentry, 0,
                                       function_list[NETDATA_FD_CLOSE]);
        bpf_program__set_attach_target(obj->progs.netdata___close_fd_fexit, 0,
                                       function_list[NETDATA_FD_CLOSE]);
    }
}

static int ebpf_attach_probes(struct fd_bpf *obj)
{
    obj->links.netdata_sys_open_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_sys_open_kprobe,
                                                                    false, function_list[NETDATA_FD_OPEN]);
    int ret = libbpf_get_error(obj->links.netdata_sys_open_kprobe);
    if (ret)
        return -1;

    obj->links.netdata_sys_open_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_sys_open_kretprobe,
                                                                       true, function_list[NETDATA_FD_OPEN]);
    ret = libbpf_get_error(obj->links.netdata_sys_open_kretprobe);
    if (ret)
        return -1;

    if (close_names[0].optional) {
        obj->links.netdata_close_fd_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata_close_fd_kretprobe,
                                                                           true, function_list[NETDATA_FD_CLOSE]);
        ret = libbpf_get_error(obj->links.netdata_close_fd_kretprobe);
        if (ret)
            return -1;

        obj->links.netdata_close_fd_kprobe = bpf_program__attach_kprobe(obj->progs.netdata_close_fd_kprobe,
                                                                        false, function_list[NETDATA_FD_CLOSE]);
        ret = libbpf_get_error(obj->links.netdata_close_fd_kprobe);
        if (ret)
            return -1;
    } else {
        obj->links.netdata___close_fd_kretprobe = bpf_program__attach_kprobe(obj->progs.netdata___close_fd_kretprobe,
                                                                             true, function_list[NETDATA_FD_CLOSE]);
        ret = libbpf_get_error(obj->links.netdata___close_fd_kretprobe);
        if (ret)
            return -1;

        obj->links.netdata___close_fd_kprobe = bpf_program__attach_kprobe(obj->progs.netdata___close_fd_kprobe,
                                                                          false, function_list[NETDATA_FD_CLOSE]);
        ret = libbpf_get_error(obj->links.netdata___close_fd_kprobe);
        if (ret)
            return -1;
    }

    return 0;
}

static inline int ebpf_load_and_attach(struct fd_bpf *obj, int selector)
{
    if (!selector) { // trampoline
        ebpf_disable_probes(obj);
        ebpf_disable_specific_trampoline(obj);

        ebpf_set_trampoline_target(obj);
    } else if (selector == NETDATA_MODE_PROBE) {  // kprobe
        ebpf_disable_trampoline(obj);

        ebpf_disable_specific_probes(obj);
    }

    int ret = fd_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    if (!selector)
        ret = fd_bpf__attach(obj);
    else
        ret = ebpf_attach_probes(obj);

    if (!ret) {
        fprintf(stdout, "File descriptor loaded with success\n");
    }

    return ret;
}

static int fd_read_apps_array(int fd, int ebpf_nprocs, uint32_t my_pid)
{
    struct netdata_fd_stat_t *stored = calloc((size_t)ebpf_nprocs, sizeof(struct netdata_fd_stat_t));
    if (!stored)
        return 2;

    int key, next_key;
    key = next_key = 0;
    uint64_t counter = 0;
    while (!bpf_map_get_next_key(fd, &key, &next_key)) {
        if (!bpf_map_lookup_elem(fd, &key, stored)) {
            counter++;
        }
        memset(stored, 0, ebpf_nprocs * sizeof(struct netdata_fd_stat_t));

        key = next_key;
    }

    free(stored);

    if (counter) {
        fprintf(stdout, "Apps data stored with success. It collected %lu pids\n", counter);
        return 0;
    }

    return 2;
}

static pid_t ebpf_update_tables(int global, int apps)
{
    pid_t pid = ebpf_fill_global(global);

    struct netdata_fd_stat_t stats = { .open_call = 1, .close_call = 1,
                                       .open_err = 1, .close_err = 1};

    uint32_t idx = (uint32_t)pid;
    int ret = bpf_map_update_elem(apps, &idx, &stats, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to apps table.");

    return pid;
}

static int ebpf_fd_tests(int selector, enum netdata_apps_level map_level)
{
    struct fd_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);

    obj = fd_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj, selector);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.fd_ctrl);
        ebpf_core_fill_ctrl(obj->maps.fd_ctrl, map_level);

        fd = bpf_map__fd(obj->maps.tbl_fd_global);
        int fd2 = bpf_map__fd(obj->maps.tbl_fd_pid);
        pid_t my_pid = ebpf_update_tables(fd, fd2);

        sleep(60);
        ret =  ebpf_read_global_array(fd, ebpf_nprocs, 1);
        if (!ret) {
            ret = fd_read_apps_array(fd2, ebpf_nprocs, (uint32_t)my_pid);
            if (ret)
                fprintf(stderr, "Cannot read apps table\n");
        } else
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }

    fd_bpf__destroy(obj);

    return ret;
}

static void ebpf_set_fd_names()
{
    ebpf_update_names(close_names);

    int i;
    for (i = 0; close_names[i].program_name ; i++) {
        if (close_names[i].optional) {
            function_list[NETDATA_FD_CLOSE] = close_names[i].optional;
            break;
        }
    }

    ebpf_update_names(open_names);
    for (i = 0; open_names[i].program_name ; i++) {
        if (open_names[i].optional) {
          function_list[NETDATA_FD_OPEN] = open_names[i].optional;
            break;
        }
    }
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  0 },
        {"probe",       no_argument,    0,  0 },
        {"tracepoint",  no_argument,    0,  0 },
        {"trampoline",  no_argument,    0,  0 },
        {"pid",         required_argument,    0,  0 },
        {0, 0, 0, 0}
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
                          ebpf_core_print_help(argv[0], "file_descriptor", 1, 1);
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

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    ebpf_set_fd_names();
    if (!function_list[NETDATA_FD_CLOSE] || !function_list[NETDATA_FD_OPEN]) {
        fprintf(stderr, "Cannot find all necessary functions\n");
        return 2;
    }

    struct btf *bf = NULL;
    if (!selector) {
        bf = netdata_parse_btf_file((const char *)NETDATA_BTF_FILE);
        if (bf) {
            selector = ebpf_find_functions(bf, selector, function_list, NETDATA_FD_ACTIONS);
            btf__free(bf);
        }
    }

    return ebpf_fd_tests(selector, map_level);
}

