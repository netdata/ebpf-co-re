// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_CORE_COMMON_H_
#define _NETDATA_CORE_COMMON_H_ 1

#include "netdata_defs.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum NETDATA_EBPF_CORE_IDX {
    NETDATA_EBPF_CORE_IDX_HELP,
    NETDATA_EBPF_CORE_IDX_PROBE,
    NETDATA_EBPF_CORE_IDX_TRACEPOINT,
    NETDATA_EBPF_CORE_IDX_TRAMPOLINE,
    NETDATA_EBPF_CORE_IDX_PID
};

#define NETDATA_EBPF_CORE_MIN_STORE 128

#define NETDATA_EBPF_KERNEL_5_19_0 332544

#define NETDATA_CORE_PROCESS_NUMBER 4096

typedef struct ebpf_specify_name {
    char *program_name;
    char *function_to_attach;
    size_t length;
    char *optional;
    bool retprobe;
} ebpf_specify_name_t;

/**
 * Update names
 *
 * Open /proc/kallsyms and update the name for specific function
 *
 * THIS FUNCTION IS ALSO PRESENT IN `kernel-collector` REPO, AS SOON IT IS TRANSFERRED FROM TEST TO
 * COMMON FILE, IT NEEDS TO BE REMOVED FROM HERE.
 *
 * @param names    vector with names to modify target.
 */
static inline void ebpf_update_names(ebpf_specify_name_t *names)
{
    if (!names)
        return;

    char line[256];
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp)
        return;

    int total;
    for (total = 0; names[total].program_name; total++);

    if (!total)
         return;

    char *data;
    int all_filled = 0;
    while ( (data = fgets(line, 255, fp))) {
        data += 19;
        ebpf_specify_name_t *name;
        int i;
        for (i = 0, name = &names[i]; name->program_name; i++, name = &names[i]) {
            if (name->optional)
                continue;

            char *end = strchr(data, ' ');
            if (!end)
                end = strchr(data, '\n');

            if (end)
                *end = '\0';

            if (!strcmp(name->function_to_attach, data)) {
                all_filled++;
                name->optional = strdup(data);
                break;
            }
        }

        if (all_filled == total)
            break;
    }

    fclose(fp);
}

/**
 * Fill Control table
 *
 * Fill control table with data allowing eBPF collectors to store specific data.
 *
 * @param map the loaded map
 * @param map_level how are we going to store PIDs
 */
static inline void ebpf_core_fill_ctrl(struct bpf_map *map, enum netdata_apps_level map_level)
{
    int fd = bpf_map__fd(map);

    unsigned int i, end = bpf_map__max_entries(map);
    uint64_t values[NETDATA_CONTROLLER_END] = { 1, map_level, 0, 0, 0, 0};
    for (i = 0; i < end; i++) {
         int ret = bpf_map_update_elem(fd, &i, &values[i], 0);
         if (ret)
             fprintf(stderr, "\"error\" : \"Add key(%u) for controller table failed.\",", i);
    }
}

/**
 * Check map level
 *
 * Verify if the given value is one of expected values to store inside hash table
 *
 * @param value is the value given
 *
 * @return It returns the given value when there is no error, or it returns the default when value is
 * invalid.
 */
static inline enum netdata_apps_level ebpf_check_map_level(int value)
{
    if (value < NETDATA_APPS_LEVEL_REAL_PARENT || value > NETDATA_APPS_LEVEL_IGNORE) {
        fprintf(stderr, "\"Error\" : \"Value given (%d) is not valid, resetting to default 0 (Real Parent).\",\n",
                value);
        value = NETDATA_APPS_LEVEL_REAL_PARENT;
   }

    return value;
}

static inline void ebpf_core_print_help(char *name, char *info, int has_trampoline, int has_integration) {
    fprintf(stdout, "%s tests if it is possible to monitor %s on host\n\n"
                    "The following options are available:\n\n"
                    "--help       : Prints this help.\n"
                    "--probe      : Use probe and do no try to use trampolines (fentry/fexit).\n"
                    "--tracepoint : Use tracepoint.\n"
                    , name, info);
    if (has_trampoline)
        fprintf(stdout, "--trampoline : Try to use trampoline(fentry/fexit). If this is not possible"
                        " probes will be used.\n");
    if (has_integration)
        fprintf(stdout, "--pid        : Store PID according argument given. Values can be:\n"
                        "\t\t0 - Real parents\n\t\t1 - Parents\n\t\t2 - All PIDs\n\t\t3 - Ignore PIDs\n");
}

/**
 * Liibbpf vfprintf
 *
 * We use this function to filter separate software error from libbpf errors.
 *
 * @param level message level.
 * @param format is the second argument used with vfprintf;
 * @param args is tthe list of args used with format.
 *
 * @return it returns number of bytes written.
 */
static inline int netdata_libbpf_vfprintf(enum libbpf_print_level level, const char *format, va_list args)
{
    // FOR DEVELOPERS: To avoid generation of a lot of messages we are not printing all debug messages.
    // When some software is developed, we strongly suggest to comment next two lines to take a look 
    // in all messages.
    if (level == LIBBPF_DEBUG)
        return 0;

    static FILE *libbpf_err = NULL;
    if (!libbpf_err)  {
        libbpf_err = fopen("libbpf.log", "a");
        if (!libbpf_err) {
            fprintf(stderr, "Cannot open libbpf.log");
            exit(1);
        }
    }

    return vfprintf(libbpf_err, format, args);
}

#endif /* _NETDATA_CORE_COMMON_H_ */

