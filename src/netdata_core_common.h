// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_CORE_COMMON_H_
#define _NETDATA_CORE_COMMON_H_ 1

#include "netdata_defs.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>

enum NETDATA_EBPF_CORE_IDX {
    NETDATA_EBPF_CORE_IDX_HELP,
    NETDATA_EBPF_CORE_IDX_PROBE,
    NETDATA_EBPF_CORE_IDX_TRACEPOINT,
    NETDATA_EBPF_CORE_IDX_TRAMPOLINE,
    NETDATA_EBPF_CORE_IDX_PID
};

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
    uint32_t values[NETDATA_CONTROLLER_END] = { 1, map_level};
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
    if (value < NETDATA_APPS_LEVEL_REAL_PARENT || value > NETDATA_APPS_LEVEL_ALL) {
        fprintf(stderr, "\"Error\" : \"Value given (%d) is not valid, resetting to default 0 (Real Parent).\",\n",
                value);
        value = NETDATA_APPS_LEVEL_REAL_PARENT;
   }

    return value;
}

#endif /* _NETDATA_CORE_COMMON_H_ */

