#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>

#define _GNU_SOURCE         /* See feature_test_macros(7) */
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"

#include "oomkill.skel.h"

static inline int ebpf_load_and_attach(struct oomkill_bpf *obj)
{
    int ret = oomkill_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    } 

    ret = oomkill_bpf__attach(obj);
    if (!ret) {
        fprintf(stdout, "OOMkill loaded with success\n");
    }

    return ret;
}

static void ebpf_update_table(int global, int ebpf_nprocs)
{
    int idx = 0;
    // PERCPU_HASH requires num_cpus * roundup(value_size, 8) bytes
    uint64_t *per_cpu = calloc(ebpf_nprocs, sizeof(uint64_t));
    if (!per_cpu) {
        fprintf(stderr, "Cannot allocate per-cpu buffer.");
        return;
    }

    int i;
    for (i = 0; i < ebpf_nprocs; i++)
        ((unsigned char *)per_cpu)[i * sizeof(uint64_t)] = 1;

    int ret = bpf_map_update_elem(global, &idx, per_cpu, 0);
    if (ret)
        fprintf(stderr, "Cannot insert value to global table.");

    free(per_cpu);
}

static int oomkill_read_array(int fd, int ebpf_nprocs)
{
    // PERCPU_HASH requires num_cpus * roundup(value_size, 8) bytes
    uint64_t *per_cpu = calloc(ebpf_nprocs, sizeof(uint64_t));
    if (!per_cpu)
        return 2;

    unsigned char counter = 0;
    int idx = 0;
    if (!bpf_map_lookup_elem(fd, &idx, per_cpu)) {
        int j;
        for (j = 0; j < ebpf_nprocs; j++)
            counter += ((unsigned char *)per_cpu)[j * sizeof(uint64_t)];
    }

    free(per_cpu);

    if (counter) {
        fprintf(stdout, "Data stored with success\n");
        return 0;
    }

    return 2;
}

static int ebpf_oomkill_tests()
{
    struct oomkill_bpf *obj = NULL;
    int ebpf_nprocs = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ebpf_nprocs < 0)
        ebpf_nprocs = NETDATA_CORE_PROCESS_NUMBER;

    obj = oomkill_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    int ret = ebpf_load_and_attach(obj);
    if (!ret) {
        int fd = bpf_map__fd(obj->maps.tbl_oomkill);
        ebpf_update_table(fd, ebpf_nprocs);

        ret = oomkill_read_array(fd, ebpf_nprocs);
        if (ret)
            fprintf(stderr, "Cannot read global table\n");
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }

    oomkill_bpf__destroy(obj);

    return ret;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",        no_argument,    0,  'h' },
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while (1) {
        int c = getopt_long(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h': {
                          ebpf_tracepoint_help("OOMkill");
                          exit(0);
                      }
            default: {
                         break;
                     }
        }
    }

    int ret = netdata_ebf_memlock_limit();
    if (ret) {
        fprintf(stderr, "Cannot increase memory: error = %d\n", ret);
        return 1;
    }

    libbpf_set_print(netdata_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    return ebpf_oomkill_tests();
}

