#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

#include "netdata_defs.h"
#include "netdata_core_common.h"
#include "netdata_tests.h"

#include "disk.skel.h"

typedef struct block_key {
    uint32_t bin;
    uint32_t dev;
} block_key_t;

typedef struct disk_attach_links {
    struct bpf_link *links[8];
    size_t count;
} disk_attach_links_t;

static int disk_symbol_in_kallsyms(const char *name)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    char line[512];
    char symbol[256];
    int found = 0;

    if (!f)
        return 1;

    while (!found && fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%*x %*c %255s", symbol) == 1)
            found = !strcmp(symbol, name);
    }
    fclose(f);
    return found;
}

static int disk_attach_target(disk_attach_links_t *links, struct bpf_program *prog, const char *target)
{
    struct bpf_link *link;
    int err;

    if (links->count >= sizeof(links->links) / sizeof(links->links[0]))
        return -ENOSPC;

    link = bpf_program__attach_kprobe(prog, false, target);
    err = libbpf_get_error(link);
    if (err)
        return err;

    links->links[links->count++] = link;
    return 0;
}

static int disk_attach_request_probes(struct disk_bpf *obj, disk_attach_links_t *links)
{
    struct bpf_program *issue = obj->progs.netdata_block_rq_issue;
    struct bpf_program *complete = obj->progs.netdata_block_rq_complete;
    int have_start = disk_symbol_in_kallsyms("blk_mq_start_request");
    int have_legacy_start = disk_symbol_in_kallsyms("blk_start_request");
    int have_end = disk_symbol_in_kallsyms("blk_mq_end_request");
    int have_internal_end = disk_symbol_in_kallsyms("__blk_mq_end_request");
    int have_free = disk_symbol_in_kallsyms("blk_mq_free_request");
    int issue_attached = 0;
    int completion_attached = 0;
    int secondary_attached = 0;
    int err = -ENOENT;
    int completion_error = -ENOENT;

    if (have_start) {
        err = disk_attach_target(links, issue, "blk_mq_start_request");
        issue_attached = !err;
    }
    if (!issue_attached && have_legacy_start) {
        err = disk_attach_target(links, issue, "blk_start_request");
        issue_attached = !err;
    }
    if (!issue_attached)
        return err;

    if (have_end) {
        completion_error = disk_attach_target(links, complete, "blk_mq_end_request");
        completion_attached = !completion_error;
    }
    if (have_internal_end) {
        err = disk_attach_target(links, obj->progs.netdata_block_rq_complete_internal,
                                 "__blk_mq_end_request");
        secondary_attached = !err;
        if (err)
            completion_error = err;
    }
    if (!secondary_attached && have_free) {
        err = disk_attach_target(links, obj->progs.netdata_block_rq_complete_free,
                                 "blk_mq_free_request");
        secondary_attached = !err;
        if (err)
            completion_error = err;
    }
    // SCSI can bypass the primary path, but a working primary still collects other disks.
    if (!completion_attached && !secondary_attached)
        return completion_error;
    if (!secondary_attached)
        fprintf(stderr, "Disk secondary completion probes unavailable; some device latency may be missed\n");

    if (disk_symbol_in_kallsyms("blk_complete_request")) {
        (void)disk_attach_target(links, obj->progs.netdata_blk_complete_request,
                                 "blk_complete_request");
    }

    return 0;
}

static int disk_histogram_total(int fd, int possible_cpus, uint64_t *total)
{
    block_key_t key = { }, next_key = { };
    uint64_t *percpu;
    int ret;

    percpu = calloc((size_t)possible_cpus, sizeof(*percpu));
    if (!percpu)
        return -ENOMEM;

    *total = 0;
    ret = bpf_map_get_next_key(fd, NULL, &next_key);
    while (!ret) {
        int cpu;
        if (!bpf_map_lookup_elem(fd, &next_key, percpu)) {
            for (cpu = 0; cpu < possible_cpus; cpu++)
                *total += percpu[cpu];
        }
        key = next_key;
        ret = bpf_map_get_next_key(fd, &key, &next_key);
    }

    free(percpu);
    return 0;
}

static int disk_generate_io(void)
{
    char path[] = "/var/tmp/netdata-disk-core-XXXXXX";
    void *buffer = NULL;
    int fd = -1;
    int err = 0;
    size_t i;
    struct stat st;

    fd = mkstemp(path);
    if (fd < 0)
        return -errno;

    if (fstat(fd, &st)) {
        err = -errno;
        goto out;
    }
    if (major(st.st_dev) == 0) {
        err = -EOPNOTSUPP;
        goto out;
    }

    if (posix_memalign(&buffer, 4096, 4096)) {
        err = -ENOMEM;
        goto out;
    }
    memset(buffer, 0x5a, 4096);

    for (i = 0; i < 256; i++) {
        ssize_t written = write(fd, buffer, 4096);
        if (written != 4096) {
            err = written < 0 ? -errno : -EIO;
            goto out;
        }
    }
    if (fsync(fd))
        err = -errno;

out:
    free(buffer);
    if (fd >= 0)
        close(fd);
    unlink(path);
    return err;
}

static inline int ebpf_load_and_attach(struct disk_bpf *obj, disk_attach_links_t *links)
{
    int ret = bpf_program__set_autoload(obj->progs.netdata_blk_complete_request,
                                        disk_symbol_in_kallsyms("blk_complete_request"));
    if (ret)
        return ret;

    ret = disk_bpf__load(obj);
    if (ret) {
        fprintf(stderr, "failed to load BPF object: %d\n", ret);
        return -1;
    }

    ret = disk_attach_request_probes(obj, links);
    if (!ret) {
        fprintf(stdout, "Disk loaded with success\n");
    }

    return ret;
}

static int ebpf_disk_tests()
{
    struct disk_bpf *obj = NULL;
    disk_attach_links_t links = { };
    int possible_cpus = libbpf_num_possible_cpus();
    uint64_t before = 0, after = 0;

    obj = disk_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot open or load BPF object\n");

        return 2;
    }

    if (possible_cpus <= 0) {
        disk_bpf__destroy(obj);
        return 2;
    }

    if (bpf_map__key_size(obj->maps.tbl_disk_iocall) != sizeof(block_key_t)) {
        fprintf(stderr, "Disk histogram key size does not match the userspace layout\n");
        disk_bpf__destroy(obj);
        return 2;
    }

    int ret = ebpf_load_and_attach(obj, &links);
    if (!ret) {
        int io_skipped = 0;
        int fd = bpf_map__fd(obj->maps.tbl_disk_iocall);
        ret = disk_histogram_total(fd, possible_cpus, &before);
        if (!ret)
            ret = disk_generate_io();
        if (ret == -EOPNOTSUPP) {
            fprintf(stdout, "Disk I/O check skipped: /var/tmp is not on a block-backed filesystem\n");
            ret = 0;
            io_skipped = 1;
        }
        if (!ret && !io_skipped) {
            struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
            int attempts;
            for (attempts = 0; attempts < 20; attempts++) {
                nanosleep(&delay, NULL);
                ret = disk_histogram_total(fd, possible_cpus, &after);
                if (ret || after > before)
                    break;
            }
        }
        if (!ret && !io_skipped && after > before)
            fprintf(stdout, "Disk request latency recorded successfully\n");
        else if (!ret && !io_skipped) {
            fprintf(stderr, "No disk request latency was recorded during the I/O check\n");
            ret = 2;
        }
    } else {
        ret = 3;
        fprintf(stderr ,"%s", NETDATA_CORE_DEFAULT_ERROR);
    }

    while (links.count)
        bpf_link__destroy(links.links[--links.count]);
    disk_bpf__destroy(obj);

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
                          ebpf_tracepoint_help("Disk");
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

    return ebpf_disk_tests();
}

