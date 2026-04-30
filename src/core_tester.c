#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "netdata_core_loader.h"
/* BPF_MAP_TYPE_RINGBUF requires kernel >= 5.8 (version code 329728). */
#if MY_LINUX_VERSION_CODE >= 329728
#include "cachestat_buffer.skel.h"
#include "dc_buffer.skel.h"
#include "dns_buffer.skel.h"
#include "fd_buffer.skel.h"
#include "oomkill_buffer.skel.h"
#include "process_buffer.skel.h"
#include "shm_buffer.skel.h"
#include "swap_buffer.skel.h"
#include "vfs_buffer.skel.h"
#endif /* MY_LINUX_VERSION_CODE >= 329728 */

#define MODE_NONE        0U
#define MODE_PROBE       (1U << 0)
#define MODE_TRACEPOINT  (1U << 1)
#define MODE_TRAMPOLINE  (1U << 2)

#define PID_MIN 0
#define PID_MAX 3

enum selection_bits {
    SELECT_CACHESTAT     = 1ULL << 0,
    SELECT_DC            = 1ULL << 1,
    SELECT_DISK          = 1ULL << 2,
    SELECT_DNS           = 1ULL << 3,
    SELECT_FD            = 1ULL << 4,
    SELECT_HARDIRQ       = 1ULL << 5,
    SELECT_MDFLUSH       = 1ULL << 6,
    SELECT_MOUNT         = 1ULL << 7,
    SELECT_NETWORKVIEWER = 1ULL << 8,
    SELECT_OOMKILL       = 1ULL << 9,
    SELECT_PROCESS       = 1ULL << 10,
    SELECT_SHM           = 1ULL << 11,
    SELECT_SOCKET        = 1ULL << 12,
    SELECT_SOFTIRQ       = 1ULL << 13,
    SELECT_SWAP          = 1ULL << 14,
    SELECT_SYNC          = 1ULL << 15,
    SELECT_VFS           = 1ULL << 16,
    SELECT_NFS           = 1ULL << 17,
    SELECT_EXT4          = 1ULL << 18,
    SELECT_BTRFS         = 1ULL << 19,
    SELECT_XFS           = 1ULL << 20,
    SELECT_ZFS           = 1ULL << 21,
    SELECT_FILESYSTEM    = SELECT_NFS | SELECT_EXT4 | SELECT_BTRFS | SELECT_XFS,
    SELECT_ALL_NON_FILESYSTEM = SELECT_CACHESTAT | SELECT_DC | SELECT_DISK | SELECT_DNS |
                                SELECT_FD | SELECT_HARDIRQ | SELECT_MDFLUSH | SELECT_MOUNT |
                                SELECT_NETWORKVIEWER | SELECT_OOMKILL | SELECT_PROCESS |
                                SELECT_SHM | SELECT_SOCKET | SELECT_SOFTIRQ | SELECT_SWAP |
                                SELECT_SYNC | SELECT_VFS
};

enum option_ids {
    OPT_PID = 1000,
    OPT_DNS_PORT,
    OPT_ITERATION,
    OPT_TESTS_DIR,
    OPT_LOG_PATH,
    OPT_ALL,
    OPT_CACHESTAT,
    OPT_DC,
    OPT_DISK,
    OPT_DNS,
    OPT_FD,
    OPT_HARDIRQ,
    OPT_MDFLUSH,
    OPT_MOUNT,
    OPT_NETWORKVIEWER,
    OPT_OOMKILL,
    OPT_PROCESS,
    OPT_SHM,
    OPT_SOCKET,
    OPT_SOFTIRQ,
    OPT_SWAP,
    OPT_SYNC,
    OPT_VFS,
    OPT_FILESYSTEM,
    OPT_NFS,
    OPT_EXT4,
    OPT_BTRFS,
    OPT_XFS,
    OPT_ZFS,
    OPT_BUFFER
};

typedef netdata_loader_fn_t aggregate_entrypoint_t;

typedef struct aggregate_test_case {
    const char *name;
    const char *binary;
    aggregate_entrypoint_t entrypoint;
    const char *extra_arg;
    const char *unavailable_reason;
    uint64_t selection_bit;
    unsigned modes;
    int emit_mode_arg;
    int pid_supported;
    int buffer_supported;
    const char *buffer_ctrl;
} aggregate_test_case_t;

typedef struct aggregate_result {
    char name[32];
    char binary[32];
    char mode[16];
    int pid;
    char status[16];
    int exit_code;
    char command[256];
    char detail[256];
    char maps_json[4096];
} aggregate_result_t;

typedef struct aggregate_state {
    const char *dns_ports;
    const char *dns_iterations;
    int selected_pid;
    uint64_t selection_mask;
    int explicit_selection;
    int buffer_mode;
    int buffer_iterations;
    const char *tests_dir;
} aggregate_state_t;

typedef struct buffer_skel_base {
    struct bpf_object_skeleton *skeleton;
    struct bpf_object *obj;
} buffer_skel_base_t;

typedef struct buffer_skel_ops {
    const char *name;
    void *(*open)(void);
    int (*load)(void *skel);
    void (*destroy)(void *skel);
} buffer_skel_ops_t;

#define DEFINE_BUFFER_SKEL_OPS(prefix)                                              \
    static void *open_##prefix(void)                                                \
    {                                                                               \
        return prefix##_bpf__open();                                                \
    }                                                                               \
                                                                                    \
    static int load_##prefix(void *skel)                                            \
    {                                                                               \
        return prefix##_bpf__load(skel);                                            \
    }                                                                               \
                                                                                    \
    static void destroy_##prefix(void *skel)                                        \
    {                                                                               \
        prefix##_bpf__destroy(skel);                                                \
    }

#if MY_LINUX_VERSION_CODE >= 329728
DEFINE_BUFFER_SKEL_OPS(cachestat_buffer)
DEFINE_BUFFER_SKEL_OPS(dc_buffer)
DEFINE_BUFFER_SKEL_OPS(dns_buffer)
DEFINE_BUFFER_SKEL_OPS(fd_buffer)
DEFINE_BUFFER_SKEL_OPS(oomkill_buffer)
DEFINE_BUFFER_SKEL_OPS(process_buffer)
DEFINE_BUFFER_SKEL_OPS(shm_buffer)
DEFINE_BUFFER_SKEL_OPS(swap_buffer)
DEFINE_BUFFER_SKEL_OPS(vfs_buffer)

static const buffer_skel_ops_t buffer_skel_ops[] = {
    { "cachestat", open_cachestat_buffer, load_cachestat_buffer, destroy_cachestat_buffer },
    { "dc", open_dc_buffer, load_dc_buffer, destroy_dc_buffer },
    { "dns", open_dns_buffer, load_dns_buffer, destroy_dns_buffer },
    { "fd", open_fd_buffer, load_fd_buffer, destroy_fd_buffer },
    { "oomkill", open_oomkill_buffer, load_oomkill_buffer, destroy_oomkill_buffer },
    { "process", open_process_buffer, load_process_buffer, destroy_process_buffer },
    { "shm", open_shm_buffer, load_shm_buffer, destroy_shm_buffer },
    { "swap", open_swap_buffer, load_swap_buffer, destroy_swap_buffer },
    { "vfs", open_vfs_buffer, load_vfs_buffer, destroy_vfs_buffer },
};
#endif /* MY_LINUX_VERSION_CODE >= 329728 */

static const aggregate_test_case_t aggregate_tests[] = {
    { "cachestat", "cachestat", netdata_cachestat_entry, NULL, NULL, SELECT_CACHESTAT,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "cstat_ctrl" },
    { "dc", "dc", netdata_dc_entry, NULL, NULL, SELECT_DC,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "dcstat_ctrl" },
    { "disk", "disk", netdata_disk_entry, NULL, NULL, SELECT_DISK,
      MODE_NONE, 0, 0 },
    { "dns", "dns", netdata_dns_entry, NULL, NULL, SELECT_DNS,
      MODE_NONE, 0, 0, 1, NULL },
    { "fd", "fd", netdata_fd_entry, NULL, NULL, SELECT_FD,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "fd_ctrl" },
    { "hardirq", "hardirq", netdata_hardirq_entry, NULL, NULL, SELECT_HARDIRQ,
      MODE_NONE, 0, 0 },
    { "mdflush", "mdflush", netdata_mdflush_entry, NULL, NULL, SELECT_MDFLUSH,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "mount", "mount", netdata_mount_entry, NULL, NULL, SELECT_MOUNT,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "networkviewer", "networkviewer", netdata_networkviewer_entry, NULL, NULL, SELECT_NETWORKVIEWER,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "oomkill", "oomkill", netdata_oomkill_entry, NULL, NULL, SELECT_OOMKILL,
      MODE_NONE, 0, 0, 1, NULL },
    { "process", "process", netdata_process_entry, NULL, NULL, SELECT_PROCESS,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "process_ctrl" },
    { "shm", "shm", netdata_shm_entry, NULL, NULL, SELECT_SHM,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "shm_ctrl" },
    { "socket", "socket", netdata_socket_entry, NULL, NULL, SELECT_SOCKET,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "softirq", "softirq", netdata_softirq_entry, NULL, NULL, SELECT_SOFTIRQ,
      MODE_NONE, 0, 0 },
    { "swap", "swap", netdata_swap_entry, NULL, NULL, SELECT_SWAP,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "swap_ctrl" },
    { "sync", "sync", netdata_sync_entry, NULL, NULL, SELECT_SYNC,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "vfs", "vfs", netdata_vfs_entry, NULL, NULL, SELECT_VFS,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1, 1, "vfs_ctrl" },
    { "nfs", "filesystem", netdata_filesystem_entry, "--nfs", NULL, SELECT_NFS,
      MODE_PROBE, 0, 0 },
    { "ext4", "filesystem", netdata_filesystem_entry, "--ext4", NULL, SELECT_EXT4,
      MODE_PROBE, 0, 0 },
    { "btrfs", "filesystem", netdata_filesystem_entry, "--btrfs", NULL, SELECT_BTRFS,
      MODE_PROBE, 0, 0 },
    { "xfs", "filesystem", netdata_filesystem_entry, "--xfs", NULL, SELECT_XFS,
      MODE_PROBE, 0, 0 },
    { "zfs", "zfs", NULL, NULL, "No CO-RE skeleton or tester is generated for zfs in this repository.",
      SELECT_ZFS, MODE_NONE, 0, 0 }
};

static void append_format(char *buffer, size_t size, const char *format, ...)
{
    size_t used;
    va_list args;

    if (!size)
        return;

    used = strlen(buffer);
    if (used >= size - 1)
        return;

    va_start(args, format);
    vsnprintf(buffer + used, size - used, format, args);
    va_end(args);
}

static const char *mode_name(unsigned mode)
{
    switch (mode) {
        case MODE_PROBE:
            return "probe";
        case MODE_TRACEPOINT:
            return "tracepoint";
        case MODE_TRAMPOLINE:
            return "trampoline";
        default:
            return "";
    }
}

static const char *mode_arg(unsigned mode)
{
    switch (mode) {
        case MODE_PROBE:
            return "--probe";
        case MODE_TRACEPOINT:
            return "--tracepoint";
        case MODE_TRAMPOLINE:
            return "--trampoline";
        default:
            return NULL;
    }
}

static void init_result(aggregate_result_t *result, const aggregate_test_case_t *test)
{
    memset(result, 0, sizeof(*result));
    snprintf(result->name, sizeof(result->name), "%s", test->name);
    snprintf(result->binary, sizeof(result->binary), "%s", test->binary ? test->binary : "");
    result->pid = -1;
}

static void json_write_string(FILE *out, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    fputc('"', out);
    while (*cursor) {
        switch (*cursor) {
            case '\\':
            case '"':
                fputc('\\', out);
                fputc(*cursor, out);
                break;
            case '\n':
                fputs("\\n", out);
                break;
            case '\r':
                fputs("\\r", out);
                break;
            case '\t':
                fputs("\\t", out);
                break;
            default:
                if (*cursor < 0x20)
                    fprintf(out, "\\u%04x", *cursor);
                else
                    fputc(*cursor, out);
                break;
        }
        cursor++;
    }
    fputc('"', out);
}

static void write_result(FILE *out, const aggregate_result_t *result, int *first)
{
    if (!*first)
        fprintf(out, ",\n");

    *first = 0;

    fprintf(out, "    {\n");
    fprintf(out, "      \"name\": ");
    json_write_string(out, result->name);
    fprintf(out, ",\n      \"binary\": ");
    json_write_string(out, result->binary);
    fprintf(out, ",\n      \"mode\": ");
    json_write_string(out, result->mode);
    fprintf(out, ",\n      \"pid\": %d,\n", result->pid);
    fprintf(out, "      \"status\": ");
    json_write_string(out, result->status);
    fprintf(out, ",\n      \"exit_code\": %d,\n", result->exit_code);
    fprintf(out, "      \"command\": ");
    json_write_string(out, result->command);
    fprintf(out, ",\n      \"detail\": ");
    json_write_string(out, result->detail);
    if (result->maps_json[0])
        fprintf(out, ",\n      \"maps\": {\n%s\n      }", result->maps_json);
    fprintf(out, "\n    }");
}

static void record_unavailable(aggregate_result_t *result, const aggregate_test_case_t *test, const char *detail)
{
    init_result(result, test);
    snprintf(result->status, sizeof(result->status), "%s", "Unavailable");
    snprintf(result->detail, sizeof(result->detail), "%s", detail);
}

static int execute_test(const aggregate_state_t *state, const aggregate_test_case_t *test,
                        unsigned mode, int pid, aggregate_result_t *result)
{
    char pid_buffer[16];
    char *argv[12];
    int argc = 0;
    int exit_code;

    init_result(result, test);
    if (mode != MODE_NONE)
        snprintf(result->mode, sizeof(result->mode), "%s", mode_name(mode));

    if (pid >= 0)
        result->pid = pid;

    argv[argc++] = (char *)test->binary;

    if (test->emit_mode_arg && mode != MODE_NONE)
        argv[argc++] = (char *)mode_arg(mode);

    if (test->extra_arg)
        argv[argc++] = (char *)test->extra_arg;

    if (!strcmp(test->name, "dns")) {
        if (state->dns_ports) {
            argv[argc++] = "--dns-port";
            argv[argc++] = (char *)state->dns_ports;
        }

        if (state->dns_iterations) {
            argv[argc++] = "--iteration";
            argv[argc++] = (char *)state->dns_iterations;
        }
    }

    if (pid >= 0) {
        snprintf(pid_buffer, sizeof(pid_buffer), "%d", pid);
        argv[argc++] = "--pid";
        argv[argc++] = pid_buffer;
    }

    argv[argc] = NULL;

    append_format(result->command, sizeof(result->command), "%s", test->binary);
    if (test->emit_mode_arg && mode != MODE_NONE)
        append_format(result->command, sizeof(result->command), " %s", mode_arg(mode));
    if (test->extra_arg)
        append_format(result->command, sizeof(result->command), " %s", test->extra_arg);
    if (!strcmp(test->name, "dns")) {
        if (state->dns_ports)
            append_format(result->command, sizeof(result->command), " --dns-port %s", state->dns_ports);
        if (state->dns_iterations)
            append_format(result->command, sizeof(result->command), " --iteration %s", state->dns_iterations);
    }
    if (pid >= 0)
        append_format(result->command, sizeof(result->command), " --pid %d", pid);

    fprintf(stderr, "Running %s\n", result->command);
    exit_code = netdata_run_fn(test->entrypoint, argc, argv);
    result->exit_code = exit_code;
    if (!exit_code) {
        snprintf(result->status, sizeof(result->status), "%s", "Success");
        snprintf(result->detail, sizeof(result->detail), "%s", "Command completed successfully.");
    } else {
        snprintf(result->status, sizeof(result->status), "%s", "Fail");
        snprintf(result->detail, sizeof(result->detail), "Command exited with code %d.", exit_code);
    }

    return exit_code;
}

typedef struct ringbuf_stats {
    size_t samples;
    size_t bytes;
} ringbuf_stats_t;

static int ringbuf_sample_cb(void *ctx, void *data, size_t size)
{
    ringbuf_stats_t *stats = ctx;

    (void)data;
    if (stats) {
        stats->samples++;
        stats->bytes += size;
    }

    return 0;
}

static int map_is_ringbuf(enum bpf_map_type type)
{
    return type == BPF_MAP_TYPE_RINGBUF || type == BPF_MAP_TYPE_USER_RINGBUF;
}

static const char *format_error(int err, char *buf, size_t size)
{
    if (!err)
        return "No error information";
    if (err < 0)
        err = -err;
    snprintf(buf, size, "%s", strerror(err));
    return buf;
}

#if MY_LINUX_VERSION_CODE >= 329728
static const buffer_skel_ops_t *find_buffer_skel_ops(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(buffer_skel_ops) / sizeof(buffer_skel_ops[0]); i++) {
        if (!strcmp(buffer_skel_ops[i].name, name))
            return &buffer_skel_ops[i];
    }

    return NULL;
}
#endif /* MY_LINUX_VERSION_CODE >= 329728 */

static void fill_ctrl_map(struct bpf_object *obj, const char *ctrl_name, int map_level)
{
    struct bpf_map *map;
    int fd;
    __u64 values[] = { 1, (uint64_t)map_level, 0, 0, 0, 0 };
    __u32 i;
    __u32 max_entries;

    if (!ctrl_name)
        return;

    map = bpf_object__find_map_by_name(obj, ctrl_name);
    if (!map)
        return;

    fd = bpf_map__fd(map);
    max_entries = bpf_map__max_entries(map);
    for (i = 0; i < max_entries && i < sizeof(values) / sizeof(values[0]); i++)
        bpf_map_update_elem(fd, &i, &values[i], 0);
}

static int test_ringbuf_map(struct bpf_map *map, int iterations,
                            char *map_json_buf, size_t map_json_size)
{
    enum bpf_map_type type = bpf_map__type(map);
    int fd = bpf_map__fd(map);
    uint32_t key_size = bpf_map__key_size(map);
    uint32_t value_size = bpf_map__value_size(map);
    const char *mode = (type == BPF_MAP_TYPE_USER_RINGBUF) ? "user_ringbuf_producer" : "ringbuf_consumer";
    int setup_error = 0;
    int op_error = 0;
    int i;
    struct ring_buffer *rb = NULL;
    struct user_ring_buffer *urb = NULL;
    ringbuf_stats_t stats = { 0 };
    ringbuf_stats_t previous = { 0 };
    size_t pos = 0;
    char errbuf[128];
    int n;

    n = snprintf(map_json_buf + pos, map_json_size - pos,
        "{\n"
        "            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
        "                       \"Type\" : %u,\n"
        "                       \"FD\" : %d,\n"
        "                       \"Data\" : [\n",
        key_size, value_size, (unsigned)type, fd);
    if (n > 0) pos += (size_t)n;

    if (type == BPF_MAP_TYPE_RINGBUF) {
        rb = ring_buffer__new(fd, ringbuf_sample_cb, &stats, NULL);
        setup_error = libbpf_get_error(rb);
        if (setup_error)
            rb = NULL;
    } else if (type == BPF_MAP_TYPE_USER_RINGBUF) {
        urb = user_ring_buffer__new(fd, NULL);
        setup_error = libbpf_get_error(urb);
        if (setup_error)
            urb = NULL;
    }

    op_error = setup_error;
    for (i = 0; i < iterations; i++) {
        size_t iter_samples = 0;
        size_t iter_bytes = 0;
        size_t ring_size = 0;
        size_t avail_data = 0;
        int cur_op_result = 0;

        sleep(10);

        if (rb) {
            struct ring *ring = ring_buffer__ring(rb, 0);

            cur_op_result = ring_buffer__poll(rb, 0);
            if (cur_op_result < 0)
                op_error = cur_op_result;

            iter_samples = stats.samples - previous.samples;
            iter_bytes = stats.bytes - previous.bytes;
            previous = stats;

            if (ring) {
                ring_size = ring__size(ring);
                avail_data = ring__avail_data_size(ring);
            }
        } else if (urb) {
            __u64 value = (__u64)(i + 1);
            void *sample = user_ring_buffer__reserve(urb, sizeof(value));
            if (!sample) {
                cur_op_result = errno ? -errno : -1;
                op_error = cur_op_result;
            } else {
                memcpy(sample, &value, sizeof(value));
                user_ring_buffer__submit(urb, sample);
            }
        }

        if (i > 0 && pos < map_json_size - 1) {
            n = snprintf(map_json_buf + pos, map_json_size - pos, ",\n");
            if (n > 0) pos += (size_t)n;
        }

        n = snprintf(map_json_buf + pos, map_json_size - pos,
            "                                    "
            "{ \"Iteration\" : %d, \"Mode\" : \"%s\", \"Setup\" : %d, "
            "\"Operation Result\" : %d, \"Samples\" : %zu, \"Bytes\" : %zu, "
            "\"Available\" : %zu, \"Ring Size\" : %zu, \"Error Code\" : %d, "
            "\"Error Message\" : \"%s\" }",
            i, mode, !setup_error, cur_op_result,
            iter_samples, iter_bytes, avail_data, ring_size,
            op_error, format_error(op_error, errbuf, sizeof(errbuf)));
        if (n > 0) pos += (size_t)n;
        if (pos >= map_json_size - 1)
            pos = map_json_size - 1;
    }

    n = snprintf(map_json_buf + pos, map_json_size - pos,
        "\n                                ]\n"
        "                      }\n"
        "        }");
    if (n > 0) pos += (size_t)n;
    if (pos < map_json_size)
        map_json_buf[pos] = '\0';

    if (rb)
        ring_buffer__free(rb);
    if (urb)
        user_ring_buffer__free(urb);

    return op_error;
}

static int netdata_core_symbol_in_kallsyms(const char *name)
{
    FILE *f;
    char line[512];
    char sym[256];
    int found = 0;

    f = fopen("/proc/kallsyms", "r");
    if (!f)
        return 1; /* can't verify; assume present to avoid false disabling */

    while (!found && fgets(line, (int)sizeof(line), f)) {
        if (sscanf(line, "%*x %*c %255s", sym) == 1)
            found = (strcmp(sym, name) == 0);
    }
    fclose(f);
    return found;
}

/* Mutually exclusive kprobe target groups in priority order (first found wins).
 * Mirrors the compile-time #if chain in kernel-collector/kernel/cachestat_buffer_kern.c
 * and swap_buffer_kern.c, resolved at runtime via kallsyms for CO-RE builds. */
static const char * const netdata_core_kprobe_groups[][4] = {
    { "__folio_mark_dirty", "__set_page_dirty", "account_page_dirtied", NULL },
    { "swap_read_folio",    "swap_readpage",    NULL,                   NULL },
    { "__swap_writepage",   "swap_writepage",   NULL,                   NULL },
    { NULL,                 NULL,               NULL,                   NULL }
};

static void netdata_core_select_kprobe_programs(struct bpf_object *obj)
{
    struct bpf_program *prog;
    int g, i;

    for (g = 0; netdata_core_kprobe_groups[g][0]; g++) {
        const char *winner = NULL;
        for (i = 0; netdata_core_kprobe_groups[g][i]; i++) {
            if (netdata_core_symbol_in_kallsyms(netdata_core_kprobe_groups[g][i])) {
                winner = netdata_core_kprobe_groups[g][i];
                break;
            }
        }
        bpf_object__for_each_program(prog, obj) {
            const char *sec = bpf_program__section_name(prog);
            const char *fn;
            if (!sec || strncmp(sec, "kprobe/", 7) != 0)
                continue;
            fn = sec + 7;
            for (i = 0; netdata_core_kprobe_groups[g][i]; i++) {
                if (strcmp(fn, netdata_core_kprobe_groups[g][i]) == 0 &&
                    (!winner || strcmp(fn, winner) != 0)) {
                    bpf_program__set_autoload(prog, false);
                    break;
                }
            }
        }
    }

    /* Disable any remaining kprobe program whose target doesn't exist. */
    bpf_object__for_each_program(prog, obj) {
        const char *sec = bpf_program__section_name(prog);
        if (!sec || strncmp(sec, "kprobe/", 7) != 0)
            continue;
        if (!netdata_core_symbol_in_kallsyms(sec + 7))
            bpf_program__set_autoload(prog, false);
    }
}

static int attach_buffer_programs(struct bpf_object *obj, struct bpf_link **links, size_t links_len,
                                  size_t *attached, size_t *skipped)
{
    struct bpf_program *prog;
    int last_error = 0;

    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link;

        if (bpf_program__type(prog) == BPF_PROG_TYPE_SOCKET_FILTER) {
            (*skipped)++;
            continue;
        }

        if (*attached >= links_len)
            return -ENOSPC;

        /* Skip programs disabled before load (missing kprobe targets). */
        if (bpf_program__fd(prog) < 0)
            continue;

        link = bpf_program__attach(prog);
        last_error = libbpf_get_error(link);
        if (last_error) {
            /* Safety net: skip if target still absent at attach time. */
            if (last_error == -ENOENT) {
                last_error = 0;
                continue;
            }
            return last_error;
        }

        links[(*attached)++] = link;
    }

    return 0;
}

#if MY_LINUX_VERSION_CODE >= 329728
static int execute_buffer_test(const aggregate_state_t *state, const aggregate_test_case_t *test,
                               aggregate_result_t *result)
{
    const buffer_skel_ops_t *ops;
    void *skel = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_map *map;
    struct bpf_link *links[64] = { 0 };
    size_t attached = 0;
    size_t skipped = 0;
    size_t ringbuf_maps = 0;
    size_t maps = 0;
    int err = 0;
    size_t i;
    size_t maps_json_pos = 0;
    char map_json_buf[2048];

    init_result(result, test);
    snprintf(result->mode, sizeof(result->mode), "%s", "buffer");
    snprintf(result->binary, sizeof(result->binary), "%s_buffer.skel.h", test->name);
    snprintf(result->command, sizeof(result->command), "%s_buffer skeleton", test->name);
    if (state->selected_pid >= 0)
        result->pid = state->selected_pid;

    if (!test->buffer_supported) {
        snprintf(result->status, sizeof(result->status), "%s", "Unavailable");
        snprintf(result->detail, sizeof(result->detail), "%s", "Collector has no CO-RE buffer object.");
        return 0;
    }

    (void)state->tests_dir;

    ops = find_buffer_skel_ops(test->name);
    if (!ops) {
        snprintf(result->status, sizeof(result->status), "%s", "Fail");
        snprintf(result->detail, sizeof(result->detail), "%s", "Buffer skeleton is not compiled into this tester.");
        return 1;
    }

    fprintf(stderr, "Running buffer skeleton test %s\n", result->command);

    skel = ops->open();
    err = libbpf_get_error(skel);
    if (err) {
        skel = NULL;
        goto fail;
    }
    obj = ((buffer_skel_base_t *)skel)->obj;
    netdata_core_select_kprobe_programs(obj);

    err = ops->load(skel);
    if (err)
        goto fail;

    fill_ctrl_map(obj, test->buffer_ctrl, state->selected_pid >= 0 ? state->selected_pid : PID_MIN);

    err = attach_buffer_programs(obj, links, sizeof(links) / sizeof(links[0]), &attached, &skipped);
    if (err)
        goto fail;

    bpf_object__for_each_map(map, obj) {
        const char *map_name = bpf_map__name(map);
        int n;

        maps++;
        if (!map_is_ringbuf(bpf_map__type(map)))
            continue;

        if (maps_json_pos > 0 && maps_json_pos < sizeof(result->maps_json) - 1) {
            n = snprintf(result->maps_json + maps_json_pos,
                         sizeof(result->maps_json) - maps_json_pos, ",\n");
            if (n > 0) maps_json_pos += (size_t)n;
        }
        n = snprintf(result->maps_json + maps_json_pos,
                     sizeof(result->maps_json) - maps_json_pos,
                     "        \"%s\" : ", map_name);
        if (n > 0) maps_json_pos += (size_t)n;

        ringbuf_maps++;
        map_json_buf[0] = '\0';
        err = test_ringbuf_map(map, state->buffer_iterations,
                               map_json_buf, sizeof(map_json_buf));

        n = snprintf(result->maps_json + maps_json_pos,
                     sizeof(result->maps_json) - maps_json_pos, "%s", map_json_buf);
        if (n > 0) maps_json_pos += (size_t)n;
        if (maps_json_pos >= sizeof(result->maps_json) - 1)
            maps_json_pos = sizeof(result->maps_json) - 1;
        result->maps_json[maps_json_pos] = '\0';

        if (err)
            goto fail;
    }

    for (i = 0; i < attached; i++)
        bpf_link__destroy(links[i]);
    ops->destroy(skel);

    snprintf(result->status, sizeof(result->status), "%s", "Success");
    snprintf(result->detail, sizeof(result->detail),
             "Loaded object, attached %zu programs, skipped %zu socket filters, checked %zu maps and %zu ring buffers.",
             attached, skipped, maps, ringbuf_maps);
    return 0;

fail:
    for (i = 0; i < attached; i++)
        bpf_link__destroy(links[i]);
    if (skel)
        ops->destroy(skel);

    snprintf(result->status, sizeof(result->status), "%s", "Fail");
    snprintf(result->detail, sizeof(result->detail), "Buffer skeleton test failed with error %d.", err);
    result->exit_code = err ? err : 1;
    return 1;
}
#endif /* MY_LINUX_VERSION_CODE >= 329728 */

static void print_help(const char *name)
{
    fprintf(stdout,
            "%s runs the CO-RE tests in-process and aggregates their results.\n\n"
            "Options:\n"
            "  --help            Print this help.\n"
            "  --all             Run all non-filesystem CO-RE tests. This is the default.\n"
            "  --pid VALUE       Run PID-aware tests with a single PID level (0-3).\n"
            "  --dns-port LIST   Forward a comma-separated DNS port list to the DNS tester.\n"
            "  --iteration N     Forward the capture iteration count to the DNS tester.\n"
            "  --tests-dir PATH  Accepted for compatibility and ignored in standalone mode.\n"
            "  --log-path FILE   Write the aggregate JSON summary to FILE instead of stdout.\n"
            "  --buffer          Test CO-RE ring-buffer BPF objects instead of standalone loaders.\n"
            "\n"
            "Selectors:\n"
            "  --cachestat --dc --disk --dns --fd --hardirq --mdflush --mount\n"
            "  --networkviewer --oomkill --process --shm --socket --softirq --swap\n"
            "  --sync --vfs --filesystem --nfs --ext4 --btrfs --xfs --zfs\n"
            "\n"
            "Notes:\n"
            "  - --all excludes filesystem coverage: nfs, ext4, btrfs, xfs, and zfs.\n"
            "  - --filesystem expands to --nfs --ext4 --btrfs --xfs.\n"
            "  - zfs is reported as unavailable because this repository does not generate\n"
            "    a CO-RE zfs skeleton/tester.\n",
            name);
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        { "help",          no_argument,       0, 'h' },
        { "pid",           required_argument, 0, OPT_PID },
        { "dns-port",      required_argument, 0, OPT_DNS_PORT },
        { "iteration",     required_argument, 0, OPT_ITERATION },
        { "tests-dir",     required_argument, 0, OPT_TESTS_DIR },
        { "log-path",      required_argument, 0, OPT_LOG_PATH },
        { "all",           no_argument,       0, OPT_ALL },
        { "cachestat",     no_argument,       0, OPT_CACHESTAT },
        { "dc",            no_argument,       0, OPT_DC },
        { "disk",          no_argument,       0, OPT_DISK },
        { "dns",           no_argument,       0, OPT_DNS },
        { "fd",            no_argument,       0, OPT_FD },
        { "hardirq",       no_argument,       0, OPT_HARDIRQ },
        { "mdflush",       no_argument,       0, OPT_MDFLUSH },
        { "mount",         no_argument,       0, OPT_MOUNT },
        { "networkviewer", no_argument,       0, OPT_NETWORKVIEWER },
        { "oomkill",       no_argument,       0, OPT_OOMKILL },
        { "process",       no_argument,       0, OPT_PROCESS },
        { "shm",           no_argument,       0, OPT_SHM },
        { "socket",        no_argument,       0, OPT_SOCKET },
        { "softirq",       no_argument,       0, OPT_SOFTIRQ },
        { "swap",          no_argument,       0, OPT_SWAP },
        { "sync",          no_argument,       0, OPT_SYNC },
        { "vfs",           no_argument,       0, OPT_VFS },
        { "filesystem",    no_argument,       0, OPT_FILESYSTEM },
        { "nfs",           no_argument,       0, OPT_NFS },
        { "ext4",          no_argument,       0, OPT_EXT4 },
        { "btrfs",         no_argument,       0, OPT_BTRFS },
        { "xfs",           no_argument,       0, OPT_XFS },
        { "zfs",           no_argument,       0, OPT_ZFS },
        { "buffer",        no_argument,       0, OPT_BUFFER },
        { 0,               0,                 0, 0 }
    };

    aggregate_state_t state = { .selected_pid = -1, .buffer_iterations = 1 };
    aggregate_result_t results[192];
    const char *log_path = NULL;
    FILE *report = stdout;
    int option_index = 0;
    int first = 1;
    size_t result_count = 0;
    int failures = 0;
    int unavailable = 0;
    size_t i;

    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                print_help(argv[0]);
                return 0;
            case OPT_PID:
                state.selected_pid = (int)strtol(optarg, NULL, 10);
                if (state.selected_pid < PID_MIN || state.selected_pid > PID_MAX) {
                    fprintf(stderr, "PID level must be between %d and %d.\n", PID_MIN, PID_MAX);
                    return 1;
                }
                break;
            case OPT_DNS_PORT:
                state.dns_ports = optarg;
                break;
            case OPT_ITERATION:
                state.dns_iterations = optarg;
                state.buffer_iterations = (int)strtol(optarg, NULL, 10);
                if (state.buffer_iterations < 1)
                    state.buffer_iterations = 1;
                break;
            case OPT_TESTS_DIR:
                state.tests_dir = optarg;
                break;
            case OPT_LOG_PATH:
                log_path = optarg;
                break;
            case OPT_ALL:
                state.selection_mask |= SELECT_ALL_NON_FILESYSTEM;
                state.explicit_selection = 1;
                break;
            case OPT_CACHESTAT:
                state.selection_mask |= SELECT_CACHESTAT;
                state.explicit_selection = 1;
                break;
            case OPT_DC:
                state.selection_mask |= SELECT_DC;
                state.explicit_selection = 1;
                break;
            case OPT_DISK:
                state.selection_mask |= SELECT_DISK;
                state.explicit_selection = 1;
                break;
            case OPT_DNS:
                state.selection_mask |= SELECT_DNS;
                state.explicit_selection = 1;
                break;
            case OPT_FD:
                state.selection_mask |= SELECT_FD;
                state.explicit_selection = 1;
                break;
            case OPT_HARDIRQ:
                state.selection_mask |= SELECT_HARDIRQ;
                state.explicit_selection = 1;
                break;
            case OPT_MDFLUSH:
                state.selection_mask |= SELECT_MDFLUSH;
                state.explicit_selection = 1;
                break;
            case OPT_MOUNT:
                state.selection_mask |= SELECT_MOUNT;
                state.explicit_selection = 1;
                break;
            case OPT_NETWORKVIEWER:
                state.selection_mask |= SELECT_NETWORKVIEWER;
                state.explicit_selection = 1;
                break;
            case OPT_OOMKILL:
                state.selection_mask |= SELECT_OOMKILL;
                state.explicit_selection = 1;
                break;
            case OPT_PROCESS:
                state.selection_mask |= SELECT_PROCESS;
                state.explicit_selection = 1;
                break;
            case OPT_SHM:
                state.selection_mask |= SELECT_SHM;
                state.explicit_selection = 1;
                break;
            case OPT_SOCKET:
                state.selection_mask |= SELECT_SOCKET;
                state.explicit_selection = 1;
                break;
            case OPT_SOFTIRQ:
                state.selection_mask |= SELECT_SOFTIRQ;
                state.explicit_selection = 1;
                break;
            case OPT_SWAP:
                state.selection_mask |= SELECT_SWAP;
                state.explicit_selection = 1;
                break;
            case OPT_SYNC:
                state.selection_mask |= SELECT_SYNC;
                state.explicit_selection = 1;
                break;
            case OPT_VFS:
                state.selection_mask |= SELECT_VFS;
                state.explicit_selection = 1;
                break;
            case OPT_FILESYSTEM:
                state.selection_mask |= SELECT_FILESYSTEM;
                state.explicit_selection = 1;
                break;
            case OPT_NFS:
                state.selection_mask |= SELECT_NFS;
                state.explicit_selection = 1;
                break;
            case OPT_EXT4:
                state.selection_mask |= SELECT_EXT4;
                state.explicit_selection = 1;
                break;
            case OPT_BTRFS:
                state.selection_mask |= SELECT_BTRFS;
                state.explicit_selection = 1;
                break;
            case OPT_XFS:
                state.selection_mask |= SELECT_XFS;
                state.explicit_selection = 1;
                break;
            case OPT_ZFS:
                state.selection_mask |= SELECT_ZFS;
                state.explicit_selection = 1;
                break;
            case OPT_BUFFER:
                state.buffer_mode = 1;
                break;
            default:
                break;
        }
    }

    if (!state.explicit_selection) {
        state.selection_mask = SELECT_ALL_NON_FILESYSTEM;
        state.explicit_selection = 1;
    }

    if (log_path) {
        report = fopen(log_path, "w");
        if (!report) {
            perror("Cannot open log file");
            return 1;
        }
    }

    fprintf(report, "{\n  \"runs\": [\n");

    for (i = 0; i < sizeof(aggregate_tests) / sizeof(aggregate_tests[0]); i++) {
        const aggregate_test_case_t *test = &aggregate_tests[i];

        if (state.explicit_selection && !(state.selection_mask & test->selection_bit))
            continue;

        if (state.buffer_mode) {
            if (!test->buffer_supported)
                continue;

#if MY_LINUX_VERSION_CODE >= 329728
            failures += execute_buffer_test(&state, test, &results[result_count]) != 0;
#else
            record_unavailable(&results[result_count], test,
                               "Ring buffer (BPF_MAP_TYPE_RINGBUF) requires kernel >= 5.8.");
            unavailable++;
#endif
            write_result(report, &results[result_count], &first);
            result_count++;
            continue;
        }

        if (test->unavailable_reason) {
            record_unavailable(&results[result_count], test, test->unavailable_reason);
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }

        if (!test->entrypoint) {
            record_unavailable(&results[result_count], test, "Standalone entrypoint is not available.");
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }

        if (test->modes == MODE_NONE) {
            failures += execute_test(&state, test, MODE_NONE, -1, &results[result_count]) != 0;
            write_result(report, &results[result_count], &first);
            result_count++;
            continue;
        }

        {
            const unsigned ordered_modes[] = { MODE_PROBE, MODE_TRACEPOINT, MODE_TRAMPOLINE };
            size_t j;
            for (j = 0; j < sizeof(ordered_modes) / sizeof(ordered_modes[0]); j++) {
                unsigned mode = ordered_modes[j];

                if (mode == MODE_TRACEPOINT && !(test->modes & MODE_TRACEPOINT)) {
                    init_result(&results[result_count], test);
                    snprintf(results[result_count].status, sizeof(results[result_count].status), "%s", "Success");
                    snprintf(results[result_count].detail, sizeof(results[result_count].detail),
                             "tracepoint is not available on this system, cannot proceed");
                    write_result(report, &results[result_count], &first);
                    result_count++;
                    unavailable++;
                    break;
                }

                if (!(test->modes & mode))
                    continue;

                int pid_start = -1;
                int pid_end = -1;

                if (test->pid_supported) {
                    if (state.selected_pid >= 0) {
                        pid_start = state.selected_pid;
                        pid_end = state.selected_pid;
                    } else {
                        pid_start = PID_MIN;
                        pid_end = PID_MAX;
                    }
                }

                if (pid_start >= 0) {
                    int pid;
                    for (pid = pid_start; pid <= pid_end; pid++) {
                        failures += execute_test(&state, test, mode, pid, &results[result_count]) != 0;
                        write_result(report, &results[result_count], &first);
                        result_count++;
                    }
                } else {
                    failures += execute_test(&state, test, mode, -1, &results[result_count]) != 0;
                    write_result(report, &results[result_count], &first);
                    result_count++;
                }
            }
        }
    }

    fprintf(report,
            "\n  ],\n"
            "  \"summary\": {\n"
            "    \"total\": %zu,\n"
            "    \"success\": %zu,\n"
            "    \"failed\": %d,\n"
            "    \"unavailable\": %d\n"
            "  }\n"
            "}\n",
            result_count,
            result_count - (size_t)failures - (size_t)unavailable,
            failures,
            unavailable);

    if (report != stdout)
        fclose(report);

    return failures ? 1 : 0;
}
