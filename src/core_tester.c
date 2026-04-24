#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

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
    SELECT_ANY_FILESYSTEM = SELECT_FILESYSTEM | SELECT_ZFS,
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
    OPT_ZFS
};

typedef struct aggregate_test_case {
    const char *name;
    const char *binary;
    const char *skel;
    const char *extra_arg;
    const char *unavailable_reason;
    uint64_t selection_bit;
    unsigned modes;
    int emit_mode_arg;
    int pid_supported;
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
} aggregate_result_t;

typedef struct aggregate_state {
    char tests_dir[PATH_MAX];
    char includes_dir[PATH_MAX];
    const char *dns_ports;
    const char *dns_iterations;
    int selected_pid;
    uint64_t selection_mask;
    int explicit_selection;
} aggregate_state_t;

static const aggregate_test_case_t aggregate_tests[] = {
    { "cachestat", "cachestat", "cachestat.skel.h", NULL, NULL, SELECT_CACHESTAT,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "dc", "dc", "dc.skel.h", NULL, NULL, SELECT_DC,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "disk", "disk", "disk.skel.h", NULL, NULL, SELECT_DISK,
      MODE_NONE, 0, 0 },
    { "dns", "dns", "dns.skel.h", NULL, NULL, SELECT_DNS,
      MODE_NONE, 0, 0 },
    { "fd", "fd", "fd.skel.h", NULL, NULL, SELECT_FD,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "hardirq", "hardirq", "hardirq.skel.h", NULL, NULL, SELECT_HARDIRQ,
      MODE_NONE, 0, 0 },
    { "mdflush", "mdflush", "mdflush.skel.h", NULL, NULL, SELECT_MDFLUSH,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "mount", "mount", "mount.skel.h", NULL, NULL, SELECT_MOUNT,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "networkviewer", "networkviewer", "networkviewer.skel.h", NULL, NULL, SELECT_NETWORKVIEWER,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "oomkill", "oomkill", "oomkill.skel.h", NULL, NULL, SELECT_OOMKILL,
      MODE_NONE, 0, 0 },
    { "process", "process", "process.skel.h", NULL, NULL, SELECT_PROCESS,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "shm", "shm", "shm.skel.h", NULL, NULL, SELECT_SHM,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "socket", "socket", "socket.skel.h", NULL, NULL, SELECT_SOCKET,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "softirq", "softirq", "softirq.skel.h", NULL, NULL, SELECT_SOFTIRQ,
      MODE_NONE, 0, 0 },
    { "swap", "swap", "swap.skel.h", NULL, NULL, SELECT_SWAP,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "sync", "sync", "sync.skel.h", NULL, NULL, SELECT_SYNC,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 0 },
    { "vfs", "vfs", "vfs.skel.h", NULL, NULL, SELECT_VFS,
      MODE_PROBE | MODE_TRACEPOINT | MODE_TRAMPOLINE, 1, 1 },
    { "nfs", "filesystem", "filesystem.skel.h", "--nfs", NULL, SELECT_NFS,
      MODE_PROBE, 0, 0 },
    { "ext4", "filesystem", "filesystem.skel.h", "--ext4", NULL, SELECT_EXT4,
      MODE_PROBE, 0, 0 },
    { "btrfs", "filesystem", "filesystem.skel.h", "--btrfs", NULL, SELECT_BTRFS,
      MODE_PROBE, 0, 0 },
    { "xfs", "filesystem", "filesystem.skel.h", "--xfs", NULL, SELECT_XFS,
      MODE_PROBE, 0, 0 },
    { "zfs", NULL, NULL, NULL, "No CO-RE skeleton or tester is generated for zfs in this repository.",
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

static void strip_last_component(char *path)
{
    char *slash = strrchr(path, '/');
    if (!slash)
        return;

    if (slash == path) {
        slash[1] = '\0';
        return;
    }

    *slash = '\0';
}

static int join_path(char *buffer, size_t size, const char *left, const char *right)
{
    int written;

    written = snprintf(buffer, size, "%s/%s", left, right);
    if (written < 0 || (size_t)written >= size)
        return -1;

    return 0;
}

static int resolve_self_paths(aggregate_state_t *state, const char *override_tests_dir)
{
    char self_path[PATH_MAX];
    ssize_t length;
    char repo_root[PATH_MAX];

    if (override_tests_dir) {
        if (!realpath(override_tests_dir, state->tests_dir))
            return -1;
    } else {
        length = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
        if (length < 0)
            return -1;

        self_path[length] = '\0';
        snprintf(state->tests_dir, sizeof(state->tests_dir), "%s", self_path);
        strip_last_component(state->tests_dir);
    }

    snprintf(repo_root, sizeof(repo_root), "%s", state->tests_dir);
    strip_last_component(repo_root);
    strip_last_component(repo_root);
    if (join_path(state->includes_dir, sizeof(state->includes_dir), repo_root, "includes"))
        return -1;

    return 0;
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
    result->exit_code = 0;
}

static int run_child(char *const argv[])
{
    pid_t pid = fork();
    int status = 0;

    if (pid < 0)
        return -errno;

    if (pid == 0) {
        dup2(STDERR_FILENO, STDOUT_FILENO);
        execv(argv[0], argv);
        perror("execv");
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0)
        return -errno;

    if (WIFEXITED(status))
        return WEXITSTATUS(status);

    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);

    return 1;
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
    fprintf(out, "\n    }");
}

static int path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

static void record_unavailable(aggregate_result_t *result, const aggregate_test_case_t *test, const char *detail)
{
    init_result(result, test);
    snprintf(result->status, sizeof(result->status), "%s", "Unavailable");
    snprintf(result->detail, sizeof(result->detail), "%s", detail);
    snprintf(result->command, sizeof(result->command), "%s", "");
}

static int execute_test(const aggregate_state_t *state, const aggregate_test_case_t *test,
                        unsigned mode, int pid, aggregate_result_t *result)
{
    char binary_path[PATH_MAX];
    char *argv[12];
    int argc = 0;
    int exit_code;

    init_result(result, test);
    if (mode != MODE_NONE)
        snprintf(result->mode, sizeof(result->mode), "%s", mode_name(mode));
    else
        snprintf(result->mode, sizeof(result->mode), "%s", "");

    if (pid >= 0)
        result->pid = pid;

    if (join_path(binary_path, sizeof(binary_path), state->tests_dir, test->binary)) {
        snprintf(result->status, sizeof(result->status), "%s", "Fail");
        snprintf(result->detail, sizeof(result->detail), "%s", "Binary path is too long.");
        result->exit_code = 1;
        return 1;
    }
    argv[argc++] = binary_path;

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
        static char pid_buffer[16];
        snprintf(pid_buffer, sizeof(pid_buffer), "%d", pid);
        argv[argc++] = "--pid";
        argv[argc++] = pid_buffer;
    }

    argv[argc] = NULL;

    append_format(result->command, sizeof(result->command), "%s", binary_path);
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
    exit_code = run_child(argv);
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

static void print_help(const char *name)
{
    fprintf(stdout,
            "%s runs the CO-RE testers built in src/tests and aggregates their results.\n\n"
            "Options:\n"
            "  --help            Print this help.\n"
            "  --all             Run all non-filesystem CO-RE tests. This is the default.\n"
            "  --pid VALUE       Run PID-aware tests with a single PID level (0-3).\n"
            "  --dns-port LIST   Forward a comma-separated DNS port list to the DNS tester.\n"
            "  --iteration N     Forward the capture iteration count to the DNS tester.\n"
            "  --tests-dir PATH  Override the directory that contains the compiled test binaries.\n"
            "  --log-path FILE   Write the aggregate JSON summary to FILE instead of stdout.\n"
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
        { 0,               0,                 0, 0 }
    };

    aggregate_state_t state = { .selected_pid = -1 };
    aggregate_result_t results[192];
    const char *tests_dir_override = NULL;
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
                break;
            case OPT_TESTS_DIR:
                tests_dir_override = optarg;
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
            default:
                break;
        }
    }

    if (!state.explicit_selection) {
        state.selection_mask = SELECT_ALL_NON_FILESYSTEM;
        state.explicit_selection = 1;
    }

    if (resolve_self_paths(&state, tests_dir_override)) {
        perror("Cannot resolve tester paths");
        return 1;
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
        char skel_path[PATH_MAX];
        char binary_path[PATH_MAX];

        if (state.explicit_selection && !(state.selection_mask & test->selection_bit))
            continue;

        if (test->unavailable_reason) {
            record_unavailable(&results[result_count], test, test->unavailable_reason);
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }

        if (join_path(skel_path, sizeof(skel_path), state.includes_dir, test->skel)) {
            record_unavailable(&results[result_count], test, "Skeleton path is too long.");
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }
        if (!path_exists(skel_path)) {
            char detail[256];
            snprintf(detail, sizeof(detail), "Missing CO-RE artifact %s.", test->skel);
            record_unavailable(&results[result_count], test, detail);
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }

        if (join_path(binary_path, sizeof(binary_path), state.tests_dir, test->binary)) {
            record_unavailable(&results[result_count], test, "Binary path is too long.");
            write_result(report, &results[result_count], &first);
            result_count++;
            unavailable++;
            continue;
        }
        if (access(binary_path, X_OK)) {
            char detail[256];
            snprintf(detail, sizeof(detail), "Missing compiled tester %s.", test->binary);
            record_unavailable(&results[result_count], test, detail);
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
                int pid_start = -1;
                int pid_end = -1;

                if (!(test->modes & mode))
                    continue;

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
