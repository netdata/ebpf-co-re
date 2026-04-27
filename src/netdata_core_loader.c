#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "netdata_core_loader.h"

void netdata_reset_getopt(void)
{
    optind = 0;
    opterr = 1;
    optopt = 0;
    optarg = NULL;
}

int netdata_run_fn(netdata_loader_fn_t fn, int argc, char **argv)
{
    int saved_stdout;
    int ret;

    if (!fn)
        return 127;

    fflush(stdout);
    saved_stdout = dup(STDOUT_FILENO);
    if (saved_stdout < 0)
        return -errno;

    if (dup2(STDERR_FILENO, STDOUT_FILENO) < 0) {
        ret = -errno;
        close(saved_stdout);
        return ret;
    }

    netdata_reset_getopt();
    ret = fn(argc, argv);
    fflush(stdout);

    if (dup2(saved_stdout, STDOUT_FILENO) < 0) {
        int restore_err = -errno;
        close(saved_stdout);
        return restore_err;
    }

    close(saved_stdout);
    return ret;
}

typedef struct {
    const char *name;
    netdata_loader_fn_t fn;
} netdata_loader_entry_t;

static const netdata_loader_entry_t netdata_loader_table[] = {
    { "cachestat",     netdata_cachestat_entry     },
    { "dc",            netdata_dc_entry            },
    { "disk",          netdata_disk_entry          },
    { "dns",           netdata_dns_entry           },
    { "fd",            netdata_fd_entry            },
    { "filesystem",    netdata_filesystem_entry    },
    { "hardirq",       netdata_hardirq_entry       },
    { "mdflush",       netdata_mdflush_entry       },
    { "mount",         netdata_mount_entry         },
    { "networkviewer", netdata_networkviewer_entry },
    { "oomkill",       netdata_oomkill_entry       },
    { "process",       netdata_process_entry       },
    { "shm",           netdata_shm_entry           },
    { "socket",        netdata_socket_entry        },
    { "softirq",       netdata_softirq_entry       },
    { "swap",          netdata_swap_entry          },
    { "sync",          netdata_sync_entry          },
    { "vfs",           netdata_vfs_entry           },
    { NULL, NULL }
};

int netdata_run_entry(const char *name, int argc, char **argv)
{
    const netdata_loader_entry_t *entry;

    if (!name)
        return 127;

    for (entry = netdata_loader_table; entry->name; entry++) {
        if (!strcmp(entry->name, name))
            return netdata_run_fn(entry->fn, argc, argv);
    }

    return 127;
}
