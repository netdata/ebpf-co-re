#ifndef NETDATA_CORE_LOADER_H
#define NETDATA_CORE_LOADER_H

typedef int (*netdata_loader_fn_t)(int argc, char **argv);

void netdata_reset_getopt(void);
int netdata_run_fn(netdata_loader_fn_t fn, int argc, char **argv);
int netdata_run_entry(const char *name, int argc, char **argv);

int netdata_cachestat_entry(int argc, char **argv);
int netdata_dc_entry(int argc, char **argv);
int netdata_disk_entry(int argc, char **argv);
int netdata_dns_entry(int argc, char **argv);
int netdata_fd_entry(int argc, char **argv);
int netdata_filesystem_entry(int argc, char **argv);
int netdata_hardirq_entry(int argc, char **argv);
int netdata_mdflush_entry(int argc, char **argv);
int netdata_mount_entry(int argc, char **argv);
int netdata_networkviewer_entry(int argc, char **argv);
int netdata_oomkill_entry(int argc, char **argv);
int netdata_process_entry(int argc, char **argv);
int netdata_shm_entry(int argc, char **argv);
int netdata_socket_entry(int argc, char **argv);
int netdata_softirq_entry(int argc, char **argv);
int netdata_swap_entry(int argc, char **argv);
int netdata_sync_entry(int argc, char **argv);
int netdata_vfs_entry(int argc, char **argv);

#endif /* NETDATA_CORE_LOADER_H */
