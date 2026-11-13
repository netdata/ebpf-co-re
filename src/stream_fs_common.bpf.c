#include "vmlinux.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include "netdata_core.h"
#include "netdata_fs.h"
#include "netdata_stream_mode.h"

#ifndef NETDATA_FS_TABLE
#error NETDATA_FS_TABLE must identify the family histogram
#endif

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_FS_MAX_ELEMENTS);
} NETDATA_FS_TABLE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4192);
} NETDATA_FS_TEMP SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} NETDATA_FS_CTRL SEC(".maps");

static __always_inline int netdata_fs_stream_entry(void)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 stamp = bpf_ktime_get_ns();
    if (!bpf_map_update_elem(&NETDATA_FS_TEMP, &tid, &stamp, BPF_ANY))
        libnetdata_update_global(&NETDATA_FS_CTRL, NETDATA_CONTROLLER_TEMP_TABLE_ADD, 1);
    return 0;
}

static __always_inline int netdata_fs_stream_exit(__u32 action)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&NETDATA_FS_TEMP, &tid);
    if (!start)
        return 0;

    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&NETDATA_FS_TEMP, &tid);
    libnetdata_update_global(&NETDATA_FS_CTRL, NETDATA_CONTROLLER_TEMP_TABLE_DEL, 1);
    if ((__s64)latency < 0)
        return 0;
    latency /= 1000;

    __u32 bin = libnetdata_select_idx(latency, NETDATA_FS_MAX_BINS_POS);
    __u32 index = action * NETDATA_FS_MAX_BINS + bin;
    if (index >= NETDATA_FS_MAX_ELEMENTS)
        return 0;
    __u64 *count = bpf_map_lookup_elem(&NETDATA_FS_TABLE, &index);
    if (count)
        libnetdata_update_u64(count, 1);
    netdata_stream_emit_fs(&NETDATA_FS_CTRL, action, latency);
    return 0;
}

SEC("kprobe/" NETDATA_FS_READ_TARGET)
int netdata_fs_stream_read_enter(struct pt_regs *ctx)
{
#ifdef NETDATA_FS_BTRFS_LEGACY_READ
    /* generic_file_read_iter also handles other file systems before 5.10. */
    struct kiocb *iocb = (struct kiocb *)PT_REGS_PARM1(ctx);
    struct file *file = BPF_CORE_READ(iocb, ki_filp);
    struct inode *inode = file ? BPF_CORE_READ(file, f_inode) : 0;
    struct super_block *sb = inode ? BPF_CORE_READ(inode, i_sb) : 0;
    struct file_system_type *type = sb ? BPF_CORE_READ(sb, s_type) : 0;
    const char *name = type ? BPF_CORE_READ(type, name) : 0;
    char fs_name[8] = { };
    if (!name || bpf_probe_read_kernel_str(fs_name, sizeof(fs_name), name) < 0 ||
        fs_name[0] != 'b' || fs_name[1] != 't' || fs_name[2] != 'r' ||
        fs_name[3] != 'f' || fs_name[4] != 's' || fs_name[5] != '\0')
        return 0;
#endif
    return netdata_fs_stream_entry();
}

SEC("kretprobe/" NETDATA_FS_READ_TARGET)
int netdata_fs_stream_read_exit(struct pt_regs *ctx)
{
    return netdata_fs_stream_exit(NETDATA_KEY_CALLS_READ);
}

SEC("kprobe/" NETDATA_FS_WRITE_TARGET)
int netdata_fs_stream_write_enter(struct pt_regs *ctx)
{
    return netdata_fs_stream_entry();
}

SEC("kretprobe/" NETDATA_FS_WRITE_TARGET)
int netdata_fs_stream_write_exit(struct pt_regs *ctx)
{
    return netdata_fs_stream_exit(NETDATA_KEY_CALLS_WRITE);
}

SEC("kprobe/" NETDATA_FS_OPEN_TARGET)
int netdata_fs_stream_open_enter(struct pt_regs *ctx)
{
    return netdata_fs_stream_entry();
}

SEC("kretprobe/" NETDATA_FS_OPEN_TARGET)
int netdata_fs_stream_open_exit(struct pt_regs *ctx)
{
    return netdata_fs_stream_exit(NETDATA_KEY_CALLS_OPEN);
}

#ifdef NETDATA_FS_EXTRA_OPEN_TARGET
SEC("kprobe/" NETDATA_FS_EXTRA_OPEN_TARGET)
int netdata_fs_stream_extra_open_enter(struct pt_regs *ctx)
{
    return netdata_fs_stream_entry();
}

SEC("kretprobe/" NETDATA_FS_EXTRA_OPEN_TARGET)
int netdata_fs_stream_extra_open_exit(struct pt_regs *ctx)
{
    return netdata_fs_stream_exit(NETDATA_KEY_CALLS_OPEN);
}
#endif

SEC("kprobe/" NETDATA_FS_SYNC_TARGET)
int netdata_fs_stream_sync_enter(struct pt_regs *ctx)
{
    return netdata_fs_stream_entry();
}

SEC("kretprobe/" NETDATA_FS_SYNC_TARGET)
int netdata_fs_stream_sync_exit(struct pt_regs *ctx)
{
    return netdata_fs_stream_exit(NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";
