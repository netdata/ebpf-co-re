#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_dc.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DIRECTORY_CACHE_END);
} dcstat_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, netdata_dc_stat_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} dcstat_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} dcstat_ctrl SEC(".maps");

/***********************************************************************************
 *
 *                               DC COMMON
 *
 ***********************************************************************************/

static __always_inline int netdata_common_lookup_fast()
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_REFERENCE, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (apps)
        if (*apps == 0)
            return 0;

    fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
    if (fill) {
        libnetdata_update_u64(&fill->references, 1);
    } else {
        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
    }

    return 0;
}

static __always_inline int netdata_common_d_lookup(long ret)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (!apps)
        return 0;

    if (*apps == 1) {
        fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
        if (fill) {
            libnetdata_update_u64(&fill->slow, 1);
        } else {
            data.slow = 1;
            bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
        }
    }

    // file not found
    if (!ret) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        if (*apps == 1) {
            fill = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
            if (fill) {
                libnetdata_update_u64(&fill->missed, 1);
            } else {
                data.missed = 1;
                bpf_map_update_elem(&dcstat_pid, &key, &data, BPF_ANY);
            }
        }
    }

    return 0;
}

static inline int netdata_release_task_dcstat()
{
    netdata_dc_stat_t *removeme;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&dcstat_ctrl ,&key);
    if (apps) {
        if (*apps == 0)
            return 0;
    } else
        return 0;

    removeme = netdata_get_pid_structure(&key, &dcstat_ctrl, &dcstat_pid);
    if (removeme) {
        bpf_map_delete_elem(&dcstat_pid, &key);
    }

    return 0;
}

/***********************************************************************************
 *
 *                            DC SECTION(kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int BPF_KPROBE(netdata_lookup_fast_kprobe)
{
    return netdata_common_lookup_fast();
}

SEC("kretprobe/d_lookup")
int BPF_KRETPROBE(netdata_d_lookup_kretprobe)
{
    long ret = PT_REGS_RC(ctx);

    return netdata_common_d_lookup(ret);
}

SEC("kprobe/release_task")
int BPF_KPROBE(netdata_dcstat_release_task_kprobe)
{
    return netdata_release_task_dcstat();
}

/***********************************************************************************
 *
 *                            DC SECTION(trampoline)
 *
 ***********************************************************************************/

SEC("fentry/lookup_fast")
int BPF_PROG(netdata_lookup_fast_fentry)
{
    return netdata_common_lookup_fast();
}

SEC("fexit/d_lookup")
int BPF_PROG(netdata_d_lookup_fexit, const struct dentry *parent, const struct qstr *name, 
             struct dentry *ret)
{
    return netdata_common_d_lookup((long)ret);
}

SEC("fentry/release_task")
int BPF_PROG(netdata_dcstat_release_task_fentry)
{
    return netdata_release_task_dcstat();
}

char _license[] SEC("license") = "GPL";

