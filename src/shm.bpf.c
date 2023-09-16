#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_shm.h"

/************************************************************************************
 *
 *                                 MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SHM_END);
} tbl_shm  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, __u32);
    __type(value, netdata_shm_t);
    __uint(max_entries, PID_MAX_DEFAULT);
} tbl_pid_shm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} shm_ctrl SEC(".maps");

/************************************************************************************
 *
 *                     SHARED MEMORY (common)
 *
 ***********************************************************************************/

static __always_inline void netdata_update_stored_data(netdata_shm_t *data, __u32 selector)
{
    // we are using if/else if instead switch to avoid warnings
    if (selector == NETDATA_KEY_SHMGET_CALL)
        libnetdata_update_u32(&data->get, 1);
    else if (selector == NETDATA_KEY_SHMAT_CALL)
        libnetdata_update_u32(&data->at, 1);
    else if (selector == NETDATA_KEY_SHMDT_CALL)
        libnetdata_update_u32(&data->dt, 1);
    else if (selector == NETDATA_KEY_SHMCTL_CALL)
        libnetdata_update_u32(&data->ctl, 1);
}

static __always_inline void netdata_set_structure_value(netdata_shm_t *data, __u32 selector)
{
    // we are using if/else if instead switch to avoid warnings
    if (selector == NETDATA_KEY_SHMGET_CALL)
        data->get = 1;
    else if (selector == NETDATA_KEY_SHMAT_CALL)
        data->at = 1;
    else if (selector == NETDATA_KEY_SHMDT_CALL)
        data->dt = 1;
    else if (selector == NETDATA_KEY_SHMCTL_CALL)
        data->ctl = 1;
}

static __always_inline int netdata_update_apps(__u32 idx)
{
    netdata_shm_t data = {};

    __u32 key;
    netdata_shm_t *fill = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (fill) {
        netdata_update_stored_data(fill, idx);
    } else {
        data.ct = bpf_ktime_get_ns();
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
        bpf_get_current_comm(&data.name, TASK_COMM_LEN);
#else
        data.name[0] = '\0';
#endif        

        netdata_set_structure_value(&data, idx);
        bpf_map_update_elem(&tbl_pid_shm, &key, &data, BPF_ANY);

        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    }

    return 0;
}

static __always_inline int netdata_global_apps_shm(__u32 idx)
{
    libnetdata_update_global(&tbl_shm, idx, 1);

    // check if apps is enabled; if not, don't record apps data.
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl, &key);
    if (apps) {
        if (*apps == 0) {
            return 0;
        }
    }

    return 1;
}

static __always_inline int netdata_ebpf_common_shmget()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMGET_CALL);
    if (!store_apps)
        return 0;

    return netdata_update_apps(NETDATA_KEY_SHMGET_CALL);
}

static __always_inline int netdata_ebpf_common_shmat()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMAT_CALL);
    if (!store_apps)
        return 0;

    return netdata_update_apps(NETDATA_KEY_SHMAT_CALL);
}

static __always_inline int netdata_ebpf_common_shmdt()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMDT_CALL);
    if (!store_apps)
        return 0;

    return netdata_update_apps(NETDATA_KEY_SHMDT_CALL);
}

static __always_inline int netdata_ebpf_common_shmctl()
{
    int store_apps = netdata_global_apps_shm(NETDATA_KEY_SHMCTL_CALL);
    if (!store_apps)
        return 0;

    return netdata_update_apps(NETDATA_KEY_SHMCTL_CALL);
}

static __always_inline int netdata_release_task_shm()
{
    netdata_shm_t *removeme;
    __u32 key = NETDATA_CONTROLLER_APPS_ENABLED;
    __u32 *apps = bpf_map_lookup_elem(&shm_ctrl ,&key);
    if (!apps || (apps && !*apps))
        return 0;

    removeme = netdata_get_pid_structure(&key, &shm_ctrl, &tbl_pid_shm);
    if (removeme) {
        bpf_map_delete_elem(&tbl_pid_shm, &key);
        libnetdata_update_global(&shm_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);
    }

    return 0;
}

/************************************************************************************
 *
 *                     SHARED MEMORY (tracepoint)
 *
 ***********************************************************************************/

SEC("tracepoint/syscalls/sys_enter_shmget")
int netdata_syscall_shmget(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmget();
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int netdata_syscall_shmat(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmat();
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int netdata_syscall_shmdt(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmdt();
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int netdata_syscall_shmctl(struct trace_event_raw_sys_enter *arg)
{
    return netdata_ebpf_common_shmctl();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (kprobe)
 *
 ***********************************************************************************/

SEC("kprobe/netdata_shmget_probe")
int BPF_KPROBE(netdata_shmget_probe)
{
    return netdata_ebpf_common_shmget();
}

SEC("kprobe/netdata_shmat_probe")
int BPF_KPROBE(netdata_shmat_probe)
{
    return netdata_ebpf_common_shmat();
}

SEC("kprobe/netdata_shmdt_probe")
int BPF_KPROBE(netdata_shmdt_probe)
{
    return netdata_ebpf_common_shmdt();
}

SEC("kprobe/netdata_shmctl_probe")
int BPF_KPROBE(netdata_shmctl_probe)
{
    return netdata_ebpf_common_shmctl();
}

SEC("kprobe/release_task")
int BPF_KPROBE(netdata_shm_release_task_probe)
{
    return netdata_release_task_shm();
}

/************************************************************************************
 *
 *                     SHARED MEMORY (trampoline)
 *
 ***********************************************************************************/

SEC("fentry/netdata_shmget")
int BPF_PROG(netdata_shmget_fentry)
{
    return netdata_ebpf_common_shmget();
}

SEC("fentry/netdata_shmat")
int BPF_PROG(netdata_shmat_fentry)
{
    return netdata_ebpf_common_shmat();
}

SEC("fentry/netdata_shmdt")
int BPF_PROG(netdata_shmdt_fentry)
{
    return netdata_ebpf_common_shmdt();
}

SEC("fentry/netdata_shmctl")
int BPF_PROG(netdata_shmctl_fentry)
{
    return netdata_ebpf_common_shmctl();
}

SEC("fentry/release_task")
int BPF_PROG(netdata_shm_release_task_fentry)
{
    return netdata_release_task_shm();
}

char _license[] SEC("license") = "GPL";

