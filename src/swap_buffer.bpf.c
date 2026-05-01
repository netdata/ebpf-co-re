#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#endif

#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE MY_LINUX_VERSION_CODE
#endif

#include "netdata_core.h"
#include "netdata_swap.h"
#include "netdata_swap_buffer.h"
/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(swap_events, NETDATA_SWAP_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(tbl_swap, __u32, __u64, NETDATA_SWAP_END);
NETDATA_BPF_ARRAY_DEF(swap_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_swap_fill_event(struct netdata_swap_event_t *ev, void *ctrl)
{
    __u32 tgid = 0;
    ev->ct   = bpf_ktime_get_ns();
    ev->pid  = netdata_get_pid(ctrl, &tgid);
    ev->tgid = tgid;
    libnetdata_update_uid_gid(&ev->uid, &ev->gid);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(4,11,0))
    bpf_get_current_comm(ev->name, TASK_COMM_LEN);
#else
    ev->name[0] = '\0';
#endif
    ev->pad[0] = ev->pad[1] = ev->pad[2] = 0;
}

/************************************************************************************
 *
 *                                   Probes Section
 *
 ***********************************************************************************/

SEC("kprobe/swap_read_folio")
int netdata_swap_read_folio_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_READ;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/swap_readpage")
int netdata_swap_readpage_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_READPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_READ;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__swap_writepage")
int netdata___swap_writepage_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_WRITE;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/swap_writepage")
int netdata_swap_writepage_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&tbl_swap, NETDATA_KEY_SWAP_WRITEPAGE_CALL, 1);

    if (!monitor_apps(&swap_ctrl))
        return 0;

    struct netdata_swap_event_t *ev = bpf_ringbuf_reserve(&swap_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_swap_fill_event(ev, &swap_ctrl);
    ev->action = NETDATA_SWAP_EVENT_WRITE;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
