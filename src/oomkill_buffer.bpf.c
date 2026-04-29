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
#include "netdata_oomkill.h"
#include "netdata_oomkill_buffer.h"
/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(oomkill_events, NETDATA_OOMKILL_RINGBUF_SIZE);

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("tracepoint/oom/mark_victim")
int netdata_oom_mark_victim_buffer(struct netdata_oom_mark_victim_entry *ptr)
{
    struct netdata_oomkill_event_t *ev = bpf_ringbuf_reserve(&oomkill_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->ct  = bpf_ktime_get_ns();
    ev->pad = 0;
    bpf_probe_read(&ev->pid, sizeof(ev->pid), &ptr->pid);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
