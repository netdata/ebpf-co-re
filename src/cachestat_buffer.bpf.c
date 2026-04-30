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
#include "netdata_cache.h"
#include "netdata_cache_buffer.h"
/************************************************************************************
 *
 *                                 MAPS Section
 *
 ***********************************************************************************/

NETDATA_BPF_RINGBUF_DEF(cachestat_events, NETDATA_CACHESTAT_RINGBUF_SIZE);
NETDATA_BPF_PERCPU_ARRAY_DEF(cstat_global, __u32, __u64, NETDATA_CACHESTAT_END);
NETDATA_BPF_ARRAY_DEF(cstat_ctrl, __u32, __u64, NETDATA_CONTROLLER_END);

/************************************************************************************
 *
 *                                Local Functions
 *
 ***********************************************************************************/

static __always_inline void netdata_cachestat_fill_event(struct netdata_cachestat_event_t *ev, void *ctrl)
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

SEC("kprobe/add_to_page_cache_lru")
int netdata_add_to_page_cache_lru_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_CACHE_LRU;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/mark_page_accessed")
int netdata_mark_page_accessed_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_ACCESSED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__folio_mark_dirty")
int netdata_folio_mark_dirty_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/__set_page_dirty")
int netdata_set_page_dirty_buffer(struct pt_regs *ctx)
{
    /* On 5.15, __set_page_dirty is called for all pages; skip anonymous ones. */
    struct page *page = (struct page *)PT_REGS_PARM1(ctx);
    struct address_space *mapping = _(page->mapping);
    if (!mapping)
        return 0;

    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/account_page_dirtied")
int netdata_account_page_dirtied_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_PAGE_DIRTIED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

SEC("kprobe/mark_buffer_dirty")
int netdata_mark_buffer_dirty_buffer(struct pt_regs *ctx)
{
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY, 1);

    if (!monitor_apps(&cstat_ctrl))
        return 0;

    struct netdata_cachestat_event_t *ev = bpf_ringbuf_reserve(&cachestat_events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    netdata_cachestat_fill_event(ev, &cstat_ctrl);
    ev->action = NETDATA_CACHESTAT_EVENT_BUFFER_DIRTY;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
