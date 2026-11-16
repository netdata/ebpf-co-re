// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NETDATA_STREAM_CORE_H
#define NETDATA_STREAM_CORE_H

/* Keep this record layout and its action values in sync with the pinned
 * kernel-collector/includes/netdata_stream.h. CO-RE needs a different pointer
 * annotation for ring buffers and arenas. */
#include "netdata_arena_common.h"

#include "netdata_stream_event.h"

#ifdef NETDATA_STREAM_ARENA
#define NETDATA_STREAM_PTR __arena
NETDATA_ARENA_QUEUE_DECL(collector, struct netdata_stream_event_t, NETDATA_ARENA_EVENT_SLOTS);
struct netdata_collector_arena_state_t collector_arena_state __arena_global = {
    .version = NETDATA_ARENA_QUEUE_VERSION,
};
NETDATA_BPF_ARENA_DEF(collector_events, NETDATA_STREAM_RINGBUF_SIZE);
#define NETDATA_STREAM_RESERVE() netdata_collector_arena_reserve()
#define NETDATA_STREAM_SUBMIT(event) netdata_collector_arena_submit(event)
#else
#define NETDATA_STREAM_PTR
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, NETDATA_STREAM_RINGBUF_SIZE);
} collector_events SEC(".maps");
#define NETDATA_STREAM_RESERVE() bpf_ringbuf_reserve(&collector_events, sizeof(struct netdata_stream_event_t), 0)
#define NETDATA_STREAM_SUBMIT(event) bpf_ringbuf_submit(event, 0)
#endif

static __always_inline struct netdata_stream_event_t NETDATA_STREAM_PTR *
netdata_stream_begin(void *ctrl, __u32 action)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = NETDATA_STREAM_RESERVE();
    __u32 tgid = 0;
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = ctrl ? netdata_get_pid(ctrl, &tgid) : netdata_get_current_pid(&tgid);
    event->tgid = tgid;
    event->action = action;
    return event;
}

static __always_inline void netdata_stream_emit_call(void *ctrl, __u32 action)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, action);
    if (event)
        NETDATA_STREAM_SUBMIT(event);
}

static __always_inline void netdata_stream_emit_fs(void *ctrl, __u32 action, __u64 latency_us)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.fs.latency_us = latency_us;
    NETDATA_STREAM_SUBMIT(event);
}

static __always_inline void netdata_stream_emit_disk(void *ctrl, __u32 device, __u64 sector, __u64 latency_us)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, NETDATA_STREAM_DISK_COMPLETE);
    if (!event)
        return;
    event->details.disk.device = device;
    event->details.disk.sector = sector;
    event->details.disk.latency_us = latency_us;
    NETDATA_STREAM_SUBMIT(event);
}

static __always_inline void netdata_stream_emit_md(void *ctrl, __u32 unit)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, NETDATA_STREAM_MD_FLUSH);
    if (!event)
        return;
    event->details.md.unit = unit;
    NETDATA_STREAM_SUBMIT(event);
}

static __always_inline void netdata_stream_emit_mount(void *ctrl, __u32 action, __s32 result, __u32 result_known)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.mount.result = result;
    event->details.mount.result_known = result_known;
    NETDATA_STREAM_SUBMIT(event);
}

static __always_inline void netdata_stream_emit_network(void *ctrl, __u32 action,
                                                        const netdata_nv_idx_t *key,
                                                        const netdata_nv_data_t *data)
{
    struct netdata_stream_event_t NETDATA_STREAM_PTR *event = netdata_stream_begin(ctrl, action);
    if (!event)
        return;
    event->details.network.key = *key;
    event->details.network.data = *data;
    NETDATA_STREAM_SUBMIT(event);
}

#endif
