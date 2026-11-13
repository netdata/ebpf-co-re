#include "vmlinux.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_sync.h"
#include "netdata_stream_mode.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_SYNC_END);
} NETDATA_SYNC_TABLE SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_" NETDATA_SYNC_NAME)
int netdata_stream_sync_entry(struct trace_event_raw_sys_enter *ctx)
{
    libnetdata_update_global(&NETDATA_SYNC_TABLE, NETDATA_KEY_SYNC_CALL, 1);
    netdata_stream_emit_call(0, NETDATA_STREAM_CALL);
    return 0;
}

char _license[] SEC("license") = "GPL";
