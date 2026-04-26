#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#include "netdata_core.h"
#include "netdata_disk.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

//Hardware
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, block_key_t);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DISK_HISTOGRAM_LENGTH);
} tbl_disk_iocall SEC(".maps");

// Temporary use only
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, netdata_disk_key_t);
    __type(value, __u64);
    __uint(max_entries, 8192);
} tmp_disk_tp_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} disk_ctrl SEC(".maps");


/************************************************************************************
 *
 *                                 Helper Functions
 *
 ***********************************************************************************/

static __always_inline netdata_disk_key_t netdata_disk_key(void *ptr)
{
    struct netdata_block_rq_issue *issue = ptr;
    netdata_disk_key_t key = {
        .dev = issue->dev,
        .pad = 0,
        .sector = (issue->sector < 0) ? 0 : issue->sector
    };

    return key;
}

/************************************************************************************
 *
 *                                 Tracepoints
 *
 ***********************************************************************************/

SEC("tracepoint/block/block_rq_issue")
int netdata_block_rq_issue(struct netdata_block_rq_issue *ptr)
{
    // blkid generates these and we're not interested in them
    if (!ptr->dev)
        return 0;

    netdata_disk_key_t key = netdata_disk_key(ptr);

    __u64 value = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_disk_tp_stat, &key, &value, BPF_ANY);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);

    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int netdata_block_rq_complete(struct netdata_block_rq_complete *ptr)
{
    netdata_disk_key_t key = netdata_disk_key(ptr);
    __u64 *fill = bpf_map_lookup_elem(&tmp_disk_tp_stat, &key);
    if (!fill)
        return 0;

    // calculate and convert to microsecond
    __u64 curr = bpf_ktime_get_ns() - *fill;
    curr /= 1000;

    block_key_t blk = {
        .bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS),
        .dev = netdata_new_encode_dev(ptr->dev)
    };

    // Update IOPS
    __u64 *update = bpf_map_lookup_elem(&tbl_disk_iocall, &blk);
    if (update) {
        libnetdata_update_u64(update, 1);
    } else {
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &(__u64){1}, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);

    return 0;
}

char _license[] SEC("license") = "GPL";
