#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

#include "netdata_core.h"
#include "netdata_disk.h"

struct request_queue___new {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct gendisk___new {
    struct block_device___new *part0;
} __attribute__((preserve_access_index));

struct block_device___new {
    dev_t bd_dev;
} __attribute__((preserve_access_index));

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, block_key_t);
    __type(value, __u64);
    __uint(max_entries, NETDATA_DISK_HISTOGRAM_LENGTH);
} tbl_disk_iocall SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, netdata_disk_inflight_t);
    __uint(max_entries, 8192);
} tmp_disk_tp_stat SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, NETDATA_CONTROLLER_END);
} disk_ctrl SEC(".maps");

static __always_inline int netdata_disk_request_key(struct request *rq, netdata_disk_key_t *key)
{
    struct gendisk *disk = NULL;

    if (!rq)
        return 0;

    if (bpf_core_field_exists(((struct request *)0)->rq_disk)) {
        if (BPF_CORE_READ_INTO(&disk, rq, rq_disk))
            return 0;
    } else {
        struct request_queue *queue = NULL;
        if (BPF_CORE_READ_INTO(&queue, rq, q) || !queue ||
            BPF_CORE_READ_INTO(&disk, (struct request_queue___new *)queue, disk))
            return 0;
    }
    if (!disk)
        return 0;

    key->dev = 0;
    key->pad = 0;
    key->sector = 0;

    if (bpf_core_field_exists(((struct gendisk *)0)->part0.__dev.devt)) {
        if (BPF_CORE_READ_INTO(&key->dev, disk, part0.__dev.devt))
            return 0;
    } else {
        struct block_device___new *part = NULL;
        if (BPF_CORE_READ_INTO(&part, (struct gendisk___new *)disk, part0) || !part ||
            BPF_CORE_READ_INTO(&key->dev, part, bd_dev))
            return 0;
    }

    if (BPF_CORE_READ_INTO(&key->sector, rq, __sector))
        return 0;
    if ((s64)key->sector < 0)
        key->sector = 0;

    return key->dev != 0;
}

static __always_inline int netdata_block_rq_issue_impl(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    netdata_disk_inflight_t value = { };
    __u64 request_key = (__u64)rq;

    if (!rq || !netdata_disk_request_key(rq, &value.key))
        return 0;

    value.timestamp = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&tmp_disk_tp_stat, &request_key, &value, BPF_ANY))
        return 0;

    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_ADD, 1);
    return 0;
}

SEC("kprobe/blk_mq_start_request")
int netdata_block_rq_issue(struct pt_regs *ctx)
{
    return netdata_block_rq_issue_impl(ctx);
}

SEC("kprobe/blk_start_request")
int netdata_block_rq_issue_legacy(struct pt_regs *ctx)
{
    return netdata_block_rq_issue_impl(ctx);
}

static __always_inline int netdata_block_rq_complete_impl(struct pt_regs *ctx)
{
    struct request *rq = (struct request *)PT_REGS_PARM1(ctx);
    __u64 request_key = (__u64)rq;
    netdata_disk_inflight_t *fill;

    if (!rq)
        return 0;

    fill = bpf_map_lookup_elem(&tmp_disk_tp_stat, &request_key);
    if (!fill)
        return 0;

    __u64 curr = (bpf_ktime_get_ns() - fill->timestamp) / 1000;
    block_key_t blk = {
        .bin = libnetdata_select_idx(curr, NETDATA_FS_MAX_BINS_POS),
        .dev = netdata_new_encode_dev(fill->key.dev)
    };

    __u64 *update = bpf_map_lookup_elem(&tbl_disk_iocall, &blk);
    if (update)
        libnetdata_update_u64(update, 1);
    else
        bpf_map_update_elem(&tbl_disk_iocall, &blk, &(__u64){1}, BPF_ANY);

    bpf_map_delete_elem(&tmp_disk_tp_stat, &request_key);
    libnetdata_update_global(&disk_ctrl, NETDATA_CONTROLLER_PID_TABLE_DEL, 1);
    return 0;
}

SEC("kprobe/blk_mq_end_request")
int netdata_block_rq_complete(struct pt_regs *ctx)
{
    return netdata_block_rq_complete_impl(ctx);
}

SEC("kprobe/__blk_mq_end_request")
int netdata_block_rq_complete_internal(struct pt_regs *ctx)
{
    return netdata_block_rq_complete_impl(ctx);
}

SEC("kprobe/blk_mq_free_request")
int netdata_block_rq_complete_free(struct pt_regs *ctx)
{
    return netdata_block_rq_complete_impl(ctx);
}

SEC("kprobe/blk_complete_request")
int netdata_blk_complete_request(struct pt_regs *ctx)
{
    return netdata_block_rq_complete_impl(ctx);
}

char _license[] SEC("license") = "GPL";
