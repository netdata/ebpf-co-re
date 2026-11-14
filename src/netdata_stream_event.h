// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NETDATA_STREAM_EVENT_H
#define NETDATA_STREAM_EVENT_H

#include "netdata_socket.h"

#define NETDATA_STREAM_RINGBUF_SIZE (1 << 20)

enum netdata_stream_action {
    NETDATA_STREAM_CALL = 1,
    NETDATA_STREAM_MOUNT = 2,
    NETDATA_STREAM_UMOUNT = 3,
    NETDATA_STREAM_MD_FLUSH = 4,
    NETDATA_STREAM_DISK_COMPLETE = 5,
    NETDATA_STREAM_NV_ACCEPT = 16,
    NETDATA_STREAM_NV_TCP_SEND = 17,
    NETDATA_STREAM_NV_TCP_RETRANSMIT = 18,
    NETDATA_STREAM_NV_TCP_STATE = 19,
    NETDATA_STREAM_NV_TCP_RECEIVE = 20,
    NETDATA_STREAM_NV_TCP_V4_CONNECT = 21,
    NETDATA_STREAM_NV_TCP_V6_CONNECT = 22,
    NETDATA_STREAM_NV_TCP_CLOSE = 23,
    NETDATA_STREAM_NV_UDP_RECEIVE = 24,
    NETDATA_STREAM_NV_UDP_SEND = 25,
};

struct netdata_stream_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 action;
    __u32 reserved;
    union {
        struct { __u64 latency_us; } fs;
        struct { __u64 latency_us; __u64 sector; __u32 device; __u32 reserved; } disk;
        struct { __u32 unit; } md;
        struct { __s32 result; __u32 result_known; } mount;
        struct { netdata_nv_idx_t key; netdata_nv_data_t data; } network;
    } details;
};

#endif
