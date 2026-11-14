// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NETDATA_STREAM_MODE_H
#define NETDATA_STREAM_MODE_H

#if defined(NETDATA_STREAM_BUFFER) || defined(NETDATA_STREAM_ARENA)
#include "netdata_socket.h"
#ifdef NETDATA_STREAM_ARENA
#include "bpf_arena_compat.h"
#endif
#include "netdata_stream_core.h"
#else
#define NETDATA_STREAM_CALL 1
#define NETDATA_STREAM_MOUNT 2
#define NETDATA_STREAM_UMOUNT 3
#define NETDATA_STREAM_NV_ACCEPT 16
#define NETDATA_STREAM_NV_TCP_SEND 17
#define NETDATA_STREAM_NV_TCP_RETRANSMIT 18
#define NETDATA_STREAM_NV_TCP_STATE 19
#define NETDATA_STREAM_NV_TCP_RECEIVE 20
#define NETDATA_STREAM_NV_TCP_V4_CONNECT 21
#define NETDATA_STREAM_NV_TCP_V6_CONNECT 22
#define NETDATA_STREAM_NV_TCP_CLOSE 23
#define NETDATA_STREAM_NV_UDP_RECEIVE 24
#define NETDATA_STREAM_NV_UDP_SEND 25
#define netdata_stream_emit_call(ctrl, action) ((void)0)
#define netdata_stream_emit_fs(ctrl, action, latency) ((void)0)
#define netdata_stream_emit_disk(ctrl, device, sector, latency) ((void)0)
#define netdata_stream_emit_md(ctrl, unit) ((void)0)
#define netdata_stream_emit_mount(ctrl, action, result, known) ((void)0)
#define netdata_stream_emit_network(ctrl, action, key, data) ((void)0)
#endif

#endif
