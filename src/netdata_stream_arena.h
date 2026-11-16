// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef NETDATA_STREAM_ARENA_H
#define NETDATA_STREAM_ARENA_H

#include "netdata_stream_event.h"
#include "netdata_arena_common.h"

NETDATA_ARENA_QUEUE_DECL(collector, struct netdata_stream_event_t, NETDATA_ARENA_EVENT_SLOTS);

#endif
