#define __BPF_FEATURE_ADDR_SPACE_CAST 1

#include "vmlinux_508.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_arena_compat.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#include "netdata_socket_arena.h"

struct netdata_socket_arena_state_t socket_arena_state __arena_global;

#define NETDATA_ARENA_MODE 1
#define NETDATA_BPF_RINGBUF_DEF(NAME, MAX_ENTRIES) NETDATA_BPF_ARENA_DEF(NAME, MAX_ENTRIES)
#define bpf_ringbuf_reserve(MAP, SIZE, FLAGS) netdata_socket_arena_reserve()
#define bpf_ringbuf_submit(EV, FLAGS) netdata_socket_arena_submit(EV)

#include "socket_buffer.bpf.c"
