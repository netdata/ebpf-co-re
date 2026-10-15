#define __BPF_FEATURE_ADDR_SPACE_CAST 1

#if MY_LINUX_VERSION_CODE >= 332544
#include "vmlinux_519.h"
#else
#include "vmlinux_508.h"
#endif
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "bpf_arena_compat.h"

#define NETDATA_SOCKET_BUFFER_MODE
#define NETDATA_ARENA_MODE
#include "netdata_socket_arena.h"

struct netdata_socket_arena_state_t socket_arena_state __arena_global;

NETDATA_BPF_ARENA_DEF(socket_events, NETDATA_SOCKET_RINGBUF_SIZE);

#include "socket.bpf.c"
