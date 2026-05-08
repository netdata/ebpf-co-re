package main

/*
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "netdata_core_loader.h"
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

static void netdata_disable_libbpf_memlock_rlim(void)
{
	libbpf_set_memlock_rlim(0);
}

// BPF_MAP_TYPE_RINGBUF requires kernel >= 5.8 (version code 329728).
#if MY_LINUX_VERSION_CODE >= 329728
#include "cachestat_buffer.skel.h"
#include "dc_buffer.skel.h"
#include "dns_buffer.skel.h"
#include "fd_buffer.skel.h"
#include "oomkill_buffer.skel.h"
#include "process_buffer.skel.h"
#include "shm_buffer.skel.h"
#include "swap_buffer.skel.h"
#include "vfs_buffer.skel.h"

struct netdata_core_ringbuf_stats {
	size_t samples;
	size_t bytes;
};

static int netdata_core_ringbuf_sample_cb(void *ctx, void *data, size_t size)
{
	struct netdata_core_ringbuf_stats *stats = ctx;

	(void)data;
	if (stats) {
		stats->samples++;
		stats->bytes += size;
	}

	return 0;
}

struct netdata_core_buffer_skel_base {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
};

struct netdata_core_buffer_skel_ops {
	const char *name;
	void *(*open)(void);
	int (*load)(void *skel);
	void (*destroy)(void *skel);
};

#define DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(prefix)                                 \
	static void *netdata_core_open_##prefix(void)                                   \
	{                                                                               \
		return prefix##_bpf__open();                                                \
	}                                                                               \
                                                                                    \
	static int netdata_core_load_##prefix(void *skel)                               \
	{                                                                               \
		return prefix##_bpf__load(skel);                                            \
	}                                                                               \
                                                                                    \
	static void netdata_core_destroy_##prefix(void *skel)                           \
	{                                                                               \
		prefix##_bpf__destroy(skel);                                                \
	}

DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(cachestat_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(dc_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(dns_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(fd_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(oomkill_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(process_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(shm_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(swap_buffer)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(vfs_buffer)

static const struct netdata_core_buffer_skel_ops netdata_core_buffer_skel_ops[] = {
	{ "cachestat", netdata_core_open_cachestat_buffer, netdata_core_load_cachestat_buffer, netdata_core_destroy_cachestat_buffer },
	{ "dc", netdata_core_open_dc_buffer, netdata_core_load_dc_buffer, netdata_core_destroy_dc_buffer },
	{ "dns", netdata_core_open_dns_buffer, netdata_core_load_dns_buffer, netdata_core_destroy_dns_buffer },
	{ "fd", netdata_core_open_fd_buffer, netdata_core_load_fd_buffer, netdata_core_destroy_fd_buffer },
	{ "oomkill", netdata_core_open_oomkill_buffer, netdata_core_load_oomkill_buffer, netdata_core_destroy_oomkill_buffer },
	{ "process", netdata_core_open_process_buffer, netdata_core_load_process_buffer, netdata_core_destroy_process_buffer },
	{ "shm", netdata_core_open_shm_buffer, netdata_core_load_shm_buffer, netdata_core_destroy_shm_buffer },
	{ "swap", netdata_core_open_swap_buffer, netdata_core_load_swap_buffer, netdata_core_destroy_swap_buffer },
	{ "vfs", netdata_core_open_vfs_buffer, netdata_core_load_vfs_buffer, netdata_core_destroy_vfs_buffer },
};

static const struct netdata_core_buffer_skel_ops *netdata_core_find_buffer_skel_ops(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(netdata_core_buffer_skel_ops) / sizeof(netdata_core_buffer_skel_ops[0]); i++) {
		if (!strcmp(netdata_core_buffer_skel_ops[i].name, name))
			return &netdata_core_buffer_skel_ops[i];
	}

	return NULL;
}

// BPF_MAP_TYPE_ARENA requires kernel >= 6.9 (version code 395520).
#if MY_LINUX_VERSION_CODE >= 395520
#include "netdata_cachestat_arena.h"
#include "netdata_dc_arena.h"
#include "netdata_dns_arena.h"
#include "netdata_fd_arena.h"
#include "netdata_oomkill_arena.h"
#include "netdata_process_arena.h"
#include "netdata_shm_arena.h"
#include "netdata_swap_arena.h"
#include "netdata_vfs_arena.h"

#include "cachestat_arena.skel.h"
#include "dc_arena.skel.h"
#include "dns_arena.skel.h"
#include "fd_arena.skel.h"
#include "oomkill_arena.skel.h"
#include "process_arena.skel.h"
#include "shm_arena.skel.h"
#include "swap_arena.skel.h"
#include "vfs_arena.skel.h"

// cgo and some compilers are more conservative about inline skeleton helpers.
#define DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(prefix) \
	struct prefix##_bpf; \
	static struct prefix##_bpf *prefix##_bpf__open(void); \
	static int prefix##_bpf__load(struct prefix##_bpf *obj); \
	static void prefix##_bpf__destroy(struct prefix##_bpf *obj)

DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(cachestat_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(dc_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(dns_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(fd_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(oomkill_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(process_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(shm_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(swap_arena);
DECLARE_NETDATA_CORE_ARENA_SKEL_OPS(vfs_arena);
#undef DECLARE_NETDATA_CORE_ARENA_SKEL_OPS

DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(cachestat_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(dc_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(dns_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(fd_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(oomkill_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(process_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(shm_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(swap_arena)
DEFINE_NETDATA_CORE_BUFFER_SKEL_OPS(vfs_arena)

static const struct netdata_core_buffer_skel_ops netdata_core_arena_skel_ops[] = {
	{ "cachestat", netdata_core_open_cachestat_arena, netdata_core_load_cachestat_arena, netdata_core_destroy_cachestat_arena },
	{ "dc", netdata_core_open_dc_arena, netdata_core_load_dc_arena, netdata_core_destroy_dc_arena },
	{ "dns", netdata_core_open_dns_arena, netdata_core_load_dns_arena, netdata_core_destroy_dns_arena },
	{ "fd", netdata_core_open_fd_arena, netdata_core_load_fd_arena, netdata_core_destroy_fd_arena },
	{ "oomkill", netdata_core_open_oomkill_arena, netdata_core_load_oomkill_arena, netdata_core_destroy_oomkill_arena },
	{ "process", netdata_core_open_process_arena, netdata_core_load_process_arena, netdata_core_destroy_process_arena },
	{ "shm", netdata_core_open_shm_arena, netdata_core_load_shm_arena, netdata_core_destroy_shm_arena },
	{ "swap", netdata_core_open_swap_arena, netdata_core_load_swap_arena, netdata_core_destroy_swap_arena },
	{ "vfs", netdata_core_open_vfs_arena, netdata_core_load_vfs_arena, netdata_core_destroy_vfs_arena },
};

static const struct netdata_core_buffer_skel_ops *netdata_core_find_arena_skel_ops(const char *name)
{
	size_t i;

	for (i = 0; i < sizeof(netdata_core_arena_skel_ops) / sizeof(netdata_core_arena_skel_ops[0]); i++) {
		if (!strcmp(netdata_core_arena_skel_ops[i].name, name))
			return &netdata_core_arena_skel_ops[i];
	}

	return NULL;
}
#endif // MY_LINUX_VERSION_CODE >= 395520

static void netdata_core_fill_ctrl_map(struct bpf_object *obj, const char *ctrl_name, int map_level)
{
	struct bpf_map *map;
	int fd;
	unsigned long long values[] = { 1, (unsigned long long)map_level, 0, 0, 0, 0 };
	unsigned int i;
	unsigned int max_entries;

	if (!ctrl_name || !ctrl_name[0])
		return;

	map = bpf_object__find_map_by_name(obj, ctrl_name);
	if (!map)
		return;

	fd = bpf_map__fd(map);
	max_entries = bpf_map__max_entries(map);
	for (i = 0; i < max_entries && i < sizeof(values) / sizeof(values[0]); i++)
		bpf_map_update_elem(fd, &i, &values[i], 0);
}

static int netdata_core_test_ringbuf_map(struct bpf_map *map, int iterations,
					 char *map_json_buf, int map_json_size)
{
	int map_type = (int)bpf_map__type(map);
	int fd = bpf_map__fd(map);
	unsigned int key_size = (unsigned int)bpf_map__key_size(map);
	unsigned int value_size = (unsigned int)bpf_map__value_size(map);
	const char *mode = (map_type == BPF_MAP_TYPE_USER_RINGBUF) ? "user_ringbuf_producer" : "ringbuf_consumer";
	int setup_err = 0;
	int op_err = 0;
	int i;
	int pos = 0;
	int n;

	if (iterations < 1)
		iterations = 1;

	n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
		"{\n"
		"            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
		"                       \"Type\" : %d,\n"
		"                       \"FD\" : %d,\n"
		"                       \"Data\" : [\n",
		key_size, value_size, map_type, fd);
	if (n > 0) pos += n;

	if (map_type == BPF_MAP_TYPE_RINGBUF) {
		struct netdata_core_ringbuf_stats stats = { 0 };
		struct netdata_core_ringbuf_stats prev = { 0 };
		struct ring_buffer *rb = ring_buffer__new(fd, netdata_core_ringbuf_sample_cb, &stats, NULL);
		setup_err = (int)libbpf_get_error(rb);
		if (setup_err) {
			rb = NULL;
			op_err = setup_err;
		}

		for (i = 0; i < iterations; i++) {
			size_t iter_samples = 0;
			size_t iter_bytes = 0;
			size_t ring_sz = 0;
			size_t avail = 0;
			int cur_result = 0;

			sleep(10);

			if (rb) {
				struct ring *ring = ring_buffer__ring(rb, 0);
				cur_result = ring_buffer__poll(rb, 0);
				if (cur_result < 0)
					op_err = cur_result;

				iter_samples = stats.samples - prev.samples;
				iter_bytes = stats.bytes - prev.bytes;
				prev = stats;

				if (ring) {
					ring_sz = ring__size(ring);
					avail = ring__avail_data_size(ring);
				}
			}

			if (pos < map_json_size - 1) {
				if (i > 0) {
					n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos), ",\n");
					if (n > 0) pos += n;
				}
				n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
					"                                    "
					"{ \"Iteration\" : %d, \"Mode\" : \"%s\", \"Setup\" : %d, "
					"\"Operation Result\" : %d, \"Samples\" : %zu, \"Bytes\" : %zu, "
					"\"Available\" : %zu, \"Ring Size\" : %zu, \"Error Code\" : %d, "
					"\"Error Message\" : \"%s\" }",
					i, mode, !setup_err, cur_result,
					iter_samples, iter_bytes, avail, ring_sz,
					op_err, op_err ? strerror(-op_err) : "No error information");
				if (n > 0) pos += n;
			}
		}

		if (rb)
			ring_buffer__free(rb);

	} else if (map_type == BPF_MAP_TYPE_USER_RINGBUF) {
		struct user_ring_buffer *rb = user_ring_buffer__new(fd, NULL);
		setup_err = (int)libbpf_get_error(rb);
		if (setup_err) {
			rb = NULL;
			op_err = setup_err;
		}

		for (i = 0; i < iterations; i++) {
			unsigned long long value = (unsigned long long)i + 1;
			int cur_result = 0;

			sleep(10);

			if (rb) {
				void *sample = user_ring_buffer__reserve(rb, sizeof(value));
				if (!sample) {
					cur_result = errno ? -errno : -1;
					op_err = cur_result;
				} else {
					memcpy(sample, &value, sizeof(value));
					user_ring_buffer__submit(rb, sample);
				}
			}

			if (pos < map_json_size - 1) {
				if (i > 0) {
					n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos), ",\n");
					if (n > 0) pos += n;
				}
				n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
					"                                    "
					"{ \"Iteration\" : %d, \"Mode\" : \"%s\", \"Setup\" : %d, "
					"\"Operation Result\" : %d, \"Samples\" : 0, \"Bytes\" : 0, "
					"\"Available\" : 0, \"Ring Size\" : 0, \"Error Code\" : %d, "
					"\"Error Message\" : \"%s\" }",
					i, mode, !setup_err, cur_result,
					op_err, op_err ? strerror(-op_err) : "No error information");
				if (n > 0) pos += n;
			}
		}

		if (rb)
			user_ring_buffer__free(rb);
	}

	if (pos < map_json_size - 1) {
		n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
			"\n                                ]\n"
			"                      }\n"
			"        }");
		if (n > 0) pos += n;
	}
	if (pos < map_json_size)
		map_json_buf[pos] = '\0';

	return op_err;
}

#if MY_LINUX_VERSION_CODE >= 395520
static int netdata_core_test_arena_map(struct bpf_map *map, int iterations,
				       char *map_json_buf, int map_json_size)
{
	int fd = bpf_map__fd(map);
	unsigned int key_size = (unsigned int)bpf_map__key_size(map);
	unsigned int value_size = (unsigned int)bpf_map__value_size(map);
	size_t arena_sz = (size_t)bpf_map__max_entries(map) * (size_t)sysconf(_SC_PAGE_SIZE);
	size_t data_sz = 0;
	// arena is already mmap'd by libbpf at load time; MAP_FIXED + map_extra required
	void *arena_mem = bpf_map__initial_value(map, &data_sz);
	int setup_err = arena_mem ? 0 : -EINVAL;
	unsigned int prev_head = 0;
	int pos = 0;
	int n, i;

	if (iterations < 1)
		iterations = 1;

	n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
		"{\n"
		"            \"Info\" : { \"Length\" : { \"Key\" : %u, \"Value\" : %u},\n"
		"                       \"Type\" : %d,\n"
		"                       \"FD\" : %d,\n"
		"                       \"Data\" : [\n",
		key_size, value_size, BPF_MAP_TYPE_ARENA, fd);
	if (n > 0) pos += n;

	if (arena_mem)
		prev_head = *(volatile unsigned int *)arena_mem;

	for (i = 0; i < iterations; i++) {
		unsigned int cur_head = 0;
		unsigned int delta = 0;

		sleep(10);

		if (arena_mem) {
			cur_head = *(volatile unsigned int *)arena_mem;
			delta = cur_head - prev_head;
			prev_head = cur_head;
		}

		if (pos < map_json_size - 1) {
			if (i > 0) {
				n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos), ",\n");
				if (n > 0) pos += n;
			}
			n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
				"                                    "
				"{ \"Iteration\" : %d, \"Mode\" : \"arena_consumer\", \"Setup\" : %d, "
				"\"Operation Result\" : %u, \"Samples\" : %u, \"Bytes\" : 0, "
				"\"Available\" : 0, \"Ring Size\" : %zu, \"Error Code\" : %d, "
				"\"Error Message\" : \"%s\" }",
				i, !setup_err, delta, delta, arena_sz,
				setup_err, setup_err ? strerror(-setup_err) : "No error information");
			if (n > 0) pos += n;
		}
	}

	if (pos < map_json_size - 1) {
		n = snprintf(map_json_buf + pos, (size_t)(map_json_size - pos),
			"\n                                ]\n"
			"                      }\n"
			"        }");
		if (n > 0) pos += n;
	}
	if (pos < map_json_size)
		map_json_buf[pos] = '\0';

	return setup_err;
}
#endif // MY_LINUX_VERSION_CODE >= 395520

// Check whether a kernel symbol is present in /proc/kallsyms.
static int netdata_core_symbol_in_kallsyms(const char *name)
{
	FILE *f;
	char line[512];
	char sym[256];
	int found = 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return 1; // can't verify; assume present to avoid false disabling

	while (!found && fgets(line, (int)sizeof(line), f)) {
		if (sscanf(line, "%*x %*c %255s", sym) == 1)
			found = (strcmp(sym, name) == 0);
	}
	fclose(f);
	return found;
}

// Mutually exclusive kprobe target groups in priority order (first found wins).
// Mirrors the compile-time #if chain in kernel-collector/kernel/cachestat_buffer_kern.c
// and swap_buffer_kern.c, resolved at runtime via kallsyms for CO-RE builds.
static const char * const netdata_core_kprobe_groups[][4] = {
	{ "__folio_mark_dirty", "__set_page_dirty", "account_page_dirtied", NULL },
	{ "swap_read_folio",    "swap_readpage",    NULL,                   NULL },
	{ "__swap_writepage",   "swap_writepage",   NULL,                   NULL },
	{ NULL,                 NULL,               NULL,                   NULL }
};

static void netdata_core_select_kprobe_programs(struct bpf_object *obj)
{
	struct bpf_program *prog;
	int g, i;

	// For each group, pick the highest-priority existing symbol and disable all others.
	for (g = 0; netdata_core_kprobe_groups[g][0]; g++) {
		const char *winner = NULL;
		const char *fn;
		for (i = 0; netdata_core_kprobe_groups[g][i]; i++) {
			if (netdata_core_symbol_in_kallsyms(netdata_core_kprobe_groups[g][i])) {
				winner = netdata_core_kprobe_groups[g][i];
				break;
			}
		}
		bpf_object__for_each_program(prog, obj) {
			const char *sec = bpf_program__section_name(prog);
			if (!sec || strncmp(sec, "kprobe/", 7) != 0)
				continue;
			fn = sec + 7;
			for (i = 0; netdata_core_kprobe_groups[g][i]; i++) {
				if (strcmp(fn, netdata_core_kprobe_groups[g][i]) == 0 &&
				    (!winner || strcmp(fn, winner) != 0)) {
					bpf_program__set_autoload(prog, false);
					break;
				}
			}
		}
	}

	// Disable any remaining kprobe program whose target still doesn't exist.
	bpf_object__for_each_program(prog, obj) {
		const char *sec = bpf_program__section_name(prog);
		if (!sec || strncmp(sec, "kprobe/", 7) != 0)
			continue;
		if (!netdata_core_symbol_in_kallsyms(sec + 7))
			bpf_program__set_autoload(prog, false);
	}
}

static int netdata_core_run_buffer_skel_test(const char *name, const char *ctrl_name, int map_level, int iterations,
						     int *attached, int *skipped, int *maps, int *ring_maps,
						     char *maps_json_buf, int maps_json_size)
{
	const struct netdata_core_buffer_skel_ops *ops = netdata_core_find_buffer_skel_ops(name);
	struct bpf_link *links[64] = { 0 };
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	void *skel = NULL;
	size_t link_count = 0;
	int err = 0;
	size_t i;
	int maps_pos = 0;

	*attached = 0;
	*skipped = 0;
	*maps = 0;
	*ring_maps = 0;

	if (maps_json_buf && maps_json_size > 0)
		maps_json_buf[0] = '\0';

	if (!ops)
		return -ENOENT;

	skel = ops->open();
	err = (int)libbpf_get_error(skel);
	if (err) {
		skel = NULL;
		goto out;
	}

	obj = ((struct netdata_core_buffer_skel_base *)skel)->obj;
	netdata_core_select_kprobe_programs(obj);
	err = ops->load(skel);
	if (err)
		goto out;

	netdata_core_fill_ctrl_map(obj, ctrl_name, map_level);

	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link;

		if (bpf_program__type(prog) == BPF_PROG_TYPE_SOCKET_FILTER) {
			(*skipped)++;
			continue;
		}

		if (link_count >= sizeof(links) / sizeof(links[0])) {
			err = -ENOSPC;
			goto out;
		}

		// Skip programs disabled before load (missing kprobe targets).
		if (bpf_program__fd(prog) < 0)
			continue;

		link = bpf_program__attach(prog);
		err = (int)libbpf_get_error(link);
		if (err) {
			// Safety net: skip if target still absent at attach time.
			if (err == -ENOENT) {
				err = 0;
				continue;
			}
			goto out;
		}

		links[link_count++] = link;
		(*attached)++;
	}

	bpf_object__for_each_map(map, obj) {
		int map_type = (int)bpf_map__type(map);
		const char *map_name = bpf_map__name(map);
		char map_json[2048];
		int n;

		(*maps)++;
		if (map_type != BPF_MAP_TYPE_RINGBUF && map_type != BPF_MAP_TYPE_USER_RINGBUF)
			continue;

		(*ring_maps)++;

		if (maps_json_buf && maps_json_size > maps_pos) {
			if (maps_pos > 0) {
				n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos), ",\n");
				if (n > 0) maps_pos += n;
			}
			n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos),
				"        \"%s\" : ", map_name);
			if (n > 0) maps_pos += n;
		}

		map_json[0] = '\0';
		err = netdata_core_test_ringbuf_map(map, iterations, map_json, (int)sizeof(map_json));

		if (maps_json_buf && maps_json_size > maps_pos) {
			n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos), "%s", map_json);
			if (n > 0) maps_pos += n;
			if (maps_pos < maps_json_size)
				maps_json_buf[maps_pos] = '\0';
		}

		if (err)
			goto out;
	}

	if (maps_json_buf && maps_pos < maps_json_size)
		maps_json_buf[maps_pos] = '\0';

out:
	for (i = 0; i < link_count; i++)
		bpf_link__destroy(links[i]);
	if (skel)
		ops->destroy(skel);

	return err;
}

#if MY_LINUX_VERSION_CODE >= 395520
static int netdata_core_run_arena_skel_test(const char *name, const char *ctrl_name, int map_level, int iterations,
					    int *attached, int *skipped, int *maps, int *ring_maps,
					    char *maps_json_buf, int maps_json_size)
{
	const struct netdata_core_buffer_skel_ops *ops = netdata_core_find_arena_skel_ops(name);
	struct bpf_link *links[64] = { 0 };
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	void *skel = NULL;
	size_t link_count = 0;
	int err = 0;
	size_t i;
	int maps_pos = 0;

	*attached = 0;
	*skipped = 0;
	*maps = 0;
	*ring_maps = 0;

	if (maps_json_buf && maps_json_size > 0)
		maps_json_buf[0] = '\0';

	if (!ops)
		return -ENOENT;

	skel = ops->open();
	err = (int)libbpf_get_error(skel);
	if (err) {
		skel = NULL;
		goto out;
	}

	obj = ((struct netdata_core_buffer_skel_base *)skel)->obj;
	netdata_core_select_kprobe_programs(obj);
	err = ops->load(skel);
	if (err)
		goto out;

	netdata_core_fill_ctrl_map(obj, ctrl_name, map_level);

	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link;

		if (bpf_program__type(prog) == BPF_PROG_TYPE_SOCKET_FILTER) {
			(*skipped)++;
			continue;
		}

		if (link_count >= sizeof(links) / sizeof(links[0])) {
			err = -ENOSPC;
			goto out;
		}

		if (bpf_program__fd(prog) < 0)
			continue;

		link = bpf_program__attach(prog);
		err = (int)libbpf_get_error(link);
		if (err) {
			if (err == -ENOENT) {
				err = 0;
				continue;
			}
			goto out;
		}

		links[link_count++] = link;
		(*attached)++;
	}

	bpf_object__for_each_map(map, obj) {
		int map_type = (int)bpf_map__type(map);
		const char *map_name = bpf_map__name(map);
		char map_json[2048];
		int n;

		(*maps)++;
		if (map_type != BPF_MAP_TYPE_RINGBUF && map_type != BPF_MAP_TYPE_USER_RINGBUF
		    && map_type != BPF_MAP_TYPE_ARENA)
			continue;

		if (maps_json_buf && maps_json_size > maps_pos) {
			if (maps_pos > 0) {
				n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos), ",\n");
				if (n > 0) maps_pos += n;
			}
			n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos),
				"        \"%s\" : ", map_name);
			if (n > 0) maps_pos += n;
		}

		if (map_type == BPF_MAP_TYPE_RINGBUF || map_type == BPF_MAP_TYPE_USER_RINGBUF)
			(*ring_maps)++;

		map_json[0] = '\0';
		if (map_type == BPF_MAP_TYPE_ARENA)
			err = netdata_core_test_arena_map(map, iterations, map_json, (int)sizeof(map_json));
		else
			err = netdata_core_test_ringbuf_map(map, iterations, map_json, (int)sizeof(map_json));

		if (maps_json_buf && maps_json_size > maps_pos) {
			n = snprintf(maps_json_buf + maps_pos, (size_t)(maps_json_size - maps_pos), "%s", map_json);
			if (n > 0) maps_pos += n;
			if (maps_pos < maps_json_size)
				maps_json_buf[maps_pos] = '\0';
		}

		if (err)
			goto out;
	}

	if (maps_json_buf && maps_pos < maps_json_size)
		maps_json_buf[maps_pos] = '\0';

out:
	for (i = 0; i < link_count; i++)
		bpf_link__destroy(links[i]);
	if (skel)
		ops->destroy(skel);

	return err;
}
#else // MY_LINUX_VERSION_CODE < 395520 (but >= 329728): arena not supported
static int netdata_core_run_arena_skel_test(const char *name, const char *ctrl_name,
	int map_level, int iterations, int *attached, int *skipped, int *maps, int *ring_maps,
	char *maps_json_buf, int maps_json_size)
{
	(void)name; (void)ctrl_name; (void)map_level; (void)iterations;
	(void)attached; (void)skipped; (void)maps; (void)ring_maps;
	(void)maps_json_buf; (void)maps_json_size;
	return -ENOSYS;
}
#endif // MY_LINUX_VERSION_CODE >= 395520

static int netdata_core_arena_supported(void)
{
#if MY_LINUX_VERSION_CODE >= 395520
	return 1;
#else
	return 0;
#endif
}
#else
static int netdata_core_run_buffer_skel_test(const char *name, const char *ctrl_name,
	int map_level, int iterations, int *attached, int *skipped, int *maps, int *ring_maps,
	char *maps_json_buf, int maps_json_size)
{
	(void)name; (void)ctrl_name; (void)map_level; (void)iterations;
	(void)attached; (void)skipped; (void)maps; (void)ring_maps;
	(void)maps_json_buf; (void)maps_json_size;
	return -ENOSYS;
}
static int netdata_core_run_arena_skel_test(const char *name, const char *ctrl_name,
	int map_level, int iterations, int *attached, int *skipped, int *maps, int *ring_maps,
	char *maps_json_buf, int maps_json_size)
{
	(void)name; (void)ctrl_name; (void)map_level; (void)iterations;
	(void)attached; (void)skipped; (void)maps; (void)ring_maps;
	(void)maps_json_buf; (void)maps_json_size;
	return -ENOSYS;
}
static int netdata_core_arena_supported(void)
{
	return 0;
}
#endif // MY_LINUX_VERSION_CODE >= 329728

static int netdata_core_ringbuf_supported(void)
{
#if MY_LINUX_VERSION_CODE >= 329728
	return 1;
#else
	return 0;
#endif
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unsafe"
)

func init() {
	C.netdata_disable_libbpf_memlock_rlim()
}

const (
	modeNone       = uint(0)
	modeProbe      = uint(1 << 0)
	modeTracepoint = uint(1 << 1)
	modeTrampoline = uint(1 << 2)

	pidMin = 0
	pidMax = 3
)

const (
	selectCachestat     = uint64(1 << 0)
	selectDC            = uint64(1 << 1)
	selectDisk          = uint64(1 << 2)
	selectDNS           = uint64(1 << 3)
	selectFD            = uint64(1 << 4)
	selectHardirq       = uint64(1 << 5)
	selectMdflush       = uint64(1 << 6)
	selectMount         = uint64(1 << 7)
	selectNetworkviewer = uint64(1 << 8)
	selectOOMKill       = uint64(1 << 9)
	selectProcess       = uint64(1 << 10)
	selectSHM           = uint64(1 << 11)
	selectSocket        = uint64(1 << 12)
	selectSoftirq       = uint64(1 << 13)
	selectSwap          = uint64(1 << 14)
	selectSync          = uint64(1 << 15)
	selectVFS           = uint64(1 << 16)
	selectNFS           = uint64(1 << 17)
	selectExt4          = uint64(1 << 18)
	selectBtrfs         = uint64(1 << 19)
	selectXFS           = uint64(1 << 20)
	selectZFS           = uint64(1 << 21)

	selectFilesystem       = selectNFS | selectExt4 | selectBtrfs | selectXFS
	selectAllNonFilesystem = selectCachestat | selectDC | selectDisk | selectDNS |
		selectFD | selectHardirq | selectMdflush | selectMount |
		selectNetworkviewer | selectOOMKill | selectProcess |
		selectSHM | selectSocket | selectSoftirq | selectSwap |
		selectSync | selectVFS
)

type aggregateTestCase struct {
	name              string
	binary            string
	extraArg          string
	unavailableReason string
	selectionBit      uint64
	modes             uint
	emitModeArg       bool
	pidSupported      bool
	bufferSupported   bool
	arenaSupported    bool
	bufferCtrl        string
}

type aggregateResult struct {
	name     string
	binary   string
	mode     string
	pid      int
	status   string
	exitCode int
	command  string
	detail   string
	mapsJSON string
}

type aggregateState struct {
	dnsPorts          string
	dnsIterations     string
	selectedPID       int
	selectionMask     uint64
	explicitSelection bool
	bufferMode        bool
	arenaMode         bool
	bufferIterations  int
	testsDir          string
}

var aggregateTests = []aggregateTestCase{
	{name: "cachestat", binary: "cachestat", selectionBit: selectCachestat, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "cstat_ctrl"},
	{name: "dc", binary: "dc", selectionBit: selectDC, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "dcstat_ctrl"},
	{name: "disk", binary: "disk", selectionBit: selectDisk},
	{name: "dns", binary: "dns", selectionBit: selectDNS, bufferSupported: true, arenaSupported: true},
	{name: "fd", binary: "fd", selectionBit: selectFD, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "fd_ctrl"},
	{name: "hardirq", binary: "hardirq", selectionBit: selectHardirq},
	{name: "mdflush", binary: "mdflush", selectionBit: selectMdflush, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "mount", binary: "mount", selectionBit: selectMount, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "networkviewer", binary: "networkviewer", selectionBit: selectNetworkviewer, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "oomkill", binary: "oomkill", selectionBit: selectOOMKill, bufferSupported: true, arenaSupported: true},
	{name: "process", binary: "process", selectionBit: selectProcess, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "process_ctrl"},
	{name: "shm", binary: "shm", selectionBit: selectSHM, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "shm_ctrl"},
	{name: "socket", binary: "socket", selectionBit: selectSocket, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true},
	{name: "softirq", binary: "softirq", selectionBit: selectSoftirq},
	{name: "swap", binary: "swap", selectionBit: selectSwap, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "swap_ctrl"},
	{name: "sync", binary: "sync", selectionBit: selectSync, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true},
	{name: "vfs", binary: "vfs", selectionBit: selectVFS, modes: modeProbe | modeTracepoint | modeTrampoline, emitModeArg: true, pidSupported: true, bufferSupported: true, arenaSupported: true, bufferCtrl: "vfs_ctrl"},
	{name: "nfs", binary: "filesystem", extraArg: "--nfs", selectionBit: selectNFS, modes: modeProbe},
	{name: "ext4", binary: "filesystem", extraArg: "--ext4", selectionBit: selectExt4, modes: modeProbe},
	{name: "btrfs", binary: "filesystem", extraArg: "--btrfs", selectionBit: selectBtrfs, modes: modeProbe},
	{name: "xfs", binary: "filesystem", extraArg: "--xfs", selectionBit: selectXFS, modes: modeProbe},
	{name: "zfs", unavailableReason: "No CO-RE skeleton or tester is generated for zfs in this repository.", selectionBit: selectZFS},
}

func modeName(mode uint) string {
	switch mode {
	case modeProbe:
		return "probe"
	case modeTracepoint:
		return "tracepoint"
	case modeTrampoline:
		return "trampoline"
	default:
		return ""
	}
}

func modeArg(mode uint) string {
	switch mode {
	case modeProbe:
		return "--probe"
	case modeTracepoint:
		return "--tracepoint"
	case modeTrampoline:
		return "--trampoline"
	default:
		return ""
	}
}

func initResult(test aggregateTestCase) aggregateResult {
	return aggregateResult{
		name:     test.name,
		binary:   test.binary,
		pid:      -1,
		exitCode: 0,
	}
}

func jsonWriteString(out io.Writer, text string) {
	encoded, err := json.Marshal(text)
	if err != nil {
		panic(err)
	}

	_, _ = out.Write(encoded)
}

func writeResult(out io.Writer, result aggregateResult, first *bool) {
	if !*first {
		_, _ = io.WriteString(out, ",\n")
	}

	*first = false

	_, _ = io.WriteString(out, "    {\n")
	_, _ = io.WriteString(out, "      \"name\": ")
	jsonWriteString(out, result.name)
	_, _ = io.WriteString(out, ",\n      \"binary\": ")
	jsonWriteString(out, result.binary)
	_, _ = io.WriteString(out, ",\n      \"mode\": ")
	jsonWriteString(out, result.mode)
	_, _ = fmt.Fprintf(out, ",\n      \"pid\": %d,\n", result.pid)
	_, _ = io.WriteString(out, "      \"status\": ")
	jsonWriteString(out, result.status)
	_, _ = fmt.Fprintf(out, ",\n      \"exit_code\": %d,\n", result.exitCode)
	_, _ = io.WriteString(out, "      \"command\": ")
	jsonWriteString(out, result.command)
	_, _ = io.WriteString(out, ",\n      \"detail\": ")
	jsonWriteString(out, result.detail)
	if result.mapsJSON != "" {
		_, _ = fmt.Fprintf(out, ",\n      \"maps\": {\n%s\n      }", result.mapsJSON)
	}
	_, _ = io.WriteString(out, "\n    }")
}

func recordUnavailable(test aggregateTestCase, detail string) aggregateResult {
	result := initResult(test)
	result.status = "Unavailable"
	result.detail = detail
	result.command = ""
	return result
}

func executeTest(state aggregateState, test aggregateTestCase, mode uint, pid int) (aggregateResult, int) {
	result := initResult(test)
	if mode != modeNone {
		result.mode = modeName(mode)
	}

	if pid >= 0 {
		result.pid = pid
	}

	args := []string{test.binary}
	if test.emitModeArg && mode != modeNone {
		args = append(args, modeArg(mode))
	}

	if test.extraArg != "" {
		args = append(args, test.extraArg)
	}

	if test.name == "dns" {
		if state.dnsPorts != "" {
			args = append(args, "--dns-port", state.dnsPorts)
		}

		if state.dnsIterations != "" {
			args = append(args, "--iteration", state.dnsIterations)
		}
	}

	if pid >= 0 {
		args = append(args, "--pid", strconv.Itoa(pid))
	}

	result.command = strings.Join(args, " ")

	_, _ = fmt.Fprintf(os.Stderr, "Running %s\n", result.command)

	cName := C.CString(test.binary)
	defer C.free(unsafe.Pointer(cName))

	cArgs := make([]*C.char, len(args))
	for i, a := range args {
		cs := C.CString(a)
		defer C.free(unsafe.Pointer(cs))
		cArgs[i] = cs
	}

	exitCode := int(C.netdata_run_entry(cName, C.int(len(cArgs)), &cArgs[0]))
	result.exitCode = exitCode
	if exitCode == 0 {
		result.status = "Success"
		result.detail = "Command completed successfully."
	} else {
		result.status = "Fail"
		result.detail = fmt.Sprintf("Command exited with code %d.", exitCode)
	}

	return result, exitCode
}

func executeBufferTest(state aggregateState, test aggregateTestCase) (aggregateResult, int) {
	result := initResult(test)
	result.mode = "buffer"
	result.binary = test.name + "_buffer.skel.h"
	result.command = test.name + "_buffer skeleton"
	if state.selectedPID >= 0 {
		result.pid = state.selectedPID
	}

	if !test.bufferSupported {
		result.status = "Unavailable"
		result.detail = "Collector has no CO-RE buffer object."
		return result, 0
	}

	if C.netdata_core_ringbuf_supported() == 0 {
		result.status = "Unavailable"
		result.detail = "Ring buffer (BPF_MAP_TYPE_RINGBUF) requires kernel >= 5.8."
		return result, 0
	}

	mapLevel := state.selectedPID
	if mapLevel < 0 {
		mapLevel = pidMin
	}

	_, _ = fmt.Fprintf(os.Stderr, "Running buffer skeleton test %s\n", result.command)

	cName := C.CString(test.name)
	defer C.free(unsafe.Pointer(cName))

	cCtrl := C.CString(test.bufferCtrl)
	defer C.free(unsafe.Pointer(cCtrl))

	attached := C.int(0)
	skipped := C.int(0)
	maps := C.int(0)
	ringMaps := C.int(0)
	var mapsBuf [4096]C.char
	errCode := int(C.netdata_core_run_buffer_skel_test(
		cName,
		cCtrl,
		C.int(mapLevel),
		C.int(state.bufferIterations),
		&attached,
		&skipped,
		&maps,
		&ringMaps,
		&mapsBuf[0],
		C.int(len(mapsBuf)),
	))
	mapsJSON := C.GoString(&mapsBuf[0])
	if errCode != 0 {
		result.status = "Fail"
		result.exitCode = errCode
		result.detail = fmt.Sprintf("Buffer skeleton test failed with error %d.", errCode)
		result.mapsJSON = mapsJSON
		return result, 1
	}

	result.status = "Success"
	result.detail = fmt.Sprintf("Loaded object, attached %d programs, skipped %d socket filters, checked %d maps and %d ring buffers.",
		int(attached), int(skipped), int(maps), int(ringMaps))
	result.mapsJSON = mapsJSON
	return result, 0
}

func executeArenaTest(state aggregateState, test aggregateTestCase) (aggregateResult, int) {
	result := initResult(test)
	result.mode = "arena"
	result.binary = test.name + "_arena.skel.h"
	result.command = test.name + "_arena skeleton"
	if state.selectedPID >= 0 {
		result.pid = state.selectedPID
	}

	if !test.arenaSupported {
		result.status = "Unavailable"
		result.detail = "Collector has no CO-RE arena object."
		return result, 0
	}

	if C.netdata_core_arena_supported() == 0 {
		result.status = "Unavailable"
		result.detail = "Arena collection requires kernel >= 6.9."
		return result, 0
	}

	mapLevel := state.selectedPID
	if mapLevel < 0 {
		mapLevel = pidMin
	}

	_, _ = fmt.Fprintf(os.Stderr, "Running arena skeleton test %s\n", result.command)

	cName := C.CString(test.name)
	defer C.free(unsafe.Pointer(cName))

	cCtrl := C.CString(test.bufferCtrl)
	defer C.free(unsafe.Pointer(cCtrl))

	attached := C.int(0)
	skipped := C.int(0)
	maps := C.int(0)
	ringMaps := C.int(0)
	var mapsBuf [4096]C.char
	errCode := int(C.netdata_core_run_arena_skel_test(
		cName,
		cCtrl,
		C.int(mapLevel),
		C.int(state.bufferIterations),
		&attached,
		&skipped,
		&maps,
		&ringMaps,
		&mapsBuf[0],
		C.int(len(mapsBuf)),
	))
	mapsJSON := C.GoString(&mapsBuf[0])
	if errCode != 0 {
		result.status = "Fail"
		result.exitCode = errCode
		result.detail = fmt.Sprintf("Arena skeleton test failed with error %d.", errCode)
		result.mapsJSON = mapsJSON
		return result, 1
	}

	result.status = "Success"
	result.detail = fmt.Sprintf("Loaded object, attached %d programs, skipped %d socket filters, checked %d maps and %d ring buffers.",
		int(attached), int(skipped), int(maps), int(ringMaps))
	result.mapsJSON = mapsJSON
	return result, 0
}

func printHelp(out io.Writer, name string) {
	_, _ = fmt.Fprintf(out,
		"%s runs the CO-RE tests in-process and aggregates their results.\n\n"+
			"Options:\n"+
			"  --help            Print this help.\n"+
			"  --all             Run all non-filesystem CO-RE tests. This is the default.\n"+
			"  --pid VALUE       Run PID-aware tests with a single PID level (0-3).\n"+
			"  --dns-port LIST   Forward a comma-separated DNS port list to the DNS tester.\n"+
			"  --iteration N     Forward the capture iteration count to the DNS tester.\n"+
			"  --tests-dir PATH  Accepted for compatibility and ignored in in-process mode.\n"+
			"  --log-path FILE   Write the aggregate JSON summary to FILE instead of stdout.\n"+
			"  --buffer          Test CO-RE ring-buffer BPF objects instead of standalone loaders.\n"+
			"  --arena           Test CO-RE arena BPF objects using compiled-in skeletons.\n"+
			"\n"+
			"Selectors:\n"+
			"  --cachestat --dc --disk --dns --fd --hardirq --mdflush --mount\n"+
			"  --networkviewer --oomkill --process --shm --socket --softirq --swap\n"+
			"  --sync --vfs --filesystem --nfs --ext4 --btrfs --xfs --zfs\n"+
			"\n"+
			"Notes:\n"+
			"  - --all excludes filesystem coverage: nfs, ext4, btrfs, xfs, and zfs.\n"+
			"  - --filesystem expands to --nfs --ext4 --btrfs --xfs.\n"+
			"  - zfs is reported as unavailable because this repository does not generate\n"+
			"    a CO-RE zfs skeleton/tester.\n",
		name)
}

func parseLeadingInt(value string) int {
	if value == "" {
		return 0
	}

	start := 0
	sign := 1
	if value[0] == '-' {
		sign = -1
		start = 1
	} else if value[0] == '+' {
		start = 1
	}

	result := 0
	digits := 0
	for ; start < len(value); start++ {
		if value[start] < '0' || value[start] > '9' {
			break
		}

		result = result*10 + int(value[start]-'0')
		digits++
	}

	if digits == 0 {
		return 0
	}

	return sign * result
}

func nextOptionValue(args []string, index *int, inlineValue string, option string) (string, error) {
	if inlineValue != "" {
		return inlineValue, nil
	}

	*index++
	if *index >= len(args) {
		return "", fmt.Errorf("option '--%s' requires an argument", option)
	}

	return args[*index], nil
}

func parseArgs(args []string) (aggregateState, string, bool, error) {
	state := aggregateState{selectedPID: -1, bufferIterations: 1}
	logPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			return state, logPath, true, nil
		}

		if !strings.HasPrefix(arg, "--") {
			return state, logPath, false, fmt.Errorf("unrecognized option '%s'", arg)
		}

		option := strings.TrimPrefix(arg, "--")
		inlineValue := ""
		if equals := strings.IndexByte(option, '='); equals >= 0 {
			inlineValue = option[equals+1:]
			option = option[:equals]
		}

		switch option {
		case "pid":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			state.selectedPID = parseLeadingInt(value)
			if state.selectedPID < pidMin || state.selectedPID > pidMax {
				return state, logPath, false, fmt.Errorf("PID level must be between %d and %d.", pidMin, pidMax)
			}
		case "dns-port":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			state.dnsPorts = value
		case "iteration":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			state.dnsIterations = value
			state.bufferIterations = parseLeadingInt(value)
			if state.bufferIterations < 1 {
				state.bufferIterations = 1
			}
		case "tests-dir":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}
			state.testsDir = value
		case "log-path":
			value, err := nextOptionValue(args, &i, inlineValue, option)
			if err != nil {
				return state, logPath, false, err
			}

			logPath = value
		case "all":
			state.selectionMask |= selectAllNonFilesystem
			state.explicitSelection = true
		case "arena":
			if state.bufferMode {
				return state, logPath, false, fmt.Errorf("--buffer and --arena are mutually exclusive")
			}
			state.arenaMode = true
		case "cachestat":
			state.selectionMask |= selectCachestat
			state.explicitSelection = true
		case "dc":
			state.selectionMask |= selectDC
			state.explicitSelection = true
		case "disk":
			state.selectionMask |= selectDisk
			state.explicitSelection = true
		case "dns":
			state.selectionMask |= selectDNS
			state.explicitSelection = true
		case "fd":
			state.selectionMask |= selectFD
			state.explicitSelection = true
		case "hardirq":
			state.selectionMask |= selectHardirq
			state.explicitSelection = true
		case "mdflush":
			state.selectionMask |= selectMdflush
			state.explicitSelection = true
		case "mount":
			state.selectionMask |= selectMount
			state.explicitSelection = true
		case "networkviewer":
			state.selectionMask |= selectNetworkviewer
			state.explicitSelection = true
		case "oomkill":
			state.selectionMask |= selectOOMKill
			state.explicitSelection = true
		case "process":
			state.selectionMask |= selectProcess
			state.explicitSelection = true
		case "shm":
			state.selectionMask |= selectSHM
			state.explicitSelection = true
		case "socket":
			state.selectionMask |= selectSocket
			state.explicitSelection = true
		case "softirq":
			state.selectionMask |= selectSoftirq
			state.explicitSelection = true
		case "swap":
			state.selectionMask |= selectSwap
			state.explicitSelection = true
		case "sync":
			state.selectionMask |= selectSync
			state.explicitSelection = true
		case "vfs":
			state.selectionMask |= selectVFS
			state.explicitSelection = true
		case "filesystem":
			state.selectionMask |= selectFilesystem
			state.explicitSelection = true
		case "nfs":
			state.selectionMask |= selectNFS
			state.explicitSelection = true
		case "ext4":
			state.selectionMask |= selectExt4
			state.explicitSelection = true
		case "btrfs":
			state.selectionMask |= selectBtrfs
			state.explicitSelection = true
		case "xfs":
			state.selectionMask |= selectXFS
			state.explicitSelection = true
		case "zfs":
			state.selectionMask |= selectZFS
			state.explicitSelection = true
		case "buffer":
			if state.arenaMode {
				return state, logPath, false, fmt.Errorf("--buffer and --arena are mutually exclusive")
			}
			state.bufferMode = true
		default:
			return state, logPath, false, fmt.Errorf("unrecognized option '--%s'", option)
		}
	}

	if !state.explicitSelection {
		state.selectionMask = selectAllNonFilesystem
		state.explicitSelection = true
	}

	return state, logPath, false, nil
}

func main() {
	state, logPath, showHelp, err := parseArgs(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}

	if showHelp {
		printHelp(os.Stdout, os.Args[0])
		return
	}

	report := io.Writer(os.Stdout)
	var reportFile *os.File
	if logPath != "" {
		reportFile, err = os.Create(logPath)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Cannot open log file: %v\n", err)
			os.Exit(1)
		}
		defer reportFile.Close()
		report = reportFile
	}

	_, _ = io.WriteString(report, "{\n  \"runs\": [\n")

	first := true
	resultCount := 0
	failures := 0
	unavailable := 0

	for _, test := range aggregateTests {
		if state.explicitSelection && (state.selectionMask&test.selectionBit) == 0 {
			continue
		}

		if state.bufferMode {
			if !test.bufferSupported {
				continue
			}

			result, exitCode := executeBufferTest(state, test)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
			continue
		}

		if state.arenaMode {
			if !test.arenaSupported {
				continue
			}

			result, exitCode := executeArenaTest(state, test)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
			continue
		}

		if test.unavailableReason != "" {
			result := recordUnavailable(test, test.unavailableReason)
			writeResult(report, result, &first)
			resultCount++
			unavailable++
			continue
		}

		if test.modes == modeNone {
			result, exitCode := executeTest(state, test, modeNone, -1)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
			continue
		}

		orderedModes := []uint{modeProbe, modeTracepoint, modeTrampoline}
		for _, mode := range orderedModes {
			if test.modes&mode == 0 {
				continue
			}

			pidStart := -1
			pidEnd := -1
			if test.pidSupported {
				if state.selectedPID >= 0 {
					pidStart = state.selectedPID
					pidEnd = state.selectedPID
				} else {
					pidStart = pidMin
					pidEnd = pidMax
				}
			}

			if pidStart >= 0 {
				for pid := pidStart; pid <= pidEnd; pid++ {
					result, exitCode := executeTest(state, test, mode, pid)
					if exitCode != 0 {
						failures++
					}
					writeResult(report, result, &first)
					resultCount++
				}
				continue
			}

			result, exitCode := executeTest(state, test, mode, -1)
			if exitCode != 0 {
				failures++
			}
			writeResult(report, result, &first)
			resultCount++
		}
	}

	_, _ = fmt.Fprintf(report,
		"\n  ],\n"+
			"  \"summary\": {\n"+
			"    \"total\": %d,\n"+
			"    \"success\": %d,\n"+
			"    \"failed\": %d,\n"+
			"    \"unavailable\": %d\n"+
			"  }\n"+
			"}\n",
		resultCount,
		resultCount-failures-unavailable,
		failures,
		unavailable)

	if failures != 0 {
		os.Exit(1)
	}
}
