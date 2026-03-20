// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_HARDIRQ_H_
#define _NETDATA_HARDIRQ_H_ 1

#define NETDATA_HARDIRQ_MAX_IRQS 1024L
#define NETDATA_HARDIRQ_NAME_LEN 32

struct netdata_irq_handler_entry {
    u64 pad;
    int irq;
    int data_loc_name;
};

struct netdata_irq_handler_exit {
    u64 pad;
    int irq;
    int ret;
};

typedef struct hardirq_key {
    int irq;
} hardirq_key_t;

struct netdata_irq_vectors_entry {
    u64 pad;
    int vector;
};

struct netdata_irq_vectors_exit {
    u64 pad;
    int vector;
};

enum netdata_hardirq_static {
    NETDATA_HARDIRQ_STATIC_APIC_THERMAL,
    NETDATA_HARDIRQ_STATIC_APIC_THRESHOLD,
    NETDATA_HARDIRQ_STATIC_APIC_ERROR,
    NETDATA_HARDIRQ_STATIC_APIC_DEFERRED_ERROR,
    NETDATA_HARDIRQ_STATIC_APIC_SPURIOUS,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL,
    NETDATA_HARDIRQ_STATIC_FUNC_CALL_SINGLE,
    NETDATA_HARDIRQ_STATIC_RESCHEDULE,
    NETDATA_HARDIRQ_STATIC_LOCAL_TIMER,
    NETDATA_HARDIRQ_STATIC_IRQ_WORK,
    NETDATA_HARDIRQ_STATIC_X86_PLATFORM_IPI,
    NETDATA_HARDIRQ_STATIC_END
};

typedef struct hardirq_val {
    u64 latency;
    u64 ts;
    u32 pid;
} hardirq_val_t;

#endif /* _NETDATA_HARDIRQ_H_ */
