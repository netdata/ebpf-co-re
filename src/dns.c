#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "netdata_defs.h"
#include "netdata_tests.h"
#include "netdata_core_common.h"

#include "../kernel-collector/tests/tester_dns.h"

#include "dns.skel.h"

#define NETDATA_DNS_MAX_PORTS 32
#define NETDATA_DNS_DEFAULT_PORT 53

static uint16_t dns_ports[NETDATA_DNS_MAX_PORTS] = { NETDATA_DNS_DEFAULT_PORT };
static size_t dns_port_count = 1;
static int dns_ports_overridden;
static int dns_iterations = 1;

static void dns_help(const char *name)
{
    fprintf(stdout,
            "%s loads the CO-RE DNS socket filter and captures DNS traffic.\n\n"
            "The following options are available:\n\n"
            "--help       : Print this help.\n"
            "--dns-port   : Comma separated list of DNS ports to monitor. Default is 53.\n"
            "--iteration  : Number of 5-second capture windows. Default is 1.\n\n"
            "This program opens an AF_PACKET raw socket, so it usually requires root.\n",
            name);
}

static int dns_add_port(uint16_t port)
{
    size_t i;

    for (i = 0; i < dns_port_count; i++) {
        if (dns_ports[i] == port)
            return 0;
    }

    if (dns_port_count >= NETDATA_DNS_MAX_PORTS) {
        fprintf(stderr, "Maximum number of DNS ports (%d) reached.\n", NETDATA_DNS_MAX_PORTS);
        return -1;
    }

    dns_ports[dns_port_count++] = port;
    return 0;
}

static int dns_parse_port_list(const char *input)
{
    char *copy;
    char *cursor = NULL;
    char *token;

    if (!dns_ports_overridden) {
        dns_port_count = 0;
        dns_ports_overridden = 1;
    }

    copy = strdup(input);
    if (!copy) {
        fprintf(stderr, "Cannot duplicate DNS port list.\n");
        return -1;
    }

    token = strtok_r(copy, ",", &cursor);
    while (token) {
        char *endptr = NULL;
        unsigned long port;

        if (*token) {
            port = strtoul(token, &endptr, 10);
            if (*endptr || port == 0 || port > UINT16_MAX) {
                fprintf(stderr, "DNS port value (%s) is not valid.\n", token);
                free(copy);
                return -1;
            }

            if (dns_add_port((uint16_t)port)) {
                free(copy);
                return -1;
            }
        }

        token = strtok_r(NULL, ",", &cursor);
    }

    free(copy);

    if (!dns_port_count)
        return dns_add_port(NETDATA_DNS_DEFAULT_PORT);

    return 0;
}

static int dns_parse_iterations(const char *input)
{
    char *endptr = NULL;
    long value = strtol(input, &endptr, 10);

    if (*endptr) {
        fprintf(stderr, "Iteration value (%s) is not valid.\n", input);
        return -1;
    }

    if (value < 1) {
        fprintf(stderr, "Iteration value (%ld) is smaller than the minimum, resetting to 1.\n", value);
        value = 1;
    }

    dns_iterations = (int)value;
    return 0;
}

static int dns_run_test(void)
{
    struct dns_bpf *obj = dns_bpf__open();
    const char *status;
    int ret = 0;

    if (!obj) {
        fprintf(stderr, "Cannot open DNS BPF object.\n");
        return 2;
    }

    if (!ebpf_object_has_socket_filter(obj->obj)) {
        fprintf(stderr, "DNS skeleton does not expose a socket filter program.\n");
        dns_bpf__destroy(obj);
        return 3;
    }

    fprintf(stdout, "{\n    \"dns\" : {\n");
    status = ebpf_socket_filter_tester(obj->obj, 1, stdout, dns_iterations, dns_ports, dns_port_count);
    fprintf(stdout, "    },\n    \"Status\" :  \"%s\"\n}\n", status);

    if (strcmp(status, "Success"))
        ret = 4;

    dns_bpf__destroy(obj);
    return ret;
}

int main(int argc, char **argv)
{
    static struct option long_options[] = {
        {"help",      no_argument,       0, 0},
        {"dns-port",  required_argument, 0, 0},
        {"iteration", required_argument, 0, 0},
        {0,           no_argument,       0, 0}
    };

    int option_index = 0;

    while (1) {
        int c = getopt_long_only(argc, argv, "", long_options, &option_index);
        if (c == -1)
            break;

        switch (option_index) {
            case 0:
                dns_help(argv[0]);
                return 0;
            case 1:
                if (dns_parse_port_list(optarg))
                    return 1;
                break;
            case 2:
                if (dns_parse_iterations(optarg))
                    return 1;
                break;
            default:
                break;
        }
    }

    if (netdata_ebf_memlock_limit()) {
        fprintf(stderr, "Cannot increase memory limits.\n");
        return 1;
    }

    libbpf_set_print(netdata_libbpf_vfprintf);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    return dns_run_test();
}
