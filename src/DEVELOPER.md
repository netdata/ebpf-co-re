# Developers

This MD file was added to help developers starting with eBPF development.

In this repo we are using the same [pattern](https://elixir.bootlin.com/linux/v6.3-rc2/source/samples/bpf) that was used with
latest [BTF](https://docs.kernel.org/bpf/btf.html) code. All source files ending with `.bpf.c` are eBPF code converted to
`.skel.h` files (These are headers used to load eBPF code). We have independent source files `*.c` to demonstrate
the usage of `skel.h` files, these files are used with [eBPF.plugin](https://github.com/netdata/netdata/tree/master/collectors/ebpf.plugin)
to load specific eBPF programs.

## Libbpf

This repo using only the latest [latest](https://github.com/netdata/libbpf) libbpf version.

## Compiling kernel

To be able to test and compile the repo code, your kernel needs to be compiled with at least the following options:

```sh
CONFIG_DEBUG_INFO_BTF=y
CONFIG_PAHOLE_HAS_SPLIT_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_MODULE_ALLOW_BTF_MISMATCH=y
```

Your environment also needs to have [pahole](https://lwn.net/Articles/335942/) installed. Install it using package management or with the following steps:

```sh
# git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git
# cd pahole
# git submodule update --init
# mkdir build
# cd build
# cmake -D__LIB=lib64 -DCMAKE_INSTALL_PREFIX=/usr ..
# make
# make install

```

## Internal Code division

The code division for `CO-RE` code (`bpf.c`) is the same used for [legacy code](https://github.com/netdata/kernel-collector/blob/master/kernel/DEVELOPER.md#internal-code-division).

## Headers

By default `eBPF CO-RE` code needs a header generated with the following `bpftool` command:

```sh
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Skel files

When all compilation is finished, the `skel.c` files are stored inside `includes/` directory. These are the files used with [eBPF.plugin](https://github.com/netdata/netdata/tree/master/collectors/ebpf.plugin).

## Running CO-RE tests

After `make`, the per-module CO-RE testers, the aggregate C tester, and the parallel aggregate Go tester are stored under `src/tests/`.

```sh
cd src/tests
./core_tester
./core_tester_go
```

The aggregate tester executes the existing CO-RE module testers, checks that the matching `includes/*.skel.h` artifacts exist, and writes a JSON summary to stdout. Use `./core_tester --help` to run a subset of modules or override options such as `--pid`, `--dns-port`, and `--iteration`.

`./core_tester_go` is a stdlib-only Go port of `./core_tester` intended for side-by-side parity checks. It preserves the same flags, default selection behavior, JSON schema, and exit-code policy without replacing the current C workflow.

`./core_tester --all` runs all non-filesystem CO-RE tests and expands each selected module across every mode that tester supports.

### Skel code division

Inside these headers we have:

-  A `structure` that defines eveyrything insie `bpf.c` files (maps and eBPF programs).
-  Functions to work with a specific eBPF code. To explain better I will use `NAME` to define these 'specific' code:
   - `NAME_bpf__open`: function that open the `CO-RE` code.
   - `NAME_bpf__load`: function that loads the binary code without to attach to final target. 
   - `NAME_bpf__attach`: Attach `CO-RE` code to targets that can be `trampolines`, and `tracepoints`. For probes it is preferred to use `bpf_program__attach_kprobe`.
      Anything that we want to modify in the code needs to be done before to call it.
   - `NAME_bpf__destroy`: function that unloads the `CO-RE` code
