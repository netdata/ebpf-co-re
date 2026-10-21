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

All BPF programs use the pinned `../includes/vmlinux.h` x86_64 type snapshot. It is sourced from
[`libbpf/vmlinux.h`](https://github.com/libbpf/vmlinux.h/blob/c32912840154a82205530cd6d498b346ac73a6d1/include/x86_64/vmlinux_6.19.h)
at commit `c32912840154a82205530cd6d498b346ac73a6d1`; its SHA-256 is
`0b19715a3b9d5b3488fe6ade51c4d889d15a322f893ccd13ec030b8f59265df2`.
Pin and review a replacement snapshot before changing this file. A generated header supplies compile-time type
declarations; libbpf uses the target kernel's BTF for CO-RE relocations at load time. Changes to probe targets,
function signatures, or available BPF helpers still need their own compatibility handling.

For a kernel whose BTF is available locally, a header can be generated with:

```sh
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Skel files

When all compilation is finished, the `skel.c` files are stored inside `includes/` directory. These are the files used with [eBPF.plugin](https://github.com/netdata/netdata/tree/master/collectors/ebpf.plugin).

## Running CO-RE tests

After `make`, use the repository root `tests.sh` to run the aggregate C and Go testers. It passes test arguments to both implementations by default; `--backend c` or `--backend go` selects one implementation.

```sh
./tests.sh
./tests.sh --process --pid 2
./tests.sh --backend c --buffer --socket --iteration 1
./tests.sh --backend both --arena --all
```

The aggregate testers execute linked CO-RE test entrypoints in-process and produce a JSON summary. Test options such as module selectors, `--pid`, `--dns-port`, `--iteration`, `--buffer`, and `--arena` are forwarded. `--log-path FILE` writes separate reports for C and Go when both backends run. Use `./tests.sh --help` for runner options and `./src/tests/core_tester --help` for tester options.

`./core_tester_go` is built from `src/core_tester_go/core_tester.go` and uses CGO plus `netdata_core_loader.{c,h}` to call the renamed C test entrypoints directly. It does not spawn `src/tests/<module>` binaries. `--tests-dir` is used to locate `*_arena.bpf.o` files when arena mode is enabled.

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
