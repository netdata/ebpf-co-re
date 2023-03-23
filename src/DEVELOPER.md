# Developers

This MD file was added to help developers starting with eBPF development.

In this repo we are using the same [pattern](https://elixir.bootlin.com/linux/v6.3-rc2/source/samples/bpf) that was used with
latest [BTF](https://docs.kernel.org/bpf/btf.html) code. All source files ending with `.bpf.c` are eBPF codes converted to
`.skel.h` files (These are headers used to load eBPF code). We have independent source files `*.c` to demonstrate
the usage of `skel.h` files, these files are used with [eBPF.plugin](https://github.com/netdata/netdata/tree/master/collectors/ebpf.plugin)
to load specific eBPF programs.

## Libbpf

This repo using only the latest [latest](https://github.com/netdata/libbpf) libbpf version.

## Compiling kernel

To be able to test and compile the repo codes, your kernel needs to be compiled with at least the following options:

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

The code division for `CO-RE` codes (`bpf.c`) is the same used for [legacy codes](https://github.com/netdata/kernel-collector/blob/master/kernel/DEVELOPER.md#internal-code-division).

## Headers

By default `eBPF CO-RE` codes needs a header generated with the following `bpftool` command:

```sh
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## Skel files

When all compilation is finished, the `skel.c` files are stored inside `includes/` directory. These are the files used with [eBPF.plugin](https://github.com/netdata/netdata/tree/master/collectors/ebpf.plugin).

### Skel code division

Inside these headers we have:

-  A `structure` that defines eveyrything insie `bpf.c` files (maps and eBPF programs).
-  Functions to work with a specific eBPF code. To explain better I will use `NAME` to define these 'specific' code:
   - `NAME_bpf__open`: function that open the `CO-RE` code.
   - `NAME_bpf__load`: function that loads the binary code without to attach to final target. 
   - `NAME_bpf__attach`: Attach `CO-RE` codes to targets that can be `trampolines`, and `tracepoints`. For probes it is preferred to use `bpf_program__attach_kprobe`.
      Anything that we want to modify in the code needs to be done before to call it.
   - `NAME_bpf__destroy`: function that unloads the `CO-RE` code

