Linux Kernel eBPF CO-RE

## Directory structure

The respository has the following directory structure:

- `artifacts`: directory that will have the eBPF programs when the compilation
  process ends.
- `includes`: headers used to compile `eBPF.plugin`.
- `kernel-collector`: this is a submodule'd fork of
  [netdata/libbpf](https://github.com/netdata/kernel-collector).
- `libbpf`: this is a submodule'd fork of
  [netdata/libbpf](https://github.com/netdata/libbpf) which is itself a fork of
  the official `libbpf` package, the user-space side of eBPF system calls.

## Requirements

#### Packages

To compile the eBPF CO-RE, it will be necessary to have the following
packages:

- libelf headers
- LLVM/Clang; this is because GCC prior to 10.0 cannot compile eBPF code.
- `bpftool`: used to generate source codes.

#### Initializing Submodules

`libbpf` directory is included as a git submodule and it is necessary to fetch contents with the git command below:
```bash
git submodule update --init --recursive

