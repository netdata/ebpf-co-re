CC=gcc

SOURCE_DIR = src/
_LIBC ?= glibc
KERNEL_VERSION="$(shell cat /proc/sys/kernel/osrelease)"
FIRST_KERNEL_VERSION=$(shell sh ./tools/complement.sh "$(KERNEL_VERSION)")
VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3 | cut -d\- -f1)
RUNNING_VERSION_CODE=$(shell echo $$(( $(VER_MAJOR) * 65536 + $(VER_MINOR) * 256 + $(VER_PATCH))) )


EXTRA_CFLAGS += -fno-stack-protector

all:
	cd $(SOURCE_DIR) && $(MAKE) all;
	tar -cf artifacts/netdata_ebpf-co-re-$(_LIBC)-${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.tar includes/*.skel.h
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf artifacts/netdata_ebpf-co-re-$(_LIBC)-${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.tar tools/check-kernel-core.sh; fi
	xz -f artifacts/netdata_ebpf-co-re-$(_LIBC)-${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.tar
	( cd artifacts; sha256sum netdata_ebpf-co-re-$(_LIBC)-${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.tar.xz > netdata_ebpf-co-re-$(_LIBC)-${VER_MAJOR}.${VER_MINOR}.${VER_PATCH}.tar.xz.sha256sum )

clean:
	cd $(SOURCE_DIR) && $(MAKE) clean;
	rm -f artifacts/*
	rm -f includes/*skel.h
	rm -rf .local_libbpf
