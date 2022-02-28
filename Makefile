CC=gcc

SOURCE_DIR = src/
_LIBC ?= glibc

EXTRA_CFLAGS += -fno-stack-protector

all:
	cd $(SOURCE_DIR) && $(MAKE) all;
	tar -cf artifacts/netdata_ebpf-co-re-$(_LIBC).tar includes/*.skel.h
	if [ "$${DEBUG:-0}" -eq 1 ]; then tar -uvf artifacts/netdata_ebpf-co-re-$(_LIBC).tar tools/check-kernel-core.sh; fi
	xz -f artifacts/netdata_ebpf-co-re-$(_LIBC).tar
	( cd artifacts; sha256sum netdata_ebpf-co-re-$(_LIBC).tar.xz > netdata_ebpf-co-re-$(_LIBC).tar.xz.sha256sum )

clean:
	cd $(SOURCE_DIR) && $(MAKE) clean;
	rm -f artifacts/*
	rm -f includes/*skel.h
	rm -rf .local_libbpf
