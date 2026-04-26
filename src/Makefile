LIBBPF = ../libbpf
CFLAGS = -Wall -ggdb
INCLUDES = -I../.local_libbpf/ -I../includes/ -I$(LIBBPF)/src/ -I. -I../kernel-collector/includes/ -I$(LIBBPF)/include/uapi/
CLANG ?= clang 
LLVM_STRIP ?= llvm-strip
OUTPUT = tests/
ARCH := $(shell uname -m | sed 's/x86_64/x86/')
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }') 
KERNEL_VERSION="$(shell cat /proc/sys/kernel/osrelease)"
FIRST_KERNEL_VERSION=$(shell sh ../kernel-collector/tools/complement.sh "$(KERNEL_VERSION)")
VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3 | cut -d\- -f1)
RUNNING_VERSION_CODE=$(shell echo $$(( $(VER_MAJOR) * 65536 + $(VER_MINOR) * 256 + $(VER_PATCH))) )

_LIBC ?= glibc

APPS = cachestat \
       dc \
       dns \
       disk \
       fd \
       filesystem \
       hardirq \
       networkviewer \
       mdflush \
       mount \
       oomkill \
       process \
       shm \
       socket \
       softirq \
       swap \
       sync \
       vfs \
       #

AGGREGATE_TESTER = core_tester
AGGREGATE_TESTER_GO = core_tester_go
GO ?= go
GO_EMBED_DIR = embedded/includes
GO_EMBED_STAMP = $(GO_EMBED_DIR)/.stamp
AGGREGATE_APP_OBJECTS = $(patsubst %,aggregate/%.o,$(APPS))
LOADER_OBJ = netdata_core_loader.o
AGGREGATE_LIB = aggregate/libnetdata_tests.a

DNS_HELPER_OBJ = dns_tester_legacy.o

all: compress $(OUTPUT)$(AGGREGATE_TESTER) $(OUTPUT)$(AGGREGATE_TESTER_GO)

libbpf:
	cd $(LIBBPF)/src && $(MAKE) BUILD_STATIC_ONLY=1 DESTDIR=../../.local_libbpf INCLUDEDIR= LIBDIR= UAPIDIR= install \

%.bpf.o: %.bpf.c libbpf
	$(CLANG) -fno-stack-protector $(INCLUDES) -ggdb -O2 -target bpf -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) -D__TARGET_ARCH_$(ARCH) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > ../includes/$@

$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

%.o: %.c 
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(filter-out dns,$(APPS)): %: %.o
	$(CC) $(CFLAGS) -L../.local_libbpf $^ -lbpf -lelf -lz -o $(OUTPUT)$@

dns: dns.o $(DNS_HELPER_OBJ)
	$(CC) $(CFLAGS) -L../.local_libbpf $^ -lbpf -lelf -lz -o $(OUTPUT)$@

$(DNS_HELPER_OBJ): ../kernel-collector/tests/tester_dns.c libbpf
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -c $< -o $@

compress: $(APPS)

aggregate/%.o: %.c %.skel.h
	mkdir -p aggregate
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -Dmain=netdata_$*_entry -c $< -o $@

$(LOADER_OBJ): netdata_core_loader.c netdata_core_loader.h
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -c $< -o $@

$(AGGREGATE_LIB): $(AGGREGATE_APP_OBJECTS) $(DNS_HELPER_OBJ) $(LOADER_OBJ)
	ar rcs $@ $^

$(OUTPUT)$(AGGREGATE_TESTER): core_tester.c $(LOADER_OBJ) $(AGGREGATE_APP_OBJECTS) $(DNS_HELPER_OBJ)
	$(CC) $(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) $(INCLUDES) -L../.local_libbpf $< $(LOADER_OBJ) $(AGGREGATE_APP_OBJECTS) $(DNS_HELPER_OBJ) -lbpf -lelf -lz -o $@

$(GO_EMBED_STAMP): compress
	mkdir -p $(GO_EMBED_DIR)
	rm -f $(GO_EMBED_DIR)/*.skel.h
	cp ../includes/*.skel.h $(GO_EMBED_DIR)/
	touch $@

$(OUTPUT)$(AGGREGATE_TESTER_GO): $(AGGREGATE_LIB) core_tester_go/core_tester.go
	CGO_ENABLED=1 \
	CGO_CFLAGS="$(CFLAGS) -DMY_LINUX_VERSION_CODE=$(RUNNING_VERSION_CODE) -I$(CURDIR) -I$(CURDIR)/../.local_libbpf -I$(CURDIR)/../includes -I$(CURDIR)/../kernel-collector/includes -I$(CURDIR)/../libbpf/src -I$(CURDIR)/../libbpf/include/uapi" \
	CGO_LDFLAGS="-L$(CURDIR)/aggregate -lnetdata_tests -L$(CURDIR)/../.local_libbpf -lbpf -lelf -lz" \
	$(GO) build -o $@ core_tester_go/core_tester.go

clean:
	rm -f ../artifacts/netdata_ebpf-CO-RE-*.tar.xz
	rm -f ../artifacts/netdata_ebpf-CO-RE-*.tar.xz.sha256sum
	cd $(LIBBPF)/src/ && make clean
	cd $(OUTPUT) && find . -type f ! -name '*.sh' ! -name '.git*'  -delete
	rm -f *.o 
	rm -rf aggregate
	rm -rf embedded
