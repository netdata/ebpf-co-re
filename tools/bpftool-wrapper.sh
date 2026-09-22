#!/bin/sh

set -eu

if [ "$#" -lt 1 ]; then
    echo "usage: $0 BPFTOOL [arguments ...]" >&2
    exit 2
fi

tool=$1
shift

if ! command -v "$tool" >/dev/null 2>&1 && [ ! -x "$tool" ]; then
    echo "bpftool executable not found: $tool" >&2
    exit 127
fi

if [ "${tool#/}" = "$tool" ]; then
    tool=$(command -v "$tool")
fi

diagnostic=$(mktemp "${TMPDIR:-/tmp}/ebpf-bpftool.XXXXXX")
library_dir=
cleanup()
{
    rm -f "$diagnostic"
    if [ -n "$library_dir" ]; then
        rm -f "$library_dir"/* 2>/dev/null || true
        rmdir "$library_dir" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if "$tool" "$@" 2>"$diagnostic"; then
    cat "$diagnostic" >&2
    exit 0
fi

missing_library=$(ldd "$tool" 2>&1 | sed -n 's/.*\(libLLVM[^ ]*\.so[^ ]*\) => not found.*/\1/p' | head -n 1)
if [ -z "$missing_library" ]; then
    cat "$diagnostic" >&2
    exit 1
fi

library_dir=$(mktemp -d "${TMPDIR:-/tmp}/ebpf-bpftool-lib.XXXXXX")
candidate=

old_ifs=$IFS
IFS=:
for search_dir in ${LD_LIBRARY_PATH:-}; do
    [ -d "$search_dir" ] || continue
    for possible in "$search_dir/$missing_library" "$search_dir/$missing_library"-*; do
        if [ -f "$possible" ]; then
            candidate=$possible
            break 2
        fi
    done
done
IFS=$old_ifs

if [ -z "$candidate" ]; then
    for search_dir in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64; do
        [ -d "$search_dir" ] || continue
        for possible in "$search_dir/$missing_library" "$search_dir/$missing_library"-*; do
            if [ -f "$possible" ]; then
                candidate=$possible
                break 2
            fi
        done
    done
fi

if [ -z "$candidate" ]; then
    cat "$diagnostic" >&2
    echo "bpftool requires $missing_library, but no compatible installed library was found" >&2
    exit 127
fi

ln -s "$candidate" "$library_dir/$missing_library"
echo "bpftool: using $candidate for missing $missing_library" >&2
LD_LIBRARY_PATH="$library_dir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$tool" "$@"
