#!/usr/bin/env bash

set -uo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
if [[ ! -d "$repo_root/src/tests" || ! -f "$repo_root/.gitignore" || -L "$repo_root/.tmp" ]]; then
    printf 'ERROR: invalid repository root or unsafe .tmp directory: %s\n' "$repo_root" >&2
    exit 1
fi
backend=both
tester_args=()
requested_log_path=

usage() {
    cat <<'EOF'
Usage: ./tests.sh [--backend c|go|both] [test options...]

Runs the aggregate CO-RE tests with the selected implementation. Test options
are passed to core_tester and core_tester_go, including module selectors,
--pid, --iteration, --buffer, and --arena. With no test options, each runner
uses its default selection and mode.

Examples:
  ./tests.sh --process --pid 2
  ./tests.sh --backend c --buffer --socket --iteration 1
  ./tests.sh --backend both --arena --all

With one backend, --log-path FILE uses that exact path. With both backends,
reports are written to FILE.c.json and FILE.go.json (or FILE.c/FILE.go before
a .json suffix).
EOF
}

while (($#)); do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --backend)
            if (($# < 2)); then
                printf 'ERROR: --backend requires c, go, or both.\n' >&2
                exit 2
            fi
            backend=$2
            shift 2
            ;;
        --backend=*)
            backend=${1#*=}
            shift
            ;;
        --log-path)
            if (($# < 2)); then
                printf 'ERROR: --log-path requires a file path.\n' >&2
                exit 2
            fi
            requested_log_path=$2
            shift 2
            ;;
        --log-path=*)
            requested_log_path=${1#*=}
            shift
            ;;
        --)
            shift
            tester_args+=("$@")
            break
            ;;
        *)
            tester_args+=("$1")
            shift
            ;;
    esac
done

case "$backend" in
    c|go|both) ;;
    *)
        printf 'ERROR: unsupported backend %q; choose c, go, or both.\n' "$backend" >&2
        exit 2
        ;;
esac

mkdir -p -- "$repo_root/.tmp" || {
    printf 'ERROR: could not create %s/.tmp\n' "$repo_root" >&2
    exit 1
}
if [[ "$(realpath -e -- "$repo_root/.tmp")" != "$repo_root/.tmp" ]]; then
    printf 'ERROR: unsafe test log directory: %s/.tmp\n' "$repo_root" >&2
    exit 1
fi
test_log_dir=$(mktemp -d "$repo_root/.tmp/ebpf-tests.XXXXXX") || {
    printf 'ERROR: could not create test log directory under %s/.tmp\n' "$repo_root" >&2
    exit 1
}

test_status=0

run_backend() {
    local name=$1
    local binary=$2
    local -a args=("${tester_args[@]}")
    local stdout_log="$test_log_dir/$name.stdout"
    local stderr_log="$test_log_dir/$name.stderr"
    local report_path=$requested_log_path

    if [[ ! -x "$binary" ]]; then
        printf '[  MISSING  ] %s tester: %s (run make first)\n' "$name" "$binary"
        test_status=1
        return
    fi

    if [[ -n "$requested_log_path" ]]; then
        if [[ "$backend" == both ]]; then
            local report_base=$requested_log_path
            if [[ "$report_base" == *.json ]]; then
                report_base=${report_base%.json}
            fi
            report_path="${report_base}.${name}.json"
        fi
        args+=(--log-path "$report_path")
    fi

    printf '[ RUN      ] %s (%s)\n' "$name" "$binary"
    local rc=0
    "$binary" "${args[@]}" >"$stdout_log" 2>"$stderr_log" || rc=$?

    if ((rc == 0)); then
        printf '[       OK ] %s\n' "$name"
    else
        printf '[  FAILED  ] %s (exit %d)\n' "$name" "$rc"
        test_status=1
    fi

    if [[ -s "$stdout_log" ]]; then
        cat "$stdout_log"
    fi
    if [[ -s "$stderr_log" ]]; then
        cat "$stderr_log" >&2
    fi
    if [[ -n "$requested_log_path" ]]; then
        printf '[ REPORT   ] %s\n' "$report_path"
    fi
}

case "$backend" in
    c) run_backend c "$repo_root/src/tests/core_tester" ;;
    go) run_backend go "$repo_root/src/tests/core_tester_go" ;;
    both)
        run_backend c "$repo_root/src/tests/core_tester"
        run_backend go "$repo_root/src/tests/core_tester_go"
        ;;
esac

printf '[ LOGS     ] %s\n' "$test_log_dir"
exit "$test_status"
