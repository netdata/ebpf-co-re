#!/bin/bash

set -u

test_log_dir=$(mktemp -d "${TMPDIR:-/tmp}/ebpf-co-re-tests.XXXXXX")
test_status=0

run_test() {
    label=$1
    shift
    printf '[ RUN      ] %s\n' "$label"
    if "$@" >"${test_log_dir}/${label}.out" 2>"${test_log_dir}/${label}.err"; then
        printf '[       OK ] %s\n' "$label"
    else
        test_status=$?
        printf '[  FAILED  ] %s (logs: %s)\n' "$label" "$test_log_dir"
    fi
}

run_test buffer-c ./src/tests/core_tester --iteration 1 --buffer --log-path "${test_log_dir}/buffer-c.log"
run_test buffer-go ./src/tests/core_tester_go --iteration 1 --buffer --log-path "${test_log_dir}/buffer-go.log"
run_test arena-c ./src/tests/core_tester --iteration 1 --arena --log-path "${test_log_dir}/arena-c.log"
run_test arena-go ./src/tests/core_tester_go --iteration 1 --arena --log-path "${test_log_dir}/arena-go.log"

exit "$test_status"
