#!/usr/bin/env bash

set -e

custom_test=$1

three_tests=( "cachestat" "dc" "fd" "mount" "process" "shm" "socket" "swap" "sync" "vfs" )
one_test=( "disk" "hardirq" "oomkill" "softirq" "filesystem" )

run_three_tests() {
    local test_to_run=$1

    echo "================  Running $test_to_run  ================"
    echo "---> Probe: "
    "./bin/$test_to_run" --probe
    echo "---> Tracepoint: "
    "./bin/$test_to_run" --tracepoint
    echo "---> Trampoline: "
    "./bin/$test_to_run" --trampoline
    echo "  "
}

run_one_test() {
    local test_to_run=$1

    echo "================  Running $test_to_run  ================"
    if [[ "$test_to_run" == "filesystem" ]]; then
        filesystem_list=( "nfs" "ext4" "btrfs" "xfs" )
        for fs in "${filesystem_list[@]}" ; do
            if grep -v nodev /proc/filesystems | grep "$fs"; then
                ./bin/filesystem --"$fs"
            fi
        done
    else
        "./bin/$test_to_run"
        echo "  "
    fi
}

if [[ -n "$custom_test" ]]; then
    if [[ ${three_tests[*]} =~ ${custom_test} ]]; then
        run_three_tests "$custom_test"
    fi
    if [[ ${one_test[*]} =~ ${custom_test} ]]; then
        run_one_test "$custom_test"
    fi
else
    echo "Running all tests with three options"
    for i in "${three_tests[@]}" ; do
        run_three_tests "$i"
    done

    echo "Running all tests with single option"
    for i in "${one_test[@]}" ; do
        run_one_test "$i"
    done
    echo "We are not running filesystem or mdflush, because they can generate error, please run them."
fi
