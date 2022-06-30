#!/bin/bash

three_tests=( "cachestat" "dc" "fd" "mount" "process" "shm" "socket" "swap" "sync" "vfs" )
one_test=( "disk" "hardirq" "oomkill" "softirq" )

echo "Running all tests with three options"
for i in "${three_tests[@]}" ; do
    {
        echo "================  Running $i  ================"
        echo "---> Probe: "
        "./$i" --probe
        echo "---> Tracepoint: "
        "./$i" --tracepoint
        echo "---> Trampoline: "
        "./$i" --trampoline
        echo "  "
    }  >> success.log 2>> error.log
done

echo "Running all tests with single option"
for i in "${one_test[@]}" ; do
    {
        echo "================  Running $i  ================"
        "./$i"
        echo "  "
    }
done

echo "We are not running filesystem or mdflush, because they can generate error, please run them."

ls -lh error.log success.log
