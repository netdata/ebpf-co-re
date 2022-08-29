#!/bin/bash

three_tests=( "cachestat" "dc" "fd" "mount" "process" "shm" "socket" "swap" "sync" "vfs" )
one_test=( "disk" "hardirq" "oomkill" "softirq" )
end_loop=

echo "Running all tests with three options"
for i in "${three_tests[@]}" ; do
    {
        pid=$("./$i" --help | grep pid)
        if [ -z "${pid}" ]; then
    	    end_loop=0
        else
    	    end_loop=2
        fi

        for j in $(seq 0 $end_loop); do
	    if [ -z "${pid}" ]; then
                printf "================  Running %s without PID  ================" "${i}"
	    else
                printf "================  Running %s with PID GROUP %s  ================" "${i}" "${j}"
	    fi
            echo "---> Probe: "
            "./$i" --probe
            echo "---> Tracepoint: "
            "./$i" --tracepoint
            echo "---> Trampoline: "
            "./$i" --trampoline
            echo "  "
        done
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
