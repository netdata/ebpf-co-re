#!/bin/bash

three_tests=( "cachestat" "dc" "fd" "mount" "networkviewer" "process" "shm" "socket" "swap" "sync" "vfs" )
one_test=( "disk" "hardirq" "oomkill" "softirq" )
end_loop=
ADDITIONAL_ARG=

echo "Running all tests with three options"
for i in "${three_tests[@]}" ; do
    {
        pid=$("./$i" --help | grep pid)
        if [ -z "${pid}" ]; then
            end_loop=0
        else
            end_loop=3
        fi

        for j in $(seq 0 $end_loop); do
	    if [ -z "${pid}" ]; then
                printf "================  Running %s without PID  ================\n" "${i}"
                ADDITIONAL_ARG=""
	    else
                printf "================  Running %s with PID GROUP %s  ================\n" "${i}" "${j}"
                ADDITIONAL_ARG="--pid $j"
	    fi

            echo "---> Probe: "
            probe_cmd="./$i --probe ${ADDITIONAL_ARG}"
            eval "$probe_cmd"

            echo "---> Tracepoint: "
            tracepoint_cmd="./$i --tracepoint ${ADDITIONAL_ARG}"
            eval "$tracepoint_cmd"

            echo "---> Trampoline: "
            trampoline_cmd="./$i --trampoline ${ADDITIONAL_ARG}"
            eval "$trampoline_cmd"
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

ls -lh ./*.log
