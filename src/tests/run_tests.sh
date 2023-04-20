#!/bin/bash

three_tests=( "cachestat" "dc" "fd" "mount" "process" "shm" "socket" "swap" "sync" "vfs" )
one_test=( "disk" "hardirq" "oomkill" "softirq" )
end_loop=
ADDITIONAL_ARG=

log_files_success=()
log_files_error=()

runThreeTests () {
    echo "================  Starting test ${1}  ================\n"  2>&1
    pid=$("$1" --help | grep pid)
    if [ -z "${pid}" ]; then
        end_loop=0
    else
        end_loop=2
    fi

    for j in $(seq 0 $end_loop); do
    if [ -z "${pid}" ]; then
            echo "================  Running %s without PID  ================\n" "${i}"
            ADDITIONAL_ARG=""
    else
            echo "================  Running %s with PID GROUP %s  ================\n" "${i}" "${j}"
            ADDITIONAL_ARG="--pid $j"
    fi

    echo "---> Probe: "
    probe_cmd="$1 --probe ${ADDITIONAL_ARG}"
    eval "$probe_cmd"

    echo "---> Tracepoint: "
    tracepoint_cmd="$1 --tracepoint ${ADDITIONAL_ARG}"
    eval "$tracepoint_cmd"

    echo "---> Trampoline: "
    trampoline_cmd="$1 --trampoline ${ADDITIONAL_ARG}"
    eval "$trampoline_cmd"
    echo "  "
    done
    echo "================  Ending test ${1}  ================\n" 2>&1
}

echo "Running all tests with three options"
for i in "${three_tests[@]}" ; do
    {
        log_file_success="output_${i}_success.log"
        log_file_error="output_${i}_error.log"
        log_files_success+=("$log_file_success")
        log_files_error+=("$log_file_error")
        runThreeTests ./"$i" >> output_"${i}"_success.log 2>> output_"${i}"_error.log &
    }
done

runOneTest () {
    echo "================  Starting test $1  ================"
    "$1" &
    echo "  "
    echo "================  End test $1  ================"
}


echo "Running all tests with single option"
for i in "${one_test[@]}" ; do 
    {
        log_file_success="output_${i}_success.log"
        log_file_error="output_${i}_error.log"
        log_files_success+=("$log_file_success")
        log_files_error+=("$log_file_error")
        runOneTest ./"$i" >> output_"${i}"_success.log 2>> output_"${i}"_error.log &
    }
done

echo "We are not running filesystem or mdflush, because they can generate error, please run them."


wait

# Concatenate log files 

cat "${log_files_success[@]}" > success.log
cat "${log_files_error[@]}" > error.log
rm "${log_files_success[@]}"
rm "${log_files_error[@]}"


ls -lh error.log success.log
