#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
    echo "Give kernel as parameter: kernel major version, kernel minor version, and function name"
    exit 1
fi

NAME="$3"

parse_kernel_version() {
    R="${1}.${2}"

    read -r -a P <<< "$(echo "${R}" | tr '.' ' ')"

    printf "%03d%03d" "${P[0]}" "${P[1]}"
}

select_kernel_version() {
    KVER=$(parse_kernel_version "${1}" "${2}")
    
    VER5_19_0="005019"

    if [ "${KVER}" -lt "${VER5_19_0}" ]; then
        KSELECTED="508";
    else
        KSELECTED="519";
    fi    

    echo "${KSELECTED}"
}

if [ "socket.skel.h" != "${NAME}" ]; then
    exit 0;
fi


KNAME=$(select_kernel_version "${1}" "${2}")

mv "../includes/$3" "../includes/socket_$KNAME.skel.h"
