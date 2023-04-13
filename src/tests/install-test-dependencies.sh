#!/usr/bin/env bash

set +e

# This script needs to be run as 'root' user or with 'sudo'

DEBIAN_DEPS=( make gcc pkg-config libelf-dev clang llvm bpftool )
UBUNTU_DEPS=( make gcc pkg-config libelf-dev clang llvm "linux-tools-$(uname -r)" "linux-cloud-tools-$(uname -r)" )
RPM_DEPS=( make gcc pkg-config elfutils-libelf-devel clang llvm bpftool )
ALPINE_DEPS=( make gcc pkgconf clang llvm linux-tools linux-headers zlib-dev elfutils-dev musl-dev )
ARCH_DEPS=( make gcc pkg-config libelf clang llvm bpf )
SUSE_DEPS=( make gcc pkg-config libelf-devel clang llvm bpftool )

if command -v apt &> /dev/null; then
    if lsb_release -a | grep -i debian &>/dev/null; then
        # Debian
        echo "Installing Debian dependencies, please wait .."
        sed -r -i 's/^deb(.*)$/deb\1 contrib non-free/g' /etc/apt/sources.list
        apt update -y
        apt upgrade -y
        apt install -y "${DEBIAN_DEPS[@]}"
	ln -s /usr/sbin/bpftool /bin/bpftool
    else
        # Ubuntu
        echo "Installing Ubuntu dependencies, please wait .."
        apt update -y
        apt upgrade -y
        apt install -y "${UBUNTU_DEPS[@]}"
    fi
elif command -v dnf &> /dev/null; then
    # CentOS8, Alma, Rocky, Fedora
    echo "Installing Centos8/Alma/Rocky/Fedora dependencies, please wait .."
    dnf update -y
    dnf upgrade -y
    dnf install -y "${RPM_DEPS[@]}"
elif command -v apk &> /dev/null; then
    # Alpine
    echo "Installing Alpine dependencies, please wait .."
    apk update
    apk upgrade
    apk add "${ALPINE_DEPS[@]}"
elif command -v pacman &> /dev/null; then
    # Arch
    echo "Installing Arch dependencies, please wait .."
    pacman -S --noconfirm "${ARCH_DEPS[@]}"
elif command -v zypper &> /dev/null; then
    # Suse,OpenSUSE
    echo "Installing SUSE dependencies, please wait .."
    zypper install -y "${SUSE_DEPS[@]}"
fi
