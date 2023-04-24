#!/bin/bash

set +e

# This script needs to be run as 'root' user or with 'sudo'

DEBIAN_DEPS="make gcc pkg-config libelf-dev clang llvm bpftool"
UBUNTU_DEPS="make gcc pkg-config libelf-dev clang llvm linux-tools-generic linux-cloud-tools-generic"
RPM_DEPS="make gcc pkg-config elfutils-libelf-devel clang llvm bpftool"
ARCH_DEPS="make gcc pkg-config libelf clang llvm bpf"
SUSE_DEPS="make gcc pkg-config libelf-devel clang llvm bpftool"


# mirror functions from https://github.com/netdata/netdata/blob/master/packaging/installer/kickstart.sh

str_in_list() {
  printf "%s\n" "${2}" | tr ' ' "\n" | grep -qE "^${1}\$"
  return $?
}

get_system_info() {
  export SYSARCH="$(uname -m)"

  case "$(uname -s)" in
    Linux)
      SYSTYPE="Linux"

      if [ -z "${SKIP_DISTRO_DETECTION}" ]; then
        os_release_file=
        if [ -s "/etc/os-release" ] && [ -r "/etc/os-release" ]; then
          os_release_file="/etc/os-release"
        elif [ -s "/usr/lib/os-release" ] && [ -r "/usr/lib/os-release" ]; then
          os_release_file="/usr/lib/os-release"
        else
          warning "Cannot find usable OS release information. Native packages will not be available for this install."
        fi

        if [ -n "${os_release_file}" ]; then
          # shellcheck disable=SC1090
          . "${os_release_file}"

          DISTRO="${ID}"
          SYSVERSION="${VERSION_ID}"
          export SYSCODENAME="${VERSION_CODENAME}"
        else
          DISTRO="unknown"
          DISTRO_COMPAT_NAME="unknown"
          SYSVERSION="unknown"
          # shellcheck disable=SC2034
          SYSCODENAME="unknown"
        fi
      else
        warning "Distribution auto-detection overridden by user. This is not guaranteed to work, and is not officially supported."
      fi

      supported_compat_names="debian ubuntu centos fedora opensuse ol amzn arch"

      if str_in_list "${DISTRO}" "${supported_compat_names}"; then
          DISTRO_COMPAT_NAME="${DISTRO}"
      else
          case "${DISTRO}" in
          opensuse-leap) DISTRO_COMPAT_NAME="opensuse" ;;
          cloudlinux|almalinux|rocky|rhel) DISTRO_COMPAT_NAME="centos" ;;
          artix|manjaro|obarun) DISTRO_COMPAT_NAME="arch" ;;
          *) DISTRO_COMPAT_NAME="unknown" ;;
          esac
      fi

      case "${DISTRO_COMPAT_NAME}" in
        centos|ol) SYSVERSION=$(echo "$SYSVERSION" | cut -d'.' -f1) ;;
      esac
      ;;
    Darwin)
      # shellcheck disable=SC2034
      SYSTYPE="Darwin"
      SYSVERSION="$(sw_vers -buildVersion)"
      ;;
    FreeBSD)
      # shellcheck disable=SC2034
      SYSTYPE="FreeBSD"
      SYSVERSION="$(uname -K)"
      ;;
    *) fatal "Unsupported system type detected. Netdata cannot be installed on this system using this script." F0200 ;;
  esac
}


get_system_info

case $DISTRO_COMPAT_NAME in 
    debian)
        # Debian
        echo "Installing Debian dependencies, please wait ..";
        sed -r -i 's/^deb(.*)$/deb\1 contrib non-free/g' /etc/apt/sources.list;
        apt update -y;
        apt upgrade -y;
        printf '%s\n' "$DEBIAN_DEPS" | xargs apt install -y
        ln -s /usr/sbin/bpftool /bin/bpftool;;
    ubuntu)
        # Ubuntu
        echo "Installing Ubuntu dependencies, please wait ..";
        apt update -y;
        apt upgrade -y;
        printf '%s\n' "$UBUNTU_DEPS" | xargs apt install -y ;;
    centos)
    # CentOS8, Alma, Rocky, Fedora
        echo "Installing Centos8/Alma/Rocky/Fedora dependencies, please wait ..";
        dnf update -y;
        dnf upgrade -y;
        printf '%s\n' "$RPM_DEPS" | xargs dnf install -y;;
    arch)
    # Arch
        echo "Installing Arch dependencies, please wait ..";
        printf '%s\n' "$ARCH_DEPS" | xargs  pacman -S --noconfirm;;
    opensuse)
    # Suse,OpenSUSE
        echo "Installing SUSE dependencies, please wait ..";
        printf '%s\n' "$SUSE_DEPS" | xargs zypper install -y;;
    * )
        echo "Error: No supported package manager found." >&2;
        exit 1;;
esac
