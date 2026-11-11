#!/usr/bin/env bash
# KERNIX G0 Linux/ARM64 CI only: HTTPS mirror failover for signed Ubuntu APT packages.
# No changes to original GNU/FEX source evidence. Fail closed if dependencies unavailable.
set -Eeuo pipefail
(( $# > 0 )) || { echo 'KERNIX_CI_APT: no packages requested' >&2; exit 2; }

required=("$@")
have() {
  case "$1" in
    clang) command -v clang >/dev/null && command -v clang++ >/dev/null ;;
    lld) command -v ld.lld >/dev/null ;;
    cmake) command -v cmake >/dev/null ;;
    ninja-build) command -v ninja >/dev/null ;;
    git) command -v git >/dev/null ;;
    python3) command -v python3 >/dev/null ;;
    pkg-config) command -v pkg-config >/dev/null ;;
    gdb) command -v gdb >/dev/null ;;
    binutils-x86-64-linux-gnu)
      command -v x86_64-linux-gnu-as >/dev/null &&
      command -v x86_64-linux-gnu-objdump >/dev/null &&
      command -v x86_64-linux-gnu-objcopy >/dev/null ;;
    *) dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -qx 'install ok installed' ;;
  esac
}
missing=()
for pkg in "${required[@]}"; do
  if ! have "$pkg"; then missing+=("$pkg"); fi
done
if (( ${#missing[@]} == 0 )); then
  echo "KERNIX_CI_ARM64_APT_PACKAGES_ALREADY_PRESENT_NO_NETWORK_NEEDED ${required[*]}"
  exit 0
fi

export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-o Acquire::Retries=0 -o Acquire::http::Timeout=12
          -o Acquire::https::Timeout=12 -o Dpkg::Use-Pty=0)
# The fallback hosts carry Ubuntu-signed packages. APT continues enforcing signed Release files.
mirrors=(
  'http://ports.ubuntu.com/ubuntu-ports'
  'https://mirrors.tuna.tsinghua.edu.cn/ubuntu-ports'
  'https://mirrors.ustc.edu.cn/ubuntu-ports'
  'https://mirrors.aliyun.com/ubuntu-ports'
)
sourcefiles=()
for f in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
  if [[ -f "$f" ]]; then sourcefiles+=("$f"); fi
done
(( ${#sourcefiles[@]} > 0 )) || { echo 'KERNIX_CI_APT: No Ubuntu APT source files' >&2; exit 1; }
mkdir -p dist
for mirror in "${mirrors[@]}"; do
  echo "KERNIX_CI_APT_ATTEMPT_MIRROR=$mirror"
  for file in "${sourcefiles[@]}"; do
    sudo sed -E -i \
      "s#https?://(ports\\.ubuntu\\.com/ubuntu-ports|mirrors\\.tuna\\.tsinghua\\.edu\\.cn/ubuntu-ports|mirrors\\.ustc\\.edu\\.cn/ubuntu-ports|mirrors\\.aliyun\\.com/ubuntu-ports)#$mirror#g" "$file"
  done
  # Explicit timeout: DNS outages must not consume the entire guest hardware test window.
  if timeout -k 3s 100s sudo apt-get "${APT_OPTS[@]}" update -qq \
      >dist/kernix-ci-apt-update.log 2>&1 &&
     timeout -k 3s 115s sudo apt-get "${APT_OPTS[@]}" install -y --no-install-recommends "${missing[@]}" \
      >dist/kernix-ci-apt-install.log 2>&1; then
    all_present=true
    for pkg in "${required[@]}"; do
      if ! have "$pkg"; then all_present=false; echo "KERNIX_CI_APT_MISSING_EXECUTABLE=$pkg"; fi
    done
    if "$all_present"; then
      echo "KERNIX_CI_ARM64_SIGNED_UBUNTU_APT_PREREQUISITES_CONFIRMED mirror=$mirror"
      exit 0
    fi
  fi
  echo "KERNIX_CI_APT_UNAVAILABLE_ON_MIRROR=$mirror"
  tail -n 9 dist/kernix-ci-apt-update.log 2>/dev/null || true
  tail -n 9 dist/kernix-ci-apt-install.log 2>/dev/null || true
done
echo 'KERNIX_CI_ARM64_PREREQUISITES_UNAVAILABLE_FAIL_CLOSED_NO_NATIVE_EVIDENCE' >&2
exit 1
