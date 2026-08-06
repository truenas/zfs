#!/usr/bin/env bash

######################################################################
# fetch and verify debs from a rolling TrueNAS kernel release
#
# fetch-tn-kernel.sh KERNEL_REPO KERNEL_TAG DIR PATTERN...
#
# KERNEL_REPO: GitHub repository publishing the rolling kernel
#              releases (e.g. truenas/linux)
# KERNEL_TAG:  release tag to install the kernel from (e.g.
#              master-nightly); the pairing lives in
#              .github/trains.json
# DIR:         directory to download into, created if needed
# PATTERN:     shell patterns matched against the manifest's debs[].
#              A pattern starting with '!' excludes, and exclusions
#              win however the patterns are ordered.
#
# Consumes the release the same way downstream consumers are meant to:
# fetch manifest.json to learn the current kernel release and file
# names, then verify the debs against SHA256SUMS.  Leaves
# manifest.json in DIR for the caller to read .release and .commit
# from.
#
# ci.yml (headers only, in a container) and qemu-tn-kernel-vm.sh
# (image and headers, on the test VM) both consume releases this way;
# one copy keeps the checksum verification identical on both paths.
######################################################################

set -eu

[ $# -ge 4 ] || {
  echo "usage: fetch-tn-kernel.sh KERNEL_REPO KERNEL_TAG DIR PATTERN..." >&2
  exit 1
}

KERNEL_REPO="$1"
KERNEL_TAG="$2"
DIR="$3"
shift 3

URL="https://github.com/${KERNEL_REPO}/releases/download/${KERNEL_TAG}"

mkdir -p "$DIR"
cd "$DIR"

if ! curl --fail -LSs -O "$URL/manifest.json"; then
  echo "ERROR: no $KERNEL_TAG kernel release published at $URL yet" >&2
  exit 1
fi
curl --fail -LSs -O "$URL/SHA256SUMS"

includes=()
excludes=()
for pattern in "$@"; do
  case "$pattern" in
    '!'*) excludes+=("${pattern#!}") ;;
    *)    includes+=("$pattern") ;;
  esac
done

wanted=()
for deb in $(jq -r '.debs[]' manifest.json); do
  keep=""
  for pattern in "${includes[@]}"; do
    # shellcheck disable=SC2254 # the patterns are meant to glob
    case "$deb" in $pattern) keep=yes ;; esac
  done
  # Exclusions win however the patterns were ordered.
  for pattern in "${excludes[@]}"; do
    # shellcheck disable=SC2254 # the patterns are meant to glob
    case "$deb" in $pattern) keep="" ;; esac
  done
  [ -n "$keep" ] || continue
  echo "Downloading $deb" >&2
  curl --fail -LSs -O "$URL/$deb"
  wanted+=("$deb")
done

[ ${#wanted[@]} -gt 0 ] || {
  echo "ERROR: $URL/manifest.json lists no deb matching $*" >&2
  exit 1
}

# sha256sum --ignore-missing exits 0 when it matched nothing at all, so
# an unexpected rename in the release would verify vacuously.  Check
# every file we downloaded is covered before trusting the result.
for deb in "${wanted[@]}"; do
  covered=""
  while read -r _ name; do
    # sha256sum marks binary-mode entries with a leading '*'
    [ "${name#\*}" = "$deb" ] || continue
    covered=yes
    break
  done < SHA256SUMS
  [ -n "$covered" ] || {
    echo "ERROR: $deb is not listed in $URL/SHA256SUMS" >&2
    exit 1
  }
done
sha256sum -c --ignore-missing SHA256SUMS >&2
