#!/usr/bin/env bash

######################################################################
# 3b) install the TrueNAS production kernel.  This is run on the VM.
#
# qemu-tn-kernel-vm.sh KERNEL_REPO KERNEL_TAG
#
# KERNEL_REPO: GitHub repository publishing the rolling kernel
#              releases (e.g. truenas/linux)
# KERNEL_TAG:  release tag to install the kernel from (e.g.
#              master-nightly)
#
# Downloads the kernel debs published as the rolling KERNEL_TAG GitHub
# release of KERNEL_REPO, verifies them against SHA256SUMS, installs
# them, and removes the distribution kernels so the next boot can only
# use the TrueNAS kernel.  Powers the VM off when done.
######################################################################

set -eu

KERNEL_REPO="$1"
KERNEL_TAG="$2"

export DEBIAN_FRONTEND="noninteractive"

echo "##[group]Download TrueNAS kernel ($KERNEL_REPO $KERNEL_TAG)"
# Only the image and headers are needed; skip the libc-dev, perf and
# any debug packages.
"$(dirname "$0")/fetch-tn-kernel.py" "$KERNEL_REPO" "$KERNEL_TAG" \
  /tmp/tn-kernel 'linux-image-*' 'linux-headers-*' '!linux-image-*-dbg_*'
cd /tmp/tn-kernel
RELEASE=$(jq -r '.release' manifest.json)
echo "Kernel release: $RELEASE" \
  "($(jq -r '.branch' manifest.json) @ $(jq -r '.commit' manifest.json))"
echo "##[endgroup]"

echo "##[group]Install TrueNAS kernel"
sudo -E apt-get install -y ./linux-image-*.deb ./linux-headers-*.deb
echo "##[endgroup]"

echo "##[group]Remove distribution kernels"
# Let apt remove the running kernel without aborting.
echo 'linux-base linux-base/removing-running-kernel boolean false' | \
  sudo debconf-set-selections
# The TrueNAS kernel packages carry version-free names
# (linux-{image,headers}-truenas-production-amd64), so tell them apart
# from the distribution kernels by name.
STOCK=$(dpkg-query -W -f '${Package}\n' 'linux-image-*' 'linux-headers-*' | \
  grep -v -- truenas || true)
if [ -n "$STOCK" ]; then
  sudo -E apt-get purge -y $STOCK
fi
sudo update-grub
echo "##[endgroup]"

# The TrueNAS kernel must now be the one and only installed kernel,
# and the module build must resolve to its development headers.
test -e "/boot/vmlinuz-$RELEASE"
test "$(ls /boot/vmlinuz-* | wc -l)" -eq 1
test -f "$(readlink -f "/lib/modules/$RELEASE/build")/Module.symvers"
cd /
rm -rf /tmp/tn-kernel

# reset cloud-init configuration and poweroff
sudo cloud-init clean --logs
sleep 2 && sudo poweroff &
exit 0
