#!/usr/bin/env bash

######################################################################
# 3b) boot the build VM into the TrueNAS production kernel
#
# qemu-tn-kernel.sh TRAIN
#
# TRAIN: name of a trains[] entry in .github/trains.json, whose
#        kernel_repo and kernel_tag name the rolling kernel release to
#        install (e.g. 'master' or '26').
#
# The train is resolved here rather than passed in as a repo/tag pair
# so that .github/trains.json stays the only place a pairing is
# written down, and so this interface keeps working for pull requests
# whose head still carries an older copy of these scripts.
#
# The dependency step powered the VM off.  Bring it back up, replace
# the distribution kernel with the TrueNAS production kernel and power
# it off again, so the build and test steps that follow run under the
# TrueNAS kernel.
######################################################################

set -eu

TRAIN="$1"

rc=0
entry=$(.github/workflows/scripts/resolve-train.sh train "$TRAIN") || rc=$?
if [ "$rc" -eq 3 ]; then
  echo "ERROR: no .github/trains.json entry for train '$TRAIN'"
  exit 1
elif [ "$rc" -ne 0 ]; then
  exit "$rc"
fi
KERNEL_REPO=$(jq -r '.kernel_repo' <<< "$entry")
KERNEL_TAG=$(jq -r '.kernel_tag' <<< "$entry")

sudo virsh start openzfs
.github/workflows/scripts/qemu-wait-for-vm.sh vm0

scp .github/workflows/scripts/qemu-tn-kernel-vm.sh \
    .github/workflows/scripts/fetch-tn-kernel.sh zfs@vm0:
PID=$(pidof /usr/bin/qemu-system-x86_64)
ssh zfs@vm0 '$HOME/qemu-tn-kernel-vm.sh' "$KERNEL_REPO" "$KERNEL_TAG"

# wait for poweroff to succeed
tail --pid=$PID -f /dev/null
sleep 5 # avoid this: "error: Domain is already active"
rm -f $HOME/.ssh/known_hosts
