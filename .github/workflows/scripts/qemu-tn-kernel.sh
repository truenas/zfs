#!/usr/bin/env bash

######################################################################
# 3b) boot the build VM into the TrueNAS production kernel
#
# qemu-tn-kernel.sh TRAIN
#
# TRAIN: TrueNAS train name ('master' or '26') whose rolling kernel
#        release (<TRAIN>-nightly) published by truenas/linux should
#        be installed.
#
# The dependency step powered the VM off.  Bring it back up, replace
# the distribution kernel with the TrueNAS production kernel and power
# it off again, so the build and test steps that follow run under the
# TrueNAS kernel.
######################################################################

set -eu

TRAIN="$1"

sudo virsh start openzfs
.github/workflows/scripts/qemu-wait-for-vm.sh vm0

scp .github/workflows/scripts/qemu-tn-kernel-vm.sh zfs@vm0:qemu-tn-kernel-vm.sh
PID=$(pidof /usr/bin/qemu-system-x86_64)
ssh zfs@vm0 "./qemu-tn-kernel-vm.sh $TRAIN"

# wait for poweroff to succeed
tail --pid=$PID -f /dev/null
sleep 5 # avoid this: "error: Domain is already active"
rm -f $HOME/.ssh/known_hosts
