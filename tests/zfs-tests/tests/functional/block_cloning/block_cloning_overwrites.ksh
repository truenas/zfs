#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or https://opensource.org/licenses/CDDL-1.0.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright (c) 2024 by Triad National Security, LLC.
#

#
# DESCRIPTION:
#	Verify that overwriting a file that is being block cloned works
#
# STRATEGY:
#	1. Create a file in a dataset
#	2. Continously block clone the file to a second file in a different
#	   dataset and sync the zpool after cloning
#	3. Continously overwrite the second file
#  

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/block_cloning/block_cloning.kshlib

verify_runnable "global"

if is_linux && [[ $(linux_version) -lt $(linux_version "4.5") ]]; then
  log_unsupported "copy_file_range not available before Linux 4.5"
fi

claim="Overwriting a block cloned file does not cause issues."

log_assert $claim

function cleanup
{
	datasetexists $TESTPOOL && destroy_pool $TESTPOOL
}

log_onexit cleanup

log_must zpool create -o feature@block_cloning=enabled $TESTPOOL $DISKS
log_must zfs create -o sync=always -o recordsize=4K $TESTPOOL/$TESTFS1
log_must zfs create -o sync=always -o recordsize=4K $TESTPOOL/$TESTFS2

log_must dd if=/dev/urandom of=/$TESTPOOL/$TESTFS1/file1 bs=1M count=1k
log_must sync_pool $TESTPOOL
runtime=$(($(date +%s) + 180)) # 3 mins

while [[ $(date +%s) -lt $runtime ]]; do
	log_must clonefile -f /$TESTPOOL/$TESTFS1/file1 \
	    /$TESTPOOL/$TESTFS2/file2 0 0 1073741824
	log_must sync_pool $TESTPOOL
done &
while [[ $(date +%s) -lt $runtime ]]; do
	log_must dd if=/dev/urandom of=/$TESTPOOL/$TESTFS2/file2 bs=1M count=1k
done &
wait

log_pass $claim
