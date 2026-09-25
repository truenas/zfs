#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0
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

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Verify that polling pool stats does not make a pool export fail.
#	The pool config is built without the namespace lock, while the
#	stats request holds a reference on the pool.
#
# STRATEGY:
#	1. Create a pool
#	2. Run zpool iostat and zpool status in a loop in the background
#	3. Export and import the pool several times
#	4. Verify that every export succeeds
#

verify_runnable "global"

DEVICE_DIR=$TEST_BASE_DIR/dev_export-stats-test
typeset poll_pid=""

function cleanup
{
	[[ -n $poll_pid ]] && proc_exists $poll_pid && kill $poll_pid
	poolexists $TESTPOOL1 && destroy_pool $TESTPOOL1
	[[ -d $DEVICE_DIR ]] && log_must rm -rf $DEVICE_DIR
}

log_assert "zpool export succeeds while pool stats are being polled"

log_onexit cleanup

log_must mkdir -p $DEVICE_DIR
log_must truncate -s $MINVDEVSIZE ${DEVICE_DIR}/disk0 ${DEVICE_DIR}/disk1
log_must zpool create -f $TESTPOOL1 mirror ${DEVICE_DIR}/disk0 \
    ${DEVICE_DIR}/disk1

while true; do
	zpool iostat -v $TESTPOOL1 >/dev/null 2>&1
	zpool status $TESTPOOL1 >/dev/null 2>&1
done &
poll_pid=$!

for i in {1..20}; do
	log_must zpool export $TESTPOOL1
	log_must zpool import -d $DEVICE_DIR $TESTPOOL1
done

log_pass "zpool export succeeds while pool stats are being polled"
