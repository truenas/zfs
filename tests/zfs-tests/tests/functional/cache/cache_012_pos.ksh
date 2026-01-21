#!/bin/ksh -p
# SPDX-License-Identifier: CDDL-1.0
#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

#
# Copyright (c) 2020, George Amanakis. All rights reserved.
#

. $STF_SUITE/tests/functional/cache/cache.cfg
. $STF_SUITE/tests/functional/cache/cache.kshlib

#
# DESCRIPTION:
#	Looping around a cache device with l2arc_write_size exceeding
#	the device size succeeds.
#
# STRATEGY:
#	1. Create pool with a cache device.
#	2. Set l2arc_write_max to a value larger than the cache device.
#	3. Create a file larger than the cache device and random read
#		for 10 sec.
#	4. Set l2arc_write_max to a value less than the cache device size but
#		larger than the default (256MB).
#	5. Record the l2_size.
#	6. Random read for 1 sec.
#	7. Record the l2_size again.
#	8. If (5) <= (7) then we have not looped around yet.
#	9. Destroy pool.
#

verify_runnable "global"

command -v fio > /dev/null || log_unsupported "fio missing"

log_assert "Looping around a cache device succeeds."

function cleanup
{
	if poolexists $TESTPOOL ; then
		destroy_pool $TESTPOOL
	fi

	log_must set_tunable32 L2ARC_WRITE_MAX $write_max
	log_must set_tunable32 L2ARC_NOPREFETCH $noprefetch
	log_must set_tunable32 L2ARC_DWPD_LIMIT $dwpd_limit
}
log_onexit cleanup

typeset write_max=$(get_tunable L2ARC_WRITE_MAX)
typeset noprefetch=$(get_tunable L2ARC_NOPREFETCH)
typeset dwpd_limit=$(get_tunable L2ARC_DWPD_LIMIT)
log_must set_tunable32 L2ARC_NOPREFETCH 0
log_must set_tunable32 L2ARC_DWPD_LIMIT 0

typeset VDEV="$VDIR/vdev.disk"
typeset VDEV_SZ=$(( 4 * 1024 * 1024 * 1024 ))
typeset VCACHE="$VDIR/vdev.cache"
typeset VCACHE_SZ=$(( $VDEV_SZ / 2 ))

typeset fill_mb=$(( floor($VDEV_SZ * 3 / 4 ) ))
export DIRECTORY=/$TESTPOOL
export NUMJOBS=4
export RUNTIME=10
export PERF_RANDSEED=1234
export PERF_COMPPERCENT=66
export PERF_COMPCHUNK=0
export BLOCKSIZE=128K
export SYNC_TYPE=0
export DIRECT=0
export FILE_SIZE=$(( floor($fill_mb / $NUMJOBS) ))

log_must set_tunable32 L2ARC_WRITE_MAX $(( $VCACHE_SZ * 2 ))

log_must truncate -s $VCACHE_SZ $VCACHE
log_must truncate -s $VDEV_SZ $VDEV

log_must zpool create -f $TESTPOOL $VDEV cache $VCACHE

# Actually, this test relies on atime writes to force the L2 ARC discards
log_must zfs set relatime=off $TESTPOOL

log_note "=== Initial state ==="
log_note "VCACHE_SZ=$VCACHE_SZ ($(($VCACHE_SZ/1024/1024))MB)"
typeset arc_c_max=$(kstat arcstats.c_max)
typeset persist_thresh=$(($arc_c_max / 2))
log_note "arc_c_max=$arc_c_max ($(($arc_c_max/1024/1024))MB)"
log_note "L2ARC_PERSIST_THRESHOLD=$persist_thresh ($(($persist_thresh/1024/1024))MB)"
if [[ $VCACHE_SZ -lt $persist_thresh ]]; then
	log_note "MODE: small device (VCACHE_SZ < threshold) -> DWPD-based"
else
	log_note "MODE: persistent device (VCACHE_SZ >= threshold)"
fi
log_note "l2_size=$(kstat arcstats.l2_size) l2_asize=$(kstat arcstats.l2_asize)"

log_must fio $FIO_SCRIPTS/mkfiles.fio
log_must fio $FIO_SCRIPTS/random_reads.fio

log_note "=== After 10s fill ==="
log_note "l2_size=$(kstat arcstats.l2_size) l2_asize=$(kstat arcstats.l2_asize)"
log_note "l2_writes=$(kstat arcstats.l2_writes) l2_feeds=$(kstat arcstats.l2_feeds)"
log_note "l2_evict_l2_eligible=$(kstat arcstats.l2_evict_l2_eligible)"

log_must set_tunable32 L2ARC_WRITE_MAX $(( 256 * 1024 * 1024 ))
export RUNTIME=1

typeset -i iteration=0
typeset -i max_iterations=120
typeset -i writes_total_start=$(kstat arcstats.l2_writes)
typeset -i feeds_start=$(kstat arcstats.l2_feeds)
typeset do_once=true
while $do_once || [[ $l2_size1 -le $l2_size2 ]]; do
	iteration=$((iteration + 1))
	if [[ $iteration -gt $max_iterations ]]; then
		log_note "=== FAILED: Final state ==="
		log_note "l2_size=$(kstat arcstats.l2_size) l2_asize=$(kstat arcstats.l2_asize)"
		log_note "l2_writes=$(kstat arcstats.l2_writes) (delta=$(($(kstat arcstats.l2_writes)-writes_total_start)))"
		log_note "l2_feeds=$(kstat arcstats.l2_feeds) (delta=$(($(kstat arcstats.l2_feeds)-feeds_start)))"
		log_note "l2_write_bytes=$(kstat arcstats.l2_write_bytes)"
		log_note "l2_evict_l2_eligible=$(kstat arcstats.l2_evict_l2_eligible)"
		log_fail "Loop-around not detected after $max_iterations iterations"
	fi
	typeset l2_size1=$(kstat arcstats.l2_size)
	typeset l2_writes1=$(kstat arcstats.l2_writes)
	typeset l2_feeds1=$(kstat arcstats.l2_feeds)
	log_must fio $FIO_SCRIPTS/random_reads.fio
	typeset l2_size2=$(kstat arcstats.l2_size)
	typeset l2_writes2=$(kstat arcstats.l2_writes)
	typeset l2_feeds2=$(kstat arcstats.l2_feeds)
	log_note "iter=$iteration l2_size:$l2_size1->$l2_size2 diff=$((l2_size1-l2_size2)) writes=$((l2_writes2-l2_writes1)) feeds=$((l2_feeds2-l2_feeds1))"
	do_once=false
done

log_note "=== Loop-around detected at iteration $iteration ==="
log_note "l2_writes=$(kstat arcstats.l2_writes) (delta=$(($(kstat arcstats.l2_writes)-writes_total_start)))"
log_note "l2_feeds=$(kstat arcstats.l2_feeds) (delta=$(($(kstat arcstats.l2_feeds)-feeds_start)))"
log_must zpool destroy $TESTPOOL

log_pass "Looping around a cache device succeeds."
