/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Portions Copyright 2020 iXsystems, Inc.
 */

/*
 * Test a corner case : a "doall" send without children datasets.
 */

#include <libzfs.h>
#include <libzfs_core.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <err.h>

static void
usage(const char *name)
{
	fprintf(stderr, "usage: %s dataset\n", name);
	exit(EX_USAGE);
}

int
main(int argc, char const * const argv[])
{
	libzfs_handle_t *zhdl;
	zfs_handle_t *zhp;
	const char *dataset;
	int error;

	if (argc != 2)
		usage(argv[0]);

	dataset = argv[1];

	zhdl = libzfs_init();
	if (zhdl == NULL)
		errx(EX_OSERR, "libzfs_init(): %s", libzfs_error_init(errno));

	zhp = zfs_open(zhdl, dataset, ZFS_TYPE_FILESYSTEM);
	if (zhp == NULL)
		err(EX_OSERR, "zfs_open(\"%s\")", dataset);

	for (;;) {
		char value[ZFS_MAXPROPLEN];
		char source[ZFS_MAX_DATASET_NAME_LEN];
		zprop_source_t src;

		error = zfs_prop_get(zhp, ZFS_PROP_USED, value, nitems(value),
		    &src, source, nitems(source), B_FALSE);
		if (error)
			err(EX_OSERR, "zfs_prop_get(\"source\", false)");

		error = zfs_prop_get(zhp, ZFS_PROP_USED, value, nitems(value),
		    NULL, NULL, 0, B_TRUE);
		if (error)
			err(EX_OSERR, "zfs_prop_get(\"source\", true)");
	}

	zfs_close(zhp);

	libzfs_fini(zhdl);

	return (0);
}
