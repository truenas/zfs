/*
 * Copyright (c) 2008, 2009 Edward Tomasz Napierała <trasz@FreeBSD.org>
 * Copyright (c) 2022 Andrew Walker <awalker@ixsystems.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef SUNACL_H
#define	SUNACL_H

#include <sys/types.h> /* uid_t */

/*
 * ACL_MAX_ENTRIES from <sys/acl.h>
 */

typedef struct acl_entry	aclent_t;

typedef struct ace {
	uid_t		a_who;		/* uid or gid */
	uint32_t	a_access_mask;	/* read,write,... */
	uint16_t	a_flags;	/* see below */
	uint16_t	a_type;		/* allow or deny */
} ace_t;

/*
 * The following are defined for ace_t.
 */
#define	ACE_READ_DATA		0x00000001
#define	ACE_LIST_DIRECTORY	0x00000001
#define	ACE_WRITE_DATA		0x00000002
#define	ACE_ADD_FILE		0x00000002
#define	ACE_APPEND_DATA		0x00000004
#define	ACE_ADD_SUBDIRECTORY	0x00000004
#define	ACE_READ_NAMED_ATTRS	0x00000008
#define	ACE_WRITE_NAMED_ATTRS	0x00000010
#define	ACE_EXECUTE		0x00000020
#define	ACE_DELETE_CHILD	0x00000040
#define	ACE_READ_ATTRIBUTES	0x00000080
#define	ACE_WRITE_ATTRIBUTES	0x00000100
#define	ACE_DELETE		0x00010000
#define	ACE_READ_ACL		0x00020000
#define	ACE_WRITE_ACL		0x00040000
#define	ACE_WRITE_OWNER		0x00080000
#define	ACE_SYNCHRONIZE		0x00100000

#define	ACE_FILE_INHERIT_ACE		0x0001
#define	ACE_DIRECTORY_INHERIT_ACE	0x0002
#define	ACE_NO_PROPAGATE_INHERIT_ACE	0x0004
#define	ACE_INHERIT_ONLY_ACE		0x0008
#define	ACE_SUCCESSFUL_ACCESS_ACE_FLAG	0x0010
#define	ACE_FAILED_ACCESS_ACE_FLAG	0x0020
#define	ACE_IDENTIFIER_GROUP		0x0040
#define	ACE_INHERITED_ACE		0x0080
#define	ACE_OWNER			0x1000
#define	ACE_GROUP			0x2000
#define	ACE_EVERYONE			0x4000

#define	ACE_ACCESS_ALLOWED_ACE_TYPE	0x0000
#define	ACE_ACCESS_DENIED_ACE_TYPE	0x0001
#define	ACE_SYSTEM_AUDIT_ACE_TYPE	0x0002
#define	ACE_SYSTEM_ALARM_ACE_TYPE	0x0003

#define	ACE_ALL_PERMS	(ACE_READ_DATA|ACE_LIST_DIRECTORY|ACE_WRITE_DATA| \
    ACE_ADD_FILE|ACE_APPEND_DATA|ACE_ADD_SUBDIRECTORY|ACE_READ_NAMED_ATTRS| \
    ACE_WRITE_NAMED_ATTRS|ACE_EXECUTE|ACE_DELETE_CHILD|ACE_READ_ATTRIBUTES| \
    ACE_WRITE_ATTRIBUTES|ACE_DELETE|ACE_READ_ACL|ACE_WRITE_ACL| \
    ACE_WRITE_OWNER|ACE_SYNCHRONIZE)

/*
 * The following flags are supported by both NFSv4 ACLs and ace_t.
 */
#define	ACE_NFSV4_SUP_FLAGS (ACE_FILE_INHERIT_ACE | \
    ACE_DIRECTORY_INHERIT_ACE | \
    ACE_NO_PROPAGATE_INHERIT_ACE | \
    ACE_INHERIT_ONLY_ACE | \
    ACE_IDENTIFIER_GROUP | \
    ACE_INHERITED_ACE)

#define	ACE_TYPE_FLAGS	(ACE_OWNER|ACE_GROUP|ACE_EVERYONE|ACE_IDENTIFIER_GROUP)

/* cmd's to manipulate ace acls. */
#define	ACE_GETACL		4
#define	ACE_SETACL		5
#define	ACE_GETACLCNT		6

int acl(const char *path, int cmd, int cnt, void *buf);
int facl(int fd, int cmd, int cnt, void *buf);

#endif /* SUNACL_H */
