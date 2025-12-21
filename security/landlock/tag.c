// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor tag helpers
 *
 * Copyright © 2024-2025 Microsoft Corporation
 */

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/jhash.h>
#include <linux/pid.h>
#include <linux/string.h>

#include "tag.h"

void landlock_supervisor_tag_init(struct landlock_supervisor_tag *tag)
{
	tag->type = LANDLOCK_SUPERVISOR_TAG_NONE;
}

void landlock_supervisor_tag_destroy(struct landlock_supervisor_tag *tag)
{
	switch (tag->type) {
	case LANDLOCK_SUPERVISOR_TAG_NONE:
		break;
	case LANDLOCK_SUPERVISOR_TAG_PIDFD:
		put_pid(tag->pid);
		break;
	case LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY:
		dput(tag->exec_dentry);
		break;
	}
	memset(tag, 0, sizeof(*tag));
	tag->type = LANDLOCK_SUPERVISOR_TAG_NONE;
}

int landlock_supervisor_tag_clone(struct landlock_supervisor_tag *dst,
				 const struct landlock_supervisor_tag *src)
{
	if (!dst || !src)
		return -EINVAL;

	landlock_supervisor_tag_destroy(dst);

	switch (src->type) {
	case LANDLOCK_SUPERVISOR_TAG_NONE:
		landlock_supervisor_tag_init(dst);
		return 0;
	case LANDLOCK_SUPERVISOR_TAG_PIDFD:
		if (!src->pid)
			return -EINVAL;
		dst->type = LANDLOCK_SUPERVISOR_TAG_PIDFD;
		dst->pid = get_pid(src->pid);
		return 0;
	case LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY:
		if (!src->exec_dentry)
			return -EINVAL;
		dst->type = LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY;
		dst->exec_dentry = dget(src->exec_dentry);
		return 0;
	}

	return -EINVAL;
}

int landlock_supervisor_tag_set_pid(struct landlock_supervisor_tag *tag,
				   struct pid *pid)
{
	if (!pid)
		return -EINVAL;

	landlock_supervisor_tag_destroy(tag);
	tag->type = LANDLOCK_SUPERVISOR_TAG_PIDFD;
	tag->pid = get_pid(pid);
	return 0;
}

int landlock_supervisor_tag_set_pidfd(struct landlock_supervisor_tag *tag,
				     const struct file *pidfd_file)
{
	struct pid *pid;

	if (!pidfd_file)
		return -EINVAL;

	pid = pidfd_pid(pidfd_file);
	if (IS_ERR(pid))
		return PTR_ERR(pid);

	return landlock_supervisor_tag_set_pid(tag, pid);
}

int landlock_supervisor_tag_set_exec_dentry(struct landlock_supervisor_tag *tag,
					  struct dentry *dentry)
{
	if (!dentry)
		return -EINVAL;

	landlock_supervisor_tag_destroy(tag);
	tag->type = LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY;
	tag->exec_dentry = dget(dentry);
	return 0;
}

bool landlock_supervisor_tag_equal(const struct landlock_supervisor_tag *a,
				  const struct landlock_supervisor_tag *b)
{
	if (a->type != b->type)
		return false;

	switch (a->type) {
	case LANDLOCK_SUPERVISOR_TAG_NONE:
		return true;
	case LANDLOCK_SUPERVISOR_TAG_PIDFD:
		return a->pid == b->pid;
	case LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY:
		return a->exec_dentry == b->exec_dentry;
	}

	return false;
}

u32 landlock_supervisor_tag_hash(const struct landlock_supervisor_tag *tag,
				 u32 seed)
{
	u32 h = seed;

	h = jhash(&tag->type, sizeof(tag->type), h);

	switch (tag->type) {
	case LANDLOCK_SUPERVISOR_TAG_NONE:
		break;
	case LANDLOCK_SUPERVISOR_TAG_PIDFD:
		h = jhash(&tag->pid, sizeof(tag->pid), h);
		break;
	case LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY:
		h = jhash(&tag->exec_dentry, sizeof(tag->exec_dentry), h);
		break;
	}

	return h;
}
