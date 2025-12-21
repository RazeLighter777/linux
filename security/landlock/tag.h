/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_LANDLOCK_TAG_H
#define _SECURITY_LANDLOCK_TAG_H

#include <linux/stddef.h>
#include <linux/types.h>
#include <uapi/linux/landlock.h>

struct dentry;
struct file;
struct pid;

/**
 * struct landlock_supervisor_tag - Tagged union for supervisor policy keys
 */
struct landlock_supervisor_tag {
	enum landlock_supervisor_tag_type type;
	union {
		struct pid *pid;
		struct dentry *exec_dentry;
	};
};

void landlock_supervisor_tag_init(struct landlock_supervisor_tag *tag);
void landlock_supervisor_tag_destroy(struct landlock_supervisor_tag *tag);

int landlock_supervisor_tag_clone(struct landlock_supervisor_tag *dst,
				 const struct landlock_supervisor_tag *src);

int landlock_supervisor_tag_set_pid(struct landlock_supervisor_tag *tag,
				   struct pid *pid);
int landlock_supervisor_tag_set_pidfd(struct landlock_supervisor_tag *tag,
				     const struct file *pidfd_file);

int landlock_supervisor_tag_set_exec_dentry(struct landlock_supervisor_tag *tag,
					  struct dentry *dentry);

bool landlock_supervisor_tag_equal(const struct landlock_supervisor_tag *a,
				  const struct landlock_supervisor_tag *b);

u32 landlock_supervisor_tag_hash(const struct landlock_supervisor_tag *tag,
				 u32 seed);

#endif /* _SECURITY_LANDLOCK_TAG_H */
