/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Internal syscall helpers
 */

#ifndef _SECURITY_LANDLOCK_SYSCALLS_H
#define _SECURITY_LANDLOCK_SYSCALLS_H

#include <linux/fs.h>

struct landlock_ruleset;
struct path;

extern const struct file_operations landlock_ruleset_fops;

struct landlock_ruleset *landlock_get_ruleset_from_fd(int fd, fmode_t mode);
int landlock_get_path_from_fd(s32 fd, struct path *path);

#endif /* _SECURITY_LANDLOCK_SYSCALLS_H */
