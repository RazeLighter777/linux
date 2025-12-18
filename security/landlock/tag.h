/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Supervisor tags
 */

#ifndef _SECURITY_LANDLOCK_TAG_H
#define _SECURITY_LANDLOCK_TAG_H

#include <linux/atomic.h>
#include <linux/refcount.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <linux/rcupdate.h>

#include "access.h"

struct landlock_request;
struct landlock_ruleset;

struct file;
struct dentry;

#ifdef CONFIG_AUDIT

struct landlock_tag;

struct landlock_tag_node {
	struct landlock_tag *tag;
	struct landlock_tag_node *next;
};

enum landlock_tag_type {
	LANDLOCK_TAG_PIDFD = 1,
	LANDLOCK_TAG_EXEC_DENTRY,
	LANDLOCK_TAG_COMPOSE_OR,
	LANDLOCK_TAG_COMPOSE_AND,
	LANDLOCK_TAG_EMPTY,
};

struct landlock_tag {
	refcount_t usage;
	enum landlock_tag_type type;
	/*
	 * Cached supervisor decision for this tag.
	 *
	 * Only applies if counter == 0.
	 *
	 * This must be a *subrules-only* ruleset of the Landlock rule this tag is
	 * a part of, i.e. it may only contain subrules that are equal to or more
	 * specific than that base rule.
	 *
	 * Example (tag attached to rule "/a/b" with access=rw):
	 * - allow: "/a/b/c" with access=rw
	 * - allow: "{} (empty ruleset)" effectively denies all access under "/a/b"
	 * - deny:  "/unrelated" with any access
	 * - deny:  "/a/b/c" with access=rwx (less restrictive / broader access)
	 */
	struct landlock_ruleset __rcu *ruleset;
	/* 
	 * Number of times to default to decision in allow. If zero, query
	 * supervisor. If -1, always query the supervisor.
	 */
	atomic64_t counter;
	union {
		struct {
			struct file *pidfd_file;
		} pidfd;
		struct dentry *exec_dentry;
		struct {
			struct landlock_tag *left;
			struct landlock_tag *right;
		} compose_or;
		struct {
			struct landlock_tag *left;
			struct landlock_tag *right;
		} compose_and;
	} u;
};

/*
 * Maximum recursion depth for composed tags (OR/AND trees).
 * This is a safety limit against malformed inputs and cycles.
 */
#define LANDLOCK_TAG_MATCH_MAX_DEPTH 16

static inline void landlock_get_tag(struct landlock_tag *const tag)
{
	if (tag)
		refcount_inc(&tag->usage);
}

void landlock_put_tag(struct landlock_tag *tag);

bool landlock_tag_matches_request(const struct landlock_tag *tag,
				 const struct landlock_request *request);

#endif /* CONFIG_AUDIT */

#endif /* _SECURITY_LANDLOCK_TAG_H */
