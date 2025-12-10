/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Supervisor management
 *
 * Copyright © 2025 Microsoft Corporation
 *
 * The supervisor functionality depends on CONFIG_AUDIT because it reuses
 * the landlock_request structure which contains common_audit_data.
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#include <linux/completion.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/rbtree.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <uapi/linux/landlock.h>

#include "access.h"
#include "audit.h"

struct landlock_ruleset;
struct path;

#ifdef CONFIG_AUDIT

/**
 * struct landlock_cache_entry - Cached supervisor decision
 *
 * This structure stores a cached decision with composite keys. All specified
 * key types must match for a cache hit. This allows fine-grained caching like
 * "PID X moving file A to B is allowed".
 */
struct landlock_cache_entry {
	struct rb_node node;
	enum landlock_rule_type rule_type;
	u32 key_types;       /* Bitmask of LANDLOCK_CACHE_KEY_* flags */
	access_mask_t access;
	int decision;        /* 0 = allow, -EACCES = deny */
	/* Composite key components - only those in key_types are valid */
	u64 inode_key;       /* LANDLOCK_CACHE_KEY_INODE */
	u64 inode2_key;      /* LANDLOCK_CACHE_KEY_INODE2 */
	u64 path_key;        /* LANDLOCK_CACHE_KEY_PATH (hash) */
	u64 path2_key;       /* LANDLOCK_CACHE_KEY_PATH2 (hash) */
	u64 pid_key;         /* LANDLOCK_CACHE_KEY_PID */
};

/**
 * struct landlock_supervisor - Supervisor state for a supervised ruleset
 *
 * This structure manages the communication channel between supervised
 * processes and the supervisor process that makes access decisions.
 */
struct landlock_supervisor {
	/**
	 * @lock: Protects @pending list, @next_id, @dead, and @cache.
	 */
	spinlock_t lock;
	/**
	 * @pending: List of pending requests waiting for supervisor decision.
	 */
	struct list_head pending;
	/**
	 * @wait: Wait queue for supervisor to wait for new requests.
	 */
	wait_queue_head_t wait;
	/**
	 * @next_id: Next request ID to assign.
	 */
	u64 next_id;
	/**
	 * @usage: Reference count.
	 */
	refcount_t usage;
	/**
	 * @dead: Set to true when the supervisor fd is closed. All pending
	 * requests will be denied when this is set.
	 */
	bool dead;
	/**
	 * @ruleset: Back-pointer to the ruleset this supervisor is for.
	 * This is a weak reference (no refcount held) since the ruleset
	 * owns the supervisor.
	 */
	struct landlock_ruleset *ruleset;
	/**
	 * @cache: RB tree of cached decisions.
	 */
	struct rb_root cache;
};

/**
 * struct landlock_pending_req - A pending access request awaiting supervisor decision
 *
 * This structure wraps a landlock_request with supervisor-specific fields
 * for tracking pending decisions and caching. All access details are stored
 * in the embedded landlock_request.audit (common_audit_data), ensuring
 * consistency between what can be audited and what can be filtered/cached.
 */
struct landlock_pending_req {
	/**
	 * @list: Entry in landlock_supervisor.pending list.
	 */
	struct list_head list;
	/**
	 * @done: Completion signaled when supervisor responds.
	 */
	struct completion done;
	/**
	 * @id: Unique request identifier.
	 */
	u64 id;
	/**
	 * @request: The landlock_request containing the access details.
	 * This reuses the audit infrastructure for common_audit_data.
	 * All path/dentry/file information is stored here.
	 */
	struct landlock_request request;
	/**
	 * @path_or_port: For network rules, this is the port number.
	 * For filesystem rules, this is unused (path is in request.audit).
	 */
	u64 path_or_port;
	/**
	 * @name1: Captured filename of the primary subject at queue time.
	 * This is needed because dentry names can change after queueing.
	 */
	char name1[256];
	/**
	 * @name2: Captured filename of the secondary subject at queue time.
	 */
	char name2[256];
	/**
	 * @task: The task that is blocked waiting for the decision.
	 */
	struct task_struct *task;
	/**
	 * @result: The decision result after completion.
	 * 0 = allow, -EACCES = deny, negative = error.
	 */
	int result;
	/**
	 * @flags: Response flags (e.g., LANDLOCK_DECISION_FLAG_CACHE).
	 */
	u32 flags;
	/**
	 * @cache_key_types: Cache key types specified by supervisor response.
	 */
	u32 cache_key_types;
};

/* Supervisor lifecycle */
struct landlock_supervisor *landlock_create_supervisor(
	struct landlock_ruleset *ruleset);
void landlock_get_supervisor(struct landlock_supervisor *supervisor);
void landlock_put_supervisor(struct landlock_supervisor *supervisor);

/* Supervisor file operations - returns fd on success */
int landlock_supervisor_get_fd(struct landlock_supervisor *supervisor);

/* Request handling - takes a landlock_request with common_audit_data */
int landlock_supervisor_request_decision(struct landlock_supervisor *supervisor,
					 const struct landlock_request *request,
					 u64 path_or_port);

#else /* CONFIG_AUDIT */

/*
 * Stub implementations when CONFIG_AUDIT is not set.
 * Supervisor functionality is not available without audit support.
 */

struct landlock_supervisor;

static inline struct landlock_supervisor *
landlock_create_supervisor(struct landlock_ruleset *ruleset)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void
landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
}

static inline void
landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
}

static inline int
landlock_supervisor_get_fd(struct landlock_supervisor *supervisor)
{
	return -EOPNOTSUPP;
}

static inline int
landlock_supervisor_request_decision(struct landlock_supervisor *supervisor,
				     const struct landlock_request *request,
				     u64 path_or_port)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_AUDIT */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
