// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Supervisor implementation
 *
 * Copyright © 2025 Microsoft Corporation
 *
 * This file is only compiled when CONFIG_AUDIT is enabled, as the supervisor
 * functionality depends on landlock_request which uses common_audit_data.
 */

#include <linux/audit.h>

#ifdef CONFIG_AUDIT

#include <linux/anon_inodes.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/fcntl.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/linux/landlock.h>

#include "audit.h"
#include "cred.h"
#include "ruleset.h"
#include "supervisor.h"

/**
 * request_type_to_rule_type - Convert landlock_request_type to landlock_rule_type
 * @type: The request type from landlock_request
 *
 * Returns the corresponding rule type for UAPI, or 0 for unsupported types.
 */
static enum landlock_rule_type
request_type_to_rule_type(enum landlock_request_type type)
{
	switch (type) {
	case LANDLOCK_REQUEST_FS_ACCESS:
	case LANDLOCK_REQUEST_FS_CHANGE_TOPOLOGY:
		return LANDLOCK_RULE_PATH_BENEATH;
	case LANDLOCK_REQUEST_NET_ACCESS:
		return LANDLOCK_RULE_NET_PORT;
	default:
		/* PTRACE and SCOPE requests are not supervised */
		return 0;
	}
}

/**
 * landlock_create_supervisor - Create a new supervisor for a ruleset
 * @ruleset: The ruleset this supervisor is associated with
 *
 * Returns a new supervisor on success, or an ERR_PTR on failure.
 */
struct landlock_supervisor *landlock_create_supervisor(
	struct landlock_ruleset *ruleset)
{
	struct landlock_supervisor *supervisor;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL);
	if (!supervisor)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&supervisor->lock);
	INIT_LIST_HEAD(&supervisor->pending);
	init_waitqueue_head(&supervisor->wait);
	supervisor->next_id = 1;
	refcount_set(&supervisor->usage, 1);
	supervisor->dead = false;
	supervisor->ruleset = ruleset;
	supervisor->cache = RB_ROOT;

	return supervisor;
}

/**
 * landlock_get_supervisor - Increment supervisor reference count
 * @supervisor: The supervisor to reference
 */
void landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor)
		refcount_inc(&supervisor->usage);
}

/* Free all cache entries */
static void supervisor_free_cache(struct landlock_supervisor *supervisor)
{
	struct rb_node *node;

	while ((node = rb_first(&supervisor->cache)) != NULL) {
		struct landlock_cache_entry *entry =
			rb_entry(node, struct landlock_cache_entry, node);
		rb_erase(node, &supervisor->cache);
		kfree(entry);
	}
}

/**
 * landlock_put_supervisor - Decrement supervisor reference count and free if zero
 * @supervisor: The supervisor to release
 */
void landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor && refcount_dec_and_test(&supervisor->usage)) {
		supervisor_free_cache(supervisor);
		kfree(supervisor);
	}
}

/**
 * struct landlock_cache_keys - Composite cache key components
 *
 * Used to pass all potential key values to cache lookup/insert functions.
 * Only the components specified in key_types are used for comparison.
 */
struct landlock_cache_keys {
	u32 key_types;
	u64 inode_key;
	u64 inode2_key;
	u64 path_key;
	u64 path2_key;
	u64 pid_key;
};

/**
 * cache_entry_compare_for_tree - Compare entries for RB-tree ordering
 *
 * This provides a consistent ordering for the RB-tree structure.
 * We order by: rule_type, key_types, access, then all key components.
 */
static int cache_entry_compare_for_tree(const struct landlock_cache_entry *a,
					const struct landlock_cache_entry *b)
{
	if (a->rule_type != b->rule_type)
		return a->rule_type < b->rule_type ? -1 : 1;
	if (a->key_types != b->key_types)
		return a->key_types < b->key_types ? -1 : 1;
	if (a->access != b->access)
		return a->access < b->access ? -1 : 1;
	if (a->inode_key != b->inode_key)
		return a->inode_key < b->inode_key ? -1 : 1;
	if (a->inode2_key != b->inode2_key)
		return a->inode2_key < b->inode2_key ? -1 : 1;
	if (a->path_key != b->path_key)
		return a->path_key < b->path_key ? -1 : 1;
	if (a->path2_key != b->path2_key)
		return a->path2_key < b->path2_key ? -1 : 1;
	if (a->pid_key != b->pid_key)
		return a->pid_key < b->pid_key ? -1 : 1;
	return 0;
}

/**
 * cache_entry_matches_request - Check if a cache entry matches a request
 * @entry: The cached entry with its key_types filter
 * @rule_type: The rule type to match
 * @access: The access mask to match
 * @keys: All available key values from the current request
 *
 * Returns true if the entry matches the request. An entry matches if:
 * - rule_type and access match exactly
 * - For EVERY key type the entry specifies, the corresponding value matches
 *
 * Key types NOT specified in the entry are ignored (wildcard behavior).
 */
static bool cache_entry_matches_request(const struct landlock_cache_entry *entry,
					enum landlock_rule_type rule_type,
					access_mask_t access,
					const struct landlock_cache_keys *keys)
{
	if (entry->rule_type != rule_type)
		return false;
	if (entry->access != access)
		return false;

	/* Check each key component that the entry requires */
	if ((entry->key_types & LANDLOCK_CACHE_KEY_INODE) &&
	    entry->inode_key != keys->inode_key)
		return false;
	if ((entry->key_types & LANDLOCK_CACHE_KEY_INODE2) &&
	    entry->inode2_key != keys->inode2_key)
		return false;
	if ((entry->key_types & LANDLOCK_CACHE_KEY_PATH) &&
	    entry->path_key != keys->path_key)
		return false;
	if ((entry->key_types & LANDLOCK_CACHE_KEY_PATH2) &&
	    entry->path2_key != keys->path2_key)
		return false;
	if ((entry->key_types & LANDLOCK_CACHE_KEY_PID) &&
	    entry->pid_key != keys->pid_key)
		return false;

	return true;  /* All required keys match */
}

/*
 * Cache lookup - must be called with supervisor->lock held
 *
 * Since entries with different key_types can potentially match a request
 * (depending on which keys they filter on), we iterate through all entries
 * to find any match. This is O(n) but the cache is expected to be small.
 */
static struct landlock_cache_entry *
cache_lookup(struct landlock_supervisor *supervisor,
	     enum landlock_rule_type rule_type,
	     access_mask_t access,
	     const struct landlock_cache_keys *keys)
{
	struct rb_node *node;

	for (node = rb_first(&supervisor->cache); node; node = rb_next(node)) {
		struct landlock_cache_entry *entry =
			rb_entry(node, struct landlock_cache_entry, node);

		if (cache_entry_matches_request(entry, rule_type, access, keys))
			return entry;
	}
	return NULL;
}

/*
 * Cache insert - must be called with supervisor->lock held
 *
 * Inserts a new cache entry or updates an existing one with the same
 * exact key combination.
 */
static int cache_insert(struct landlock_supervisor *supervisor,
			enum landlock_rule_type rule_type,
			access_mask_t access,
			int decision,
			const struct landlock_cache_keys *keys)
{
	struct rb_node **new = &supervisor->cache.rb_node;
	struct rb_node *parent = NULL;
	struct landlock_cache_entry *entry;
	struct landlock_cache_entry search_entry = {
		.rule_type = rule_type,
		.key_types = keys->key_types,
		.access = access,
		.inode_key = keys->inode_key,
		.inode2_key = keys->inode2_key,
		.path_key = keys->path_key,
		.path2_key = keys->path2_key,
		.pid_key = keys->pid_key,
	};

	while (*new) {
		struct landlock_cache_entry *this =
			rb_entry(*new, struct landlock_cache_entry, node);
		int cmp = cache_entry_compare_for_tree(&search_entry, this);

		parent = *new;

		if (cmp < 0)
			new = &(*new)->rb_left;
		else if (cmp > 0)
			new = &(*new)->rb_right;
		else {
			/* Already exists, update decision */
			this->decision = decision;
			return 0;
		}
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->rule_type = rule_type;
	entry->key_types = keys->key_types;
	entry->access = access;
	entry->decision = decision;
	entry->inode_key = keys->inode_key;
	entry->inode2_key = keys->inode2_key;
	entry->path_key = keys->path_key;
	entry->path2_key = keys->path2_key;
	entry->pid_key = keys->pid_key;

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, &supervisor->cache);
	return 0;
}

/**
 * supervisor_kill_pending - Deny all pending requests
 * @supervisor: The supervisor whose requests to kill
 *
 * Called when the supervisor fd is closed. All pending requests will be
 * denied with -EACCES.
 */
static void supervisor_kill_pending(struct landlock_supervisor *supervisor)
{
	struct landlock_pending_req *req, *tmp;

	spin_lock(&supervisor->lock);
	supervisor->dead = true;
	list_for_each_entry_safe(req, tmp, &supervisor->pending, list) {
		req->result = -EACCES;
		complete(&req->done);
	}
	spin_unlock(&supervisor->lock);
}

/* File operations for the supervisor fd */

/**
 * is_supervisor_allowed - Check if current task can access supervisor fd
 * @supervisor: The supervisor being accessed
 *
 * Returns true if access is allowed, false if denied.
 *
 * Security check: A sandboxed process whose domain includes this supervisor
 * must NOT be able to read/write to the supervisor fd. This prevents the
 * supervised process from approving its own access requests.
 */
static bool is_supervisor_allowed(struct landlock_supervisor *supervisor)
{
	const struct landlock_cred_security *subject;
	size_t i;

	/* Non-sandboxed processes can access the fd */
	subject = landlock_cred(current_cred());
	if (!subject || !subject->domain)
		return true;

	/*
	 * Check if this supervisor is in the current task's domain chain.
	 * If so, deny access - we can't let the supervised process
	 * approve its own requests!
	 */
	if (subject->domain->supervisors) {
		for (i = 0; i < subject->domain->num_supervisors; i++) {
			if (subject->domain->supervisors[i] == supervisor)
				return false;
		}
	}

	return true;
}

static int supervisor_release(struct inode *inode, struct file *file)
{
	struct landlock_supervisor *supervisor = file->private_data;

	supervisor_kill_pending(supervisor);
	landlock_put_supervisor(supervisor);
	return 0;
}

static ssize_t supervisor_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	struct landlock_supervisor *supervisor = file->private_data;
	struct landlock_supervisor_request user_req;
	struct landlock_pending_req *req;
	enum landlock_rule_type rule_type;
	int ret;

	/* Security: supervised processes cannot read their own requests */
	if (!is_supervisor_allowed(supervisor))
		return -EPERM;

	if (count < sizeof(user_req))
		return -EINVAL;

	/* Wait for a pending request */
	ret = wait_event_interruptible(supervisor->wait,
		supervisor->dead || !list_empty(&supervisor->pending));
	if (ret)
		return ret;

	spin_lock(&supervisor->lock);
	if (supervisor->dead) {
		spin_unlock(&supervisor->lock);
		return -ENODEV;
	}

	if (list_empty(&supervisor->pending)) {
		spin_unlock(&supervisor->lock);
		return -EAGAIN;
	}

	/* Get the first pending request (don't remove it yet) */
	req = list_first_entry(&supervisor->pending, struct landlock_pending_req,
			       list);
	spin_unlock(&supervisor->lock);

	/* Convert request type to rule type for UAPI */
	rule_type = request_type_to_rule_type(req->request.type);

	/* Build the user-space request structure */
	memset(&user_req, 0, sizeof(user_req));
	user_req.id = req->id;
	user_req.pid = task_pid_nr(req->task);
	user_req.tgid = task_tgid_nr(req->task);
	user_req.rule_type = rule_type;
	user_req.flags = 0;
	user_req.access_request = req->request.access;
	user_req.port = req->path_or_port;  /* Only used for network rules */
	user_req.reserved = 0;

	if (copy_to_user(buf, &user_req, sizeof(user_req)))
		return -EFAULT;

	/*
	 * For filesystem requests, the supervisor should use the
	 * LANDLOCK_IOCTL_SUPERVISOR_RECV_FD ioctl to retrieve an O_PATH
	 * file descriptor for the path involved in the request.
	 */

	return sizeof(user_req);
}

static ssize_t supervisor_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct landlock_supervisor *supervisor = file->private_data;
	struct landlock_supervisor_response user_resp;
	struct landlock_pending_req *req, *found = NULL;

	/* Security: supervised processes cannot respond to requests */
	if (!is_supervisor_allowed(supervisor))
		return -EPERM;

	if (count < sizeof(user_resp))
		return -EINVAL;

	if (copy_from_user(&user_resp, buf, sizeof(user_resp)))
		return -EFAULT;

	/* Validate decision */
	if (user_resp.decision != LANDLOCK_DECISION_DENY &&
	    user_resp.decision != LANDLOCK_DECISION_ALLOW)
		return -EINVAL;

	/* Find the request by ID */
	spin_lock(&supervisor->lock);
	list_for_each_entry(req, &supervisor->pending, list) {
		if (req->id == user_resp.id) {
			found = req;
			list_del(&req->list);
			break;
		}
	}
	spin_unlock(&supervisor->lock);

	if (!found)
		return -ENOENT;

	/* Set the result and wake up the blocked task */
	if (user_resp.decision == LANDLOCK_DECISION_ALLOW)
		found->result = 0;  /* 0 means allow in LSM hooks */
	else
		found->result = -EACCES;

	found->flags = user_resp.flags;
	found->cache_key_types = user_resp.cache_key_types;
	complete(&found->done);

	return sizeof(user_resp);
}

static __poll_t supervisor_poll(struct file *file, poll_table *wait)
{
	struct landlock_supervisor *supervisor = file->private_data;
	__poll_t mask = 0;

	/* Security: supervised processes cannot poll */
	if (!is_supervisor_allowed(supervisor))
		return EPOLLERR;

	poll_wait(file, &supervisor->wait, wait);

	spin_lock(&supervisor->lock);
	if (supervisor->dead)
		mask |= EPOLLERR | EPOLLHUP;
	if (!list_empty(&supervisor->pending))
		mask |= EPOLLIN | EPOLLRDNORM;
	/* Always writable for responses */
	mask |= EPOLLOUT | EPOLLWRNORM;
	spin_unlock(&supervisor->lock);

	return mask;
}

/**
 * get_path_fd - Create an O_PATH file descriptor for a dentry
 * @parent: The parent path  
 * @dentry: The dentry to create an fd for (may or may not exist)
 *
 * Returns a file descriptor on success, or a negative error code.
 * Returns -1 if the dentry doesn't have an inode (doesn't exist).
 */
static int get_path_fd(struct path *parent, struct dentry *dentry)
{
	struct file *file;
	struct path target_path;
	int fd;

	if (!parent || !dentry)
		return -1;

	/* Check if dentry has an inode (i.e., exists) */
	if (!dentry->d_inode)
		return -1;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;

	/* Build the path for the specific dentry */
	target_path.mnt = parent->mnt;
	target_path.dentry = dentry;

	file = dentry_open(&target_path, O_PATH | O_CLOEXEC, current_cred());
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		return PTR_ERR(file);
	}

	fd_install(fd, file);
	return fd;
}

static long supervisor_ioctl_recv_fd(struct landlock_supervisor *supervisor,
				     unsigned long arg)
{
	struct landlock_supervisor_recv_fd __user *user_arg =
		(struct landlock_supervisor_recv_fd __user *)arg;
	struct landlock_supervisor_recv_fd recv_fd;
	struct landlock_pending_req *req;
	struct path path1 = {}, path2 = {};
	int fd = -1, fd2 = -1;
	u32 flags = 0;
	bool found = false;
	bool has_path1 = false, has_path2 = false;

	if (copy_from_user(&recv_fd, user_arg, sizeof(recv_fd)))
		return -EFAULT;

	spin_lock(&supervisor->lock);
	if (supervisor->dead) {
		spin_unlock(&supervisor->lock);
		return -ENODEV;
	}

	/* Find the request by ID */
	list_for_each_entry(req, &supervisor->pending, list) {
		if (req->id == recv_fd.id) {
			found = true;
			/*
			 * Extract path from common_audit_data. This is the
			 * single source of truth for filesystem information.
			 */
			switch (req->request.audit.type) {
			case LSM_AUDIT_DATA_PATH:
				path1 = req->request.audit.u.path;
				path_get(&path1);
				has_path1 = true;
				break;
			case LSM_AUDIT_DATA_FILE:
				if (req->request.audit.u.file) {
					path1 = req->request.audit.u.file->f_path;
					path_get(&path1);
					has_path1 = true;
				}
				break;
			default:
				/* No path available (network, etc.) */
				break;
			}

			/* Check for second path (rename/link operations) */
			if (req->request.has_audit2) {
				flags |= LANDLOCK_RECV_FD_FLAG_HAS_SUBJECT2;
				switch (req->request.audit2.type) {
				case LSM_AUDIT_DATA_PATH:
					path2 = req->request.audit2.u.path;
					path_get(&path2);
					has_path2 = true;
					break;
				case LSM_AUDIT_DATA_FILE:
					if (req->request.audit2.u.file) {
						path2 = req->request.audit2.u.file->f_path;
						path_get(&path2);
						has_path2 = true;
					}
					break;
				default:
					break;
				}
			}
			break;
		}
	}
	spin_unlock(&supervisor->lock);

	if (!found)
		return -ENOENT;

	/*
	 * Get O_PATH fds outside the lock (this operation can sleep).
	 */
	if (has_path1 && path1.dentry) {
		fd = get_path_fd(&path1, path1.dentry);
		if (fd < 0) {
			/*
			 * File doesn't exist yet (make_* operation).
			 * Try to get fd to the parent directory instead.
			 */
			if (path1.dentry->d_parent) {
				fd = get_path_fd(&path1, path1.dentry->d_parent);
			}
			if (fd < 0)
				fd = -1;
		}
	}

	if (has_path2 && path2.dentry) {
		fd2 = get_path_fd(&path2, path2.dentry);
		if (fd2 < 0) {
			/*
			 * Destination file doesn't exist yet (rename to new name).
			 * Try to get fd to the parent directory instead so the
			 * supervisor can see where the file is being moved to.
			 */
			if (path2.dentry->d_parent) {
				fd2 = get_path_fd(&path2, path2.dentry->d_parent);
			}
			if (fd2 < 0)
				fd2 = -1;
		}
	}

	/*
	 * Copy the pre-captured dentry names. These were captured when the
	 * request was queued to avoid races with dentry name changes.
	 */
	memset(recv_fd.name1, 0, sizeof(recv_fd.name1));
	recv_fd.name1_len = 0;
	memset(recv_fd.name2, 0, sizeof(recv_fd.name2));
	recv_fd.name2_len = 0;

	/* Find the request again to get the captured names */
	spin_lock(&supervisor->lock);
	list_for_each_entry(req, &supervisor->pending, list) {
		if (req->id == recv_fd.id) {
			if (req->name1[0]) {
				size_t len = strlen(req->name1);

				if (len >= sizeof(recv_fd.name1))
					len = sizeof(recv_fd.name1) - 1;
				memcpy(recv_fd.name1, req->name1, len);
				recv_fd.name1_len = len;
			}
			if (req->name2[0]) {
				size_t len = strlen(req->name2);

				if (len >= sizeof(recv_fd.name2))
					len = sizeof(recv_fd.name2) - 1;
				memcpy(recv_fd.name2, req->name2, len);
				recv_fd.name2_len = len;
			}
			break;
		}
	}
	spin_unlock(&supervisor->lock);

	/* Release path references */
	if (has_path1)
		path_put(&path1);
	if (has_path2)
		path_put(&path2);

	/* Return fds to userspace */
	recv_fd.fd = fd;
	recv_fd.fd2 = fd2;
	recv_fd.flags = flags;
	recv_fd.reserved = 0;

	if (copy_to_user(user_arg, &recv_fd, sizeof(recv_fd))) {
		if (fd >= 0)
			close_fd(fd);
		if (fd2 >= 0)
			close_fd(fd2);
		return -EFAULT;
	}

	return 0;
}

static long supervisor_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct landlock_supervisor *supervisor = file->private_data;

	/* Security: supervised processes cannot use ioctls */
	if (!is_supervisor_allowed(supervisor))
		return -EPERM;

	switch (cmd) {
	case LANDLOCK_IOCTL_SUPERVISOR_RECV_FD:
		return supervisor_ioctl_recv_fd(supervisor, arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations supervisor_fops = {
	.release = supervisor_release,
	.read = supervisor_read,
	.write = supervisor_write,
	.poll = supervisor_poll,
	.unlocked_ioctl = supervisor_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
	.llseek = noop_llseek,
};

/**
 * landlock_supervisor_get_fd - Get a file descriptor for the supervisor
 * @supervisor: The supervisor to get an fd for
 *
 * Returns a file descriptor on success, or a negative error code.
 * The supervisor's reference count is incremented.
 */
int landlock_supervisor_get_fd(struct landlock_supervisor *supervisor)
{
	int fd;

	landlock_get_supervisor(supervisor);
	fd = anon_inode_getfd("[landlock-supervisor]", &supervisor_fops,
			      supervisor, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		landlock_put_supervisor(supervisor);
	return fd;
}

/**
 * landlock_supervisor_request_decision - Request a decision from the supervisor
 * @supervisor: The supervisor to ask
 * @request: The landlock_request containing the access details (with common_audit_data)
 * @path_or_port: Port number for network requests, or 0 for filesystem
 *
 * All access details (paths, files, dentries) come from the common_audit_data
 * in the request. This ensures consistency between what can be audited and
 * what can be filtered/cached by the supervisor.
 *
 * This function blocks until the supervisor makes a decision or the
 * supervisor fd is closed.
 *
 * Returns 0 if access is allowed, -EACCES if denied, or another negative
 * error code on failure.
 */
int landlock_supervisor_request_decision(struct landlock_supervisor *supervisor,
					 const struct landlock_request *request,
					 u64 path_or_port)
{
	struct landlock_pending_req req;
	struct landlock_cache_entry *cached;
	struct landlock_cache_keys lookup_keys = {};
	enum landlock_rule_type rule_type;
	const struct path *path = NULL;
	const struct dentry *dentry = NULL;
	int ret;

	if (!supervisor || !request)
		return -EINVAL;

	/* Convert request type to rule type and extract path from audit data */
	rule_type = request_type_to_rule_type(request->type);
	if (!rule_type)
		return -EINVAL;

	/*
	 * Extract path/dentry from common_audit_data. This is the single
	 * source of truth for all filesystem subject information.
	 */
	switch (request->audit.type) {
	case LSM_AUDIT_DATA_PATH:
		path = &request->audit.u.path;
		dentry = path->dentry;
		break;
	case LSM_AUDIT_DATA_FILE:
		if (request->audit.u.file) {
			path = &request->audit.u.file->f_path;
			dentry = path->dentry;
		}
		break;
	case LSM_AUDIT_DATA_DENTRY:
		dentry = request->audit.u.dentry;
		break;
	case LSM_AUDIT_DATA_INODE:
		/* Inode only - no path available */
		break;
	default:
		/* Network or other - no filesystem path */
		break;
	}

	/*
	 * Build lookup keys for cache search. We populate all possible key
	 * components so we can match against any cached entry regardless of
	 * which key types the supervisor specified when caching.
	 */
	if (rule_type == LANDLOCK_RULE_PATH_BENEATH) {
		const struct dentry *dentry2 = NULL;

		/* Populate inode key from dentry or path */
		if (dentry && dentry->d_inode)
			lookup_keys.inode_key = (u64)(uintptr_t)dentry->d_inode;

		/* Populate inode2 key from audit2 if available */
		if (request->has_audit2) {
			switch (request->audit2.type) {
			case LSM_AUDIT_DATA_PATH:
				dentry2 = request->audit2.u.path.dentry;
				break;
			case LSM_AUDIT_DATA_FILE:
				if (request->audit2.u.file)
					dentry2 = request->audit2.u.file->f_path.dentry;
				break;
			case LSM_AUDIT_DATA_DENTRY:
				dentry2 = request->audit2.u.dentry;
				break;
			default:
				break;
			}
			if (dentry2 && dentry2->d_inode)
				lookup_keys.inode2_key = (u64)(uintptr_t)dentry2->d_inode;
		}

		/* Populate PID key */
		lookup_keys.pid_key = (u64)task_tgid_nr(current);
	} else {
		/* For network rules, use port as inode key (reused) */
		lookup_keys.inode_key = path_or_port;
	}

	/* Check if supervisor is already dead, and check cache */
	spin_lock(&supervisor->lock);
	if (supervisor->dead) {
		spin_unlock(&supervisor->lock);
		return -EACCES;
	}

	/*
	 * Check cache first. We do a quick lookup with the keys we have.
	 * Path-based keys require memory allocation so we defer those.
	 */
	cached = cache_lookup(supervisor, rule_type, request->access, &lookup_keys);

	/* If no hit, try with path-based keys */
	if (!cached && rule_type == LANDLOCK_RULE_PATH_BENEATH) {
		char *path_buf = kmalloc(PATH_MAX, GFP_ATOMIC);
		if (path_buf) {
			if (path) {
				char *full_path = d_path(path, path_buf, PATH_MAX);
				if (!IS_ERR(full_path))
					lookup_keys.path_key = full_name_hash(NULL, full_path, strlen(full_path));
			}
			/* Also populate path2 if audit2 is available */
			if (request->has_audit2 &&
			    request->audit2.type == LSM_AUDIT_DATA_PATH) {
				char *full_path = d_path(&request->audit2.u.path, path_buf, PATH_MAX);
				if (!IS_ERR(full_path))
					lookup_keys.path2_key = full_name_hash(NULL, full_path, strlen(full_path));
			}
			kfree(path_buf);
		}
		/* Try lookup again with path keys populated */
		cached = cache_lookup(supervisor, rule_type, request->access, &lookup_keys);
	}

	if (cached) {
		ret = cached->decision;
		spin_unlock(&supervisor->lock);
		return ret;
	}

	/* Initialize the request - copy the landlock_request data */
	init_completion(&req.done);
	req.id = supervisor->next_id++;
	memcpy(&req.request, request, sizeof(req.request));
	req.path_or_port = path_or_port;
	req.task = current;
	req.result = -EACCES;  /* Default to deny */
	req.flags = 0;
	req.cache_key_types = 0;

	/*
	 * Capture dentry names now because they can change after we release
	 * the lock. The dentry name is stable as long as we hold a reference
	 * to the path/dentry.
	 */
	memset(req.name1, 0, sizeof(req.name1));
	memset(req.name2, 0, sizeof(req.name2));
	if (dentry && dentry->d_name.name) {
		strscpy(req.name1, dentry->d_name.name, sizeof(req.name1));
	}
	if (request->has_audit2) {
		const struct dentry *dentry2 = NULL;

		switch (request->audit2.type) {
		case LSM_AUDIT_DATA_PATH:
			dentry2 = request->audit2.u.path.dentry;
			break;
		case LSM_AUDIT_DATA_FILE:
			if (request->audit2.u.file)
				dentry2 = request->audit2.u.file->f_path.dentry;
			break;
		case LSM_AUDIT_DATA_DENTRY:
			dentry2 = request->audit2.u.dentry;
			break;
		default:
			break;
		}
		if (dentry2 && dentry2->d_name.name) {
			strscpy(req.name2, dentry2->d_name.name, sizeof(req.name2));
		}
	}

	/* Add to pending list */
	list_add_tail(&req.list, &supervisor->pending);
	spin_unlock(&supervisor->lock);

	/* Wake up the supervisor */
	wake_up_interruptible(&supervisor->wait);

	/* Wait for the decision (interruptible) */
	ret = wait_for_completion_interruptible(&req.done);
	if (ret) {
		/* Interrupted - remove from list if still there */
		spin_lock(&supervisor->lock);
		if (!list_empty(&req.list))
			list_del(&req.list);
		spin_unlock(&supervisor->lock);
		return ret;
	}

	/* Cache the decision if CACHE flag was set */
	if (req.flags & LANDLOCK_DECISION_FLAG_CACHE) {
		struct landlock_cache_keys keys = {};
		const struct dentry *dentry2 = NULL;
		const struct path *path2 = NULL;
		u32 key_types = req.cache_key_types;

		/* If no key types specified, use default (inode) */
		if (key_types == 0)
			key_types = LANDLOCK_CACHE_KEY_INODE;

		/* Extract second path from audit2 if available */
		if (request->has_audit2) {
			switch (request->audit2.type) {
			case LSM_AUDIT_DATA_PATH:
				path2 = &request->audit2.u.path;
				dentry2 = path2->dentry;
				break;
			case LSM_AUDIT_DATA_FILE:
				if (request->audit2.u.file) {
					path2 = &request->audit2.u.file->f_path;
					dentry2 = path2->dentry;
				}
				break;
			case LSM_AUDIT_DATA_DENTRY:
				dentry2 = request->audit2.u.dentry;
				break;
			default:
				break;
			}
		}

		/*
		 * Build composite cache key from all requested key types.
		 * All specified key types form a single composite key -
		 * a cache hit requires ALL components to match.
		 */
		if (key_types & LANDLOCK_CACHE_KEY_INODE) {
			if (dentry && dentry->d_inode)
				keys.inode_key = (u64)(uintptr_t)dentry->d_inode;
		}

		if (key_types & LANDLOCK_CACHE_KEY_INODE2) {
			if (dentry2 && dentry2->d_inode)
				keys.inode2_key = (u64)(uintptr_t)dentry2->d_inode;
		}

		if (key_types & LANDLOCK_CACHE_KEY_PATH) {
			/* Use absolute path hash for consistent caching */
			if (path) {
				char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (path_buf) {
					char *full_path = d_path(path, path_buf, PATH_MAX);
					if (!IS_ERR(full_path))
						keys.path_key = full_name_hash(NULL, full_path, strlen(full_path));
					kfree(path_buf);
				}
			}
		}

		if (key_types & LANDLOCK_CACHE_KEY_PATH2) {
			/* Use absolute path hash for second subject */
			if (path2) {
				char *path_buf = kmalloc(PATH_MAX, GFP_KERNEL);
				if (path_buf) {
					char *full_path = d_path(path2, path_buf, PATH_MAX);
					if (!IS_ERR(full_path))
						keys.path2_key = full_name_hash(NULL, full_path, strlen(full_path));
					kfree(path_buf);
				}
			}
		}

		if (key_types & LANDLOCK_CACHE_KEY_PID)
			keys.pid_key = (u64)task_tgid_nr(req.task);

		/* Store the key_types in the keys struct for cache insertion */
		keys.key_types = key_types;

		spin_lock(&supervisor->lock);
		cache_insert(supervisor, rule_type, request->access,
			    req.result, &keys);
		spin_unlock(&supervisor->lock);
	}

	return req.result;
}

#endif /* CONFIG_AUDIT */
