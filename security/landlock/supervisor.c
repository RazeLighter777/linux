// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor support
 */

#include <linux/anon_inodes.h>
#include <linux/bug.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/landlock.h>

#include "domain.h"
#include "fs.h"
#include "ruleset.h"
#include "syscalls.h"
#include "tag.h"
#include "supervisor.h"

#ifdef CONFIG_AUDIT

struct landlock_supervisor {
	refcount_t usage;
	struct landlock_ruleset *domain;
	spinlock_t lock;
	struct list_head pending;
	struct list_head inflight;
	u64 next_cookie;
	struct eventfd_ctx *efd;
};

struct landlock_sup_event {
	struct list_head node;
	u64 cookie;
	wait_queue_head_t wq;
	bool decided;
	bool allow;
	struct landlock_supervisor_event uapi;
};

static void landlock_get_supervisor(struct landlock_supervisor *supervisor)
{
	if (supervisor)
		refcount_inc(&supervisor->usage);
}

void landlock_put_supervisor(struct landlock_supervisor *supervisor)
{
	if (!supervisor)
		return;
	if (!refcount_dec_and_test(&supervisor->usage))
		return;

	if (supervisor->efd)
		eventfd_ctx_put(supervisor->efd);
	landlock_put_ruleset(supervisor->domain);
	kfree(supervisor);
}

static struct landlock_supervisor *landlock_get_domain_supervisor(
	const struct landlock_ruleset *const domain)
{
	struct landlock_supervisor *supervisor;

	if (!domain || !domain->hierarchy)
		return NULL;
	supervisor = READ_ONCE(domain->hierarchy->supervisor);
	landlock_get_supervisor(supervisor);
	return supervisor;
}

static void landlock_supervisor_wake_all(struct landlock_supervisor *supervisor)
{
	struct landlock_sup_event *event, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&supervisor->lock, flags);
	list_for_each_entry_safe(event, tmp, &supervisor->pending, node) {
		list_del_init(&event->node);
		event->allow = false;
		event->decided = true;
		wake_up_all(&event->wq);
	}
	list_for_each_entry_safe(event, tmp, &supervisor->inflight, node) {
		list_del_init(&event->node);
		event->allow = false;
		event->decided = true;
		wake_up_all(&event->wq);
	}
	spin_unlock_irqrestore(&supervisor->lock, flags);
}

static u16 landlock_layer_level_from_ruleset_id(
	const struct landlock_ruleset *const domain,
	const u64 ruleset_id)
{
	const struct landlock_hierarchy *hierarchy;
	u16 depth = 0;

	if (!domain || !domain->hierarchy)
		return 0;

	for (hierarchy = domain->hierarchy; hierarchy; hierarchy = hierarchy->parent) {
		if (hierarchy->layer_ruleset_id == ruleset_id) {
			if (WARN_ON_ONCE(depth >= domain->num_layers))
				return 0;
			return domain->num_layers - depth;
		}
		depth++;
	}
	return 0;
}

static struct landlock_rule *find_rule_raw(struct landlock_ruleset *const ruleset,
					 const struct landlock_id id)
{
	struct rb_root *root;
	struct rb_node *node;

	if (!ruleset)
		return NULL;

	switch (id.type) {
	case LANDLOCK_KEY_INODE:
		root = &ruleset->root_inode;
		break;

#if IS_ENABLED(CONFIG_INET)
	case LANDLOCK_KEY_NET_PORT:
		root = &ruleset->root_net_port;
		break;
#endif /* IS_ENABLED(CONFIG_INET) */

	default:
		return NULL;
	}

	node = root->rb_node;
	while (node) {
		struct landlock_rule *this = rb_entry(node, struct landlock_rule, node);

		if (this->key.data == id.key.data)
			return this;
		if (this->key.data < id.key.data)
			node = node->rb_right;
		else
			node = node->rb_left;
	}
	return NULL;
}
static struct landlock_layer *find_layer(struct landlock_rule *const rule,
				       const u16 level)
{
	u32 i;

	if (!rule || !level)
		return NULL;

	for (i = 0; i < rule->num_layers; i++) {
		if (rule->layers[i].level == level)
			return &rule->layers[i];
	}
	return NULL;
}

static int validate_subruleset(const struct landlock_ruleset *const ruleset,
			      const struct landlock_ruleset *const subruleset)
{
	if (!ruleset || !subruleset)
		return -EINVAL;
	if (WARN_ON_ONCE(ruleset->num_layers != 1 || subruleset->num_layers != 1))
		return -EINVAL;
	if (WARN_ON_ONCE(ruleset->hierarchy || subruleset->hierarchy))
		return -EINVAL;

	/* Subruleset must not handle accesses outside the base ruleset. */
	if ((subruleset->access_masks[0].fs | ruleset->access_masks[0].fs) !=
	    ruleset->access_masks[0].fs)
		return -EINVAL;
	if ((subruleset->access_masks[0].net | ruleset->access_masks[0].net) !=
	    ruleset->access_masks[0].net)
		return -EINVAL;
	if ((subruleset->access_masks[0].scope | ruleset->access_masks[0].scope) !=
	    ruleset->access_masks[0].scope)
		return -EINVAL;

	return 0;
}

static struct landlock_tag *alloc_empty_tag(gfp_t gfp)
{
	struct landlock_tag *tag;

	tag = kzalloc(sizeof(*tag), gfp);
	if (!tag)
		return NULL;

	refcount_set(&tag->usage, 1);
	tag->type = LANDLOCK_TAG_EMPTY;
	atomic64_set(&tag->counter, 0);
	rcu_assign_pointer(tag->ruleset, NULL);
	return tag;
}

static struct landlock_tag *alloc_exec_dentry_tag(struct dentry *dentry, gfp_t gfp)
{
	struct landlock_tag *tag;

	if (!dentry)
		return NULL;

	tag = kzalloc(sizeof(*tag), gfp);
	if (!tag)
		return NULL;

	refcount_set(&tag->usage, 1);
	tag->type = LANDLOCK_TAG_EXEC_DENTRY;
	atomic64_set(&tag->counter, 0);
	rcu_assign_pointer(tag->ruleset, NULL);
	tag->u.exec_dentry = dget(dentry);
	return tag;
}

static struct landlock_tag *alloc_pidfd_tag(struct file *pidfd_file, gfp_t gfp)
{
	struct landlock_tag *tag;

	if (!pidfd_file)
		return NULL;

	tag = kzalloc(sizeof(*tag), gfp);
	if (!tag)
		return NULL;

	refcount_set(&tag->usage, 1);
	tag->type = LANDLOCK_TAG_PIDFD;
	atomic64_set(&tag->counter, 0);
	rcu_assign_pointer(tag->ruleset, NULL);
	tag->u.pidfd.pidfd_file = pidfd_file;
	return tag;
}

static struct landlock_tag *alloc_compose_tag(enum landlock_tag_type type,
				      struct landlock_tag *left,
				      struct landlock_tag *right,
				      gfp_t gfp)
{
	struct landlock_tag *tag;

	if (!left || !right)
		return NULL;
	if (type != LANDLOCK_TAG_COMPOSE_AND && type != LANDLOCK_TAG_COMPOSE_OR)
		return NULL;

	tag = kzalloc(sizeof(*tag), gfp);
	if (!tag)
		return NULL;

	refcount_set(&tag->usage, 1);
	tag->type = type;
	atomic64_set(&tag->counter, 0);
	rcu_assign_pointer(tag->ruleset, NULL);

	landlock_get_tag(left);
	landlock_get_tag(right);
	if (type == LANDLOCK_TAG_COMPOSE_AND) {
		tag->u.compose_and.left = left;
		tag->u.compose_and.right = right;
	} else {
		tag->u.compose_or.left = left;
		tag->u.compose_or.right = right;
	}
	return tag;
}

static int validate_tag_expr_depth(const struct landlock_tag_expr *nodes,
				 const u32 nodes_len, const u32 idx,
				 u8 *state, const int depth)
{
	const struct landlock_tag_expr *n;
	int err;

	if (idx >= nodes_len)
		return -EINVAL;
	if (depth > LANDLOCK_TAG_MATCH_MAX_DEPTH)
		return -E2BIG;
	if (state[idx] == 2)
		return 0;
	if (state[idx] == 1)
		return -ELOOP;
	state[idx] = 1;

	n = &nodes[idx];
	if (n->flags)
		return -EINVAL;

	switch (n->op) {
	case LANDLOCK_TAG_EXPR_PIDFD:
	case LANDLOCK_TAG_EXPR_EXEC_FD:
		break;
	case LANDLOCK_TAG_EXPR_AND:
	case LANDLOCK_TAG_EXPR_OR:
		err = validate_tag_expr_depth(nodes, nodes_len, n->left, state, depth + 1);
		if (err)
			return err;
		err = validate_tag_expr_depth(nodes, nodes_len, n->right, state, depth + 1);
		if (err)
			return err;
		break;
	default:
		return -EINVAL;
	}

	state[idx] = 2;
	return 0;
}

static int build_tag_from_user_tree(const struct landlock_tag_tree_attr *tree,
				   struct landlock_tag **out)
{
	struct landlock_tag_expr *nodes = NULL;
	struct landlock_tag **tags = NULL;
	u8 *state = NULL;
	u32 i;
	int err;

	if (!out)
		return -EINVAL;
	*out = NULL;

	if (!tree || !tree->nodes_len) {
		*out = alloc_empty_tag(GFP_KERNEL_ACCOUNT);
		return *out ? 0 : -ENOMEM;
	}
	if (!tree->nodes)
		return -EINVAL;
	if (tree->root >= tree->nodes_len)
		return -EINVAL;

	if (tree->nodes_len > U32_MAX / sizeof(*nodes))
		return -E2BIG;

	nodes = memdup_user((const void __user *)(uintptr_t)tree->nodes,
				tree->nodes_len * sizeof(*nodes));
	if (IS_ERR(nodes))
		return PTR_ERR(nodes);

	state = kcalloc(tree->nodes_len, sizeof(*state), GFP_KERNEL_ACCOUNT);
	if (!state) {
		err = -ENOMEM;
		goto out_free_nodes;
	}
	err = validate_tag_expr_depth(nodes, tree->nodes_len, tree->root, state, 0);
	if (err)
		goto out_free_state;

	tags = kcalloc(tree->nodes_len, sizeof(*tags), GFP_KERNEL_ACCOUNT);
	if (!tags) {
		err = -ENOMEM;
		goto out_free_state;
	}

	/* Build leaves first. */
	for (i = 0; i < tree->nodes_len; i++) {
		struct file *file;
		struct dentry *dentry;
		struct pid *pid;

		switch (nodes[i].op) {
		case LANDLOCK_TAG_EXPR_PIDFD:
			file = fget(nodes[i].fd);
			if (!file) {
				err = -EBADF;
				goto out_put_tags;
			}
			pid = pidfd_pid(file);
			if (IS_ERR(pid)) {
				err = PTR_ERR(pid);
				fput(file);
				goto out_put_tags;
			}
			tags[i] = alloc_pidfd_tag(file, GFP_KERNEL_ACCOUNT);
			if (!tags[i]) {
				fput(file);
				err = -ENOMEM;
				goto out_put_tags;
			}
			break;
		case LANDLOCK_TAG_EXPR_EXEC_FD:
			file = fget(nodes[i].fd);
			if (!file) {
				err = -EBADF;
				goto out_put_tags;
			}
			dentry = file->f_path.dentry;
			tags[i] = alloc_exec_dentry_tag(dentry, GFP_KERNEL_ACCOUNT);
			fput(file);
			if (!tags[i]) {
				err = -ENOMEM;
				goto out_put_tags;
			}
			break;
		default:
			break;
		}
	}

	/* Build composite nodes. */
	for (i = 0; i < tree->nodes_len; i++) {
		enum landlock_tag_type type;

		switch (nodes[i].op) {
		case LANDLOCK_TAG_EXPR_AND:
			type = LANDLOCK_TAG_COMPOSE_AND;
			break;
		case LANDLOCK_TAG_EXPR_OR:
			type = LANDLOCK_TAG_COMPOSE_OR;
			break;
		default:
			continue;
		}
		if (!tags[nodes[i].left] || !tags[nodes[i].right]) {
			err = -EINVAL;
			goto out_put_tags;
		}
		tags[i] = alloc_compose_tag(type, tags[nodes[i].left], tags[nodes[i].right],
					 GFP_KERNEL_ACCOUNT);
		if (!tags[i]) {
			err = -ENOMEM;
			goto out_put_tags;
		}
	}

	if (!tags[tree->root]) {
		err = -EINVAL;
		goto out_put_tags;
	}

	*out = tags[tree->root];
	/* Transfer ownership: keep root, drop all other local refs. */
	for (i = 0; i < tree->nodes_len; i++) {
		if (i == tree->root)
			continue;
		landlock_put_tag(tags[i]);
	}
	kfree(tags);
	kfree(state);
	kfree(nodes);
	return 0;

out_put_tags:
	if (tags) {
		for (i = 0; i < tree->nodes_len; i++)
			landlock_put_tag(tags[i]);
	}
	kfree(tags);
out_free_state:
	kfree(state);
out_free_nodes:
	kfree(nodes);
	return err;
}

static int set_layer_subruleset(struct landlock_layer *const layer,
			       struct landlock_ruleset *const subruleset,
			       const struct landlock_tag_tree_attr *const tree)
{
	struct landlock_tag_node *node;
	struct landlock_tag *tag = NULL;
	struct landlock_ruleset *old;
	int err;

	if (!layer || !subruleset)
		return -EINVAL;

	/* Fast path: keep the old behavior for the default (empty) tag. */
	if (!tree || !tree->nodes_len) {
		for (node = layer->tags; node; node = node->next) {
			if (node->tag && node->tag->type == LANDLOCK_TAG_EMPTY) {
				tag = node->tag;
				break;
			}
		}
		if (!tag) {
			node = kzalloc(sizeof(*node), GFP_KERNEL_ACCOUNT);
			if (!node)
				return -ENOMEM;
			tag = alloc_empty_tag(GFP_KERNEL_ACCOUNT);
			if (!tag) {
				kfree(node);
				return -ENOMEM;
			}
			node->tag = tag;
			node->next = layer->tags;
			layer->tags = node;
		}
	} else {
		err = build_tag_from_user_tree(tree, &tag);
		if (err)
			return err;
		node = kzalloc(sizeof(*node), GFP_KERNEL_ACCOUNT);
		if (!node) {
			landlock_put_tag(tag);
			return -ENOMEM;
		}
		node->tag = tag;
		node->next = layer->tags;
		layer->tags = node;
	}

	landlock_get_ruleset(subruleset);
	old = rcu_dereference_protected(tag->ruleset, 1);
	rcu_assign_pointer(tag->ruleset, subruleset);
	if (old) {
		synchronize_rcu();
		landlock_put_ruleset(old);
	}
	return 0;
}

static int fop_supervisor_set_subruleset(struct landlock_supervisor *const supervisor,
					const struct landlock_supervisor_set_subruleset_attr *const attr)
{
	struct landlock_ruleset *ruleset __free(landlock_put_ruleset) = NULL;
	struct landlock_ruleset *subruleset __free(landlock_put_ruleset) = NULL;
	struct landlock_ruleset *domain;
	struct landlock_rule *domain_rule;
	struct landlock_layer *layer;
	enum landlock_key_type key_type;
	union landlock_key key = {};
	u16 layer_level;
	int err;

	if (!supervisor || !attr)
		return -EINVAL;
	if (attr->flags)
		return -EINVAL;

	ruleset = landlock_get_ruleset_from_fd(attr->ruleset_fd, FMODE_CAN_READ);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	subruleset = landlock_get_ruleset_from_fd(attr->subruleset_fd, FMODE_CAN_READ);
	if (IS_ERR(subruleset))
		return PTR_ERR(subruleset);

	err = validate_subruleset(ruleset, subruleset);
	if (err)
		return err;

	domain = supervisor->domain;
	layer_level = landlock_layer_level_from_ruleset_id(domain, ruleset->id);
	if (!layer_level)
		return -EINVAL;

	switch (attr->rule_type) {
	case LANDLOCK_RULE_PATH_BENEATH: {
		struct path path;
		const struct inode *inode;
		struct landlock_object *object;
		const struct landlock_rule *base_rule;

		err = landlock_get_path_from_fd(attr->rule_attr.path_beneath.parent_fd,
					&path);
		if (err)
			return err;

		inode = d_backing_inode(path.dentry);
		rcu_read_lock();
		object = rcu_dereference(landlock_inode(inode)->object);
		const struct landlock_id id_tmp = {
			.type = LANDLOCK_KEY_INODE,
			.key.object = object,
		};
		base_rule = landlock_find_rule(ruleset, id_tmp);
		rcu_read_unlock();
		path_put(&path);
		if (!object || !base_rule)
			return -ENOENT;
		key_type = LANDLOCK_KEY_INODE;
		key.object = object;
		break;
	}

#if IS_ENABLED(CONFIG_INET)
	case LANDLOCK_RULE_NET_PORT: {
		u64 port64 = attr->rule_attr.net_port.port;
		u16 port;
		const struct landlock_rule *base_rule;

		if (port64 > U16_MAX)
			return -EINVAL;
		port = (u16)port64;
		const struct landlock_id id_tmp = {
			.type = LANDLOCK_KEY_NET_PORT,
			.key.data = (__force uintptr_t)htons(port),
		};
		base_rule = landlock_find_rule(ruleset, id_tmp);
		if (!base_rule)
			return -ENOENT;
		key_type = LANDLOCK_KEY_NET_PORT;
		key.data = (__force uintptr_t)htons(port);
		break;
	}
#endif /* IS_ENABLED(CONFIG_INET) */

	default:
		return -EINVAL;
	}

	/* Build an immutable ID (struct landlock_id::type is const). */
	const struct landlock_id id = {
		.type = key_type,
		.key = key,
	};

	/* Locate the rule in the supervisor's domain and update only that layer. */
	domain_rule = find_rule_raw(domain, id);
	if (!domain_rule)
		return -ENOENT;

	mutex_lock(&domain->lock);
	layer = find_layer(domain_rule, layer_level);
	if (!layer) {
		err = -ENOENT;
		goto out_unlock;
	}
	err = set_layer_subruleset(layer, subruleset, &attr->tag_tree);

out_unlock:
	mutex_unlock(&domain->lock);
	return err;
}

static int fop_supervisor_release(struct inode *const inode,
				 struct file *const filp)
{
	struct landlock_supervisor *supervisor = filp->private_data;

	if (supervisor) {
		landlock_supervisor_wake_all(supervisor);
		landlock_put_supervisor(supervisor);
	}
	return 0;
}

static int supervisor_set_eventfd(struct landlock_supervisor *supervisor,
				 const int efd)
{
	struct eventfd_ctx *ctx, *old;
	unsigned long flags;

	ctx = eventfd_ctx_fdget(efd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	spin_lock_irqsave(&supervisor->lock, flags);
	old = supervisor->efd;
	supervisor->efd = ctx;
	spin_unlock_irqrestore(&supervisor->lock, flags);

	if (old)
		eventfd_ctx_put(old);
	return 0;
}
static int supervisor_recv_event(struct landlock_supervisor *supervisor,
				 struct landlock_supervisor_event __user *uarg)
{
	struct landlock_sup_event *event;
	unsigned long flags;
	struct landlock_supervisor_event out;

	spin_lock_irqsave(&supervisor->lock, flags);
	if (list_empty(&supervisor->pending)) {
		spin_unlock_irqrestore(&supervisor->lock, flags);
		return -EAGAIN;
	}
	event = list_first_entry(&supervisor->pending, struct landlock_sup_event,
				 node);
	list_move(&event->node, &supervisor->inflight);
	out = event->uapi;
	spin_unlock_irqrestore(&supervisor->lock, flags);

	return copy_to_user(uarg, &out, sizeof(out)) ? -EFAULT : 0;
}

static int supervisor_decide(struct landlock_supervisor *supervisor,
			     const struct landlock_supervisor_decide_attr *attr)
{
	struct landlock_sup_event *event;
	unsigned long flags;

	if (attr->flags)
		return -EINVAL;

	spin_lock_irqsave(&supervisor->lock, flags);
	list_for_each_entry(event, &supervisor->inflight, node) {
		if (event->cookie != attr->cookie)
			continue;
		list_del_init(&event->node);
		event->allow = !!attr->allow;
		event->decided = true;
		wake_up_all(&event->wq);
		spin_unlock_irqrestore(&supervisor->lock, flags);
		return 0;
	}
	list_for_each_entry(event, &supervisor->pending, node) {
		if (event->cookie != attr->cookie)
			continue;
		list_del_init(&event->node);
		event->allow = !!attr->allow;
		event->decided = true;
		wake_up_all(&event->wq);
		spin_unlock_irqrestore(&supervisor->lock, flags);
		return 0;
	}
	spin_unlock_irqrestore(&supervisor->lock, flags);
	return -ENOENT;
}

static long fop_supervisor_ioctl(struct file *const filp, const unsigned int cmd,
				const unsigned long arg)
{
	struct landlock_supervisor *supervisor = filp->private_data;

	switch (cmd) {
	case LANDLOCK_SUPERVISOR_SET_SUBRULESET: {
		struct landlock_supervisor_set_subruleset_attr attr;

		if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
			return -EFAULT;
		return fop_supervisor_set_subruleset(supervisor, &attr);
	}
	case LANDLOCK_SUPERVISOR_SET_EVENTFD: {
		struct landlock_supervisor_eventfd_attr attr;

		if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
			return -EFAULT;
		if (attr.flags)
			return -EINVAL;
		return supervisor_set_eventfd(supervisor, attr.event_fd);
	}
	case LANDLOCK_SUPERVISOR_RECV_EVENT:
		return supervisor_recv_event(supervisor,
					 (struct landlock_supervisor_event __user *)arg);
	case LANDLOCK_SUPERVISOR_DECIDE: {
		struct landlock_supervisor_decide_attr attr;

		if (copy_from_user(&attr, (void __user *)arg, sizeof(attr)))
			return -EFAULT;
		return supervisor_decide(supervisor, &attr);
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations supervisor_fops = {
	.release = fop_supervisor_release,
	.unlocked_ioctl = fop_supervisor_ioctl,
};

int landlock_create_supervisor_fd(struct landlock_ruleset *const domain)
{
	struct landlock_supervisor *supervisor;
	int fd;

	if (WARN_ON_ONCE(!domain || !domain->num_layers))
		return -EINVAL;

	supervisor = kzalloc(sizeof(*supervisor), GFP_KERNEL_ACCOUNT);
	if (!supervisor)
		return -ENOMEM;

	refcount_set(&supervisor->usage, 1);
	spin_lock_init(&supervisor->lock);
	INIT_LIST_HEAD(&supervisor->pending);
	INIT_LIST_HEAD(&supervisor->inflight);
	supervisor->next_cookie = 1;

	landlock_get_ruleset(domain);
	supervisor->domain = domain;
	WRITE_ONCE(domain->hierarchy->supervisor, supervisor);
	/* Extra ref held by the domain hierarchy. */
	landlock_get_supervisor(supervisor);

	fd = anon_inode_getfd("[landlock-supervisor]", &supervisor_fops,
			      supervisor, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		WRITE_ONCE(domain->hierarchy->supervisor, NULL);
		landlock_put_supervisor(supervisor);
		landlock_put_supervisor(supervisor);
	}
	return fd;
}

static int supervisor_wait_for_decision(struct landlock_supervisor *supervisor,
				       struct landlock_sup_event *event)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&supervisor->lock, flags);
	if (!supervisor->efd) {
		spin_unlock_irqrestore(&supervisor->lock, flags);
		/* No userspace notification channel registered: do not auto-allow. */
		return -EPIPE;
	}
	list_add_tail(&event->node, &supervisor->pending);
	eventfd_signal(supervisor->efd);
	spin_unlock_irqrestore(&supervisor->lock, flags);

	ret = wait_event_killable(event->wq, READ_ONCE(event->decided));
	if (ret) {
		/* Cleanup on signal. */
		spin_lock_irqsave(&supervisor->lock, flags);
		if (!list_empty(&event->node))
			list_del_init(&event->node);
		spin_unlock_irqrestore(&supervisor->lock, flags);
		return ret;
	}
	return event->allow ? 0 : -EACCES;
}

static int supervisor_prompt(const struct landlock_ruleset *domain,
			    const struct landlock_request *request,
			    const enum landlock_rule_type rule_type,
			    const u64 ino,
			    const u64 port)
{
	struct landlock_supervisor *supervisor;
	struct landlock_sup_event *event;
	unsigned long flags;
	int ret;

	supervisor = landlock_get_domain_supervisor(domain);
	if (!supervisor)
		return -EPIPE;

	event = kzalloc(sizeof(*event), GFP_KERNEL_ACCOUNT);
	if (!event) {
		landlock_put_supervisor(supervisor);
		return -ENOMEM;
	}
	INIT_LIST_HEAD(&event->node);
	init_waitqueue_head(&event->wq);

	spin_lock_irqsave(&supervisor->lock, flags);
	event->cookie = supervisor->next_cookie++;
	spin_unlock_irqrestore(&supervisor->lock, flags);

	event->uapi.cookie = event->cookie;
	event->uapi.request_type = request ? request->type : 0;
	event->uapi.rule_type = rule_type;
	event->uapi.access = request ? request->access : 0;
	event->uapi.tgid = task_tgid_nr(current);
	event->uapi.flags = 0;
	event->uapi.ino = ino;
	event->uapi.port = port;

	ret = supervisor_wait_for_decision(supervisor, event);
	landlock_put_supervisor(supervisor);
	kfree(event);
	return ret;
}

int landlock_supervisor_enforce_fs(const struct landlock_ruleset *domain,
				  const struct path *path,
				  access_mask_t access_request)
{
	struct landlock_id id = { .type = LANDLOCK_KEY_INODE };
	struct landlock_request request = {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit.type = LSM_AUDIT_DATA_TASK,
		.audit.u.tsk = current,
		.access = access_request,
	};
	struct path walker;
	int ret = 0;

	if (!domain || !domain->hierarchy || !path)
		return 0;
	if (!access_request)
		return 0;

	if (!path->dentry || d_is_negative(path->dentry))
		return 0;

	/*
	 * Walk up the dentry hierarchy (within the current mount) and evaluate
	 * tagged subrulesets on each matching ancestor rule.
	 *
	 * This mirrors the base Landlock path walk behavior enough to make a
	 * directory rule's tags apply to its descendants.
	 */
	walker = *path;
	path_get(&walker);
	while (true) {
		const struct landlock_rule *rule;
		struct landlock_object *object;
		unsigned int i;

		if (!walker.dentry || d_is_negative(walker.dentry))
			break;

		rcu_read_lock();
		object = rcu_dereference(landlock_inode(d_backing_inode(walker.dentry))->object);
		id.key.object = object;
		rule = object ? landlock_find_rule(domain, id) : NULL;
		rcu_read_unlock();

		if (rule) {
			for (i = 0; i < rule->num_layers; i++) {
				struct landlock_tag_node *node;
				struct landlock_ruleset *sub;
				const struct landlock_rule *sub_rule;
				const struct landlock_layer *layer = &rule->layers[i];
				bool allowed;

				for (node = layer->tags; node; node = node->next) {
					struct landlock_tag *tag = node->tag;

					if (!tag)
						continue;
					if (!landlock_tag_matches_request(tag, &request))
						continue;

					rcu_read_lock();
					sub = rcu_dereference(tag->ruleset);
					rcu_read_unlock();
					if (!sub) {
						ret = supervisor_prompt(domain, &request,
									LANDLOCK_RULE_PATH_BENEATH,
									d_backing_inode(path->dentry)->i_ino,
									0);
						goto out_put_walker;
					}

					rcu_read_lock();
					sub_rule = landlock_find_rule(sub, id);
					allowed = sub_rule &&
						(sub_rule->layers[0].access & access_request) == access_request;
					rcu_read_unlock();
					if (!allowed) {
						ret = supervisor_prompt(domain, &request,
									LANDLOCK_RULE_PATH_BENEATH,
									d_backing_inode(path->dentry)->i_ino,
									0);
						goto out_put_walker;
					}
				}
			}
		}

		if (walker.dentry == walker.mnt->mnt_root)
			break;
		if (IS_ROOT(walker.dentry))
			break;
		{
			struct dentry *parent = dget_parent(walker.dentry);

			dput(walker.dentry);
			walker.dentry = parent;
		}
	}

out_put_walker:
	path_put(&walker);
	return ret;
}

#if IS_ENABLED(CONFIG_INET)
int landlock_supervisor_enforce_net(const struct landlock_ruleset *domain,
				   u16 port,
				   access_mask_t access_request)
{
	const struct landlock_rule *rule;
	struct landlock_id id = {
		.type = LANDLOCK_KEY_NET_PORT,
	};
	struct landlock_request request = {
		.type = LANDLOCK_REQUEST_NET_ACCESS,
		.audit.type = LSM_AUDIT_DATA_TASK,
		.audit.u.tsk = current,
		.access = access_request,
	};
	unsigned int i;

	if (!domain || !domain->hierarchy)
		return 0;
	if (!access_request)
		return 0;

	id.key.data = (__force uintptr_t)htons(port);
	rule = landlock_find_rule(domain, id);
	if (!rule)
		return 0;

	for (i = 0; i < rule->num_layers; i++) {
		struct landlock_tag_node *node;
		struct landlock_ruleset *sub;
		const struct landlock_rule *sub_rule;
		const struct landlock_layer *layer = &rule->layers[i];
		bool allowed;

		for (node = layer->tags; node; node = node->next) {
			struct landlock_tag *tag = node->tag;

			if (!tag)
				continue;
			if (!landlock_tag_matches_request(tag, &request))
				continue;

			rcu_read_lock();
			sub = rcu_dereference(tag->ruleset);
			rcu_read_unlock();
			if (!sub)
				return supervisor_prompt(domain, &request,
							LANDLOCK_RULE_NET_PORT, 0, port);

			rcu_read_lock();
			sub_rule = landlock_find_rule(sub, id);
			allowed = sub_rule &&
				(sub_rule->layers[0].access & access_request) == access_request;
			rcu_read_unlock();
			if (!allowed)
				return supervisor_prompt(domain, &request,
							LANDLOCK_RULE_NET_PORT, 0, port);
		}
	}
	return 0;
}
#endif /* IS_ENABLED(CONFIG_INET) */

#endif /* CONFIG_AUDIT */
