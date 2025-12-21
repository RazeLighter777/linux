// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor runtime helpers
 */

#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/poll.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stddef.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <linux/wait.h>
#include <uapi/linux/landlock.h>

#include "cred.h"
#include "fs.h"
#include "ruleset.h"
#include "super_table.h"
#include "supervisor.h"
#include "tag.h"

struct landlock_supervisor_pending_event {
	refcount_t usage;
	atomic_t pending;
	bool denied;
	wait_queue_head_t wq;
	struct landlock_supervisor_event uapi;
};

struct landlock_supervisor_queued_event {
	struct list_head list;
	struct landlock_supervisor_pending_event *event;
};

struct landlock_supervisor_listener {
	refcount_t usage;
	struct eventfd_ctx *eventfd;
	pid_t owner_pid;
	struct mutex lock;
	struct list_head pending;
	struct list_head inflight;
};

static void event_get(struct landlock_supervisor_pending_event *event)
{
	refcount_inc(&event->usage);
}

static void event_put(struct landlock_supervisor_pending_event *event)
{
	if (event && refcount_dec_and_test(&event->usage))
		kfree(event);
}

static void listener_destroy(struct landlock_supervisor_listener *listener)
{
	struct landlock_supervisor_queued_event *qe, *tmp;

	if (!listener)
		return;

	mutex_lock(&listener->lock);
	list_for_each_entry_safe(qe, tmp, &listener->pending, list) {
		struct landlock_supervisor_pending_event *event = qe->event;

		list_del(&qe->list);
		kfree(qe);

		WRITE_ONCE(event->denied, true);
		if (atomic_dec_and_test(&event->pending))
			wake_up_all(&event->wq);
		event_put(event);
	}
	list_for_each_entry_safe(qe, tmp, &listener->inflight, list) {
		struct landlock_supervisor_pending_event *event = qe->event;

		list_del(&qe->list);
		kfree(qe);

		WRITE_ONCE(event->denied, true);
		if (atomic_dec_and_test(&event->pending))
			wake_up_all(&event->wq);
		event_put(event);
	}
	mutex_unlock(&listener->lock);

	eventfd_ctx_put(listener->eventfd);
	kfree(listener);
}

static void listener_get(struct landlock_supervisor_listener *listener)
{
	refcount_inc(&listener->usage);
}

static void listener_put(struct landlock_supervisor_listener *listener)
{
	if (listener && refcount_dec_and_test(&listener->usage))
		listener_destroy(listener);
}

void landlock_supervisor_ruleset_cleanup(struct landlock_ruleset *ruleset)
{
	struct landlock_supervisor_listener *listener;

	if (!ruleset)
		return;

	/*
	 * This function is called from ruleset freeing paths, including the
	 * deferred workqueue path where @ruleset->lock shares storage with
	 * @ruleset->work_free and must not be touched.
	 */
	listener = xchg(&ruleset->supervisor_listener, NULL);

	listener_put(listener);
}

int landlock_supervisor_ruleset_listen(struct landlock_ruleset *ruleset,
				      const struct landlock_supervisor_listen_attr *attr)
{
	struct landlock_supervisor_listener *listener, *old;
	struct eventfd_ctx *ctx;

	if (!ruleset || !attr)
		return -EINVAL;
	if (attr->event_fd < 0)
		return -EBADF;

	ctx = eventfd_ctx_fdget(attr->event_fd);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	listener = kzalloc(sizeof(*listener), GFP_KERNEL_ACCOUNT);
	if (!listener) {
		eventfd_ctx_put(ctx);
		return -ENOMEM;
	}

	refcount_set(&listener->usage, 1);
	listener->eventfd = ctx;
	listener->owner_pid = task_pid_nr(current);
	mutex_init(&listener->lock);
	INIT_LIST_HEAD(&listener->pending);
	INIT_LIST_HEAD(&listener->inflight);

	mutex_lock(&ruleset->lock);
	old = ruleset->supervisor_listener;
	ruleset->supervisor_listener = listener;
	mutex_unlock(&ruleset->lock);

	listener_put(old);
	return 0;
}

int landlock_supervisor_ruleset_recv(struct landlock_ruleset *ruleset,
				    struct landlock_supervisor_event *event)
{
	struct landlock_supervisor_listener *listener;
	struct landlock_supervisor_queued_event *qe;

	if (!ruleset || !event)
		return -EINVAL;

	mutex_lock(&ruleset->lock);
	listener = ruleset->supervisor_listener;
	if (listener)
		listener_get(listener);
	mutex_unlock(&ruleset->lock);

	if (!listener)
		return -ENOENT;

	mutex_lock(&listener->lock);
	if (list_empty(&listener->pending)) {
		mutex_unlock(&listener->lock);
		listener_put(listener);
		return -EAGAIN;
	}

	qe = list_first_entry(&listener->pending,
			     struct landlock_supervisor_queued_event, list);
	list_move_tail(&qe->list, &listener->inflight);
	*event = qe->event->uapi;
	mutex_unlock(&listener->lock);

	listener_put(listener);
	return 0;
}

int landlock_supervisor_ruleset_decide(struct landlock_ruleset *ruleset,
				      const struct landlock_supervisor_decide_attr *attr)
{
	struct landlock_supervisor_listener *listener;
	struct landlock_supervisor_queued_event *qe, *tmp;
	struct landlock_supervisor_pending_event *event = NULL;
	bool allow;

	if (!ruleset || !attr)
		return -EINVAL;

	allow = (attr->decision == LANDLOCK_SUPERVISOR_DECISION_ALLOW);
	if (!allow && attr->decision != LANDLOCK_SUPERVISOR_DECISION_DENY)
		return -EINVAL;

	mutex_lock(&ruleset->lock);
	listener = ruleset->supervisor_listener;
	if (listener)
		listener_get(listener);
	mutex_unlock(&ruleset->lock);

	if (!listener)
		return -ENOENT;

	mutex_lock(&listener->lock);
	list_for_each_entry_safe(qe, tmp, &listener->inflight, list) {
		if (qe->event->uapi.id != attr->id)
			continue;
		event = qe->event;
		list_del(&qe->list);
		kfree(qe);
		break;
	}
	mutex_unlock(&listener->lock);

	listener_put(listener);

	if (!event)
		return -ENOENT;

	if (!allow)
		WRITE_ONCE(event->denied, true);
	if (atomic_dec_and_test(&event->pending))
		wake_up_all(&event->wq);
	event_put(event);
	return 0;
}

struct landlock_ruleset *
landlock_supervisor_resolve_current(struct landlock_ruleset *domain)
{
	struct landlock_supervisor_tag tags[3];
	u32 num_tags = 0;
	struct landlock_ruleset **rulesets = NULL;
	size_t num_rulesets = 0, i;
	struct landlock_ruleset *dom = NULL;
	int err;
	struct file *exe_file;

	if (!domain || !domain->super_table)
		return NULL;

	landlock_supervisor_tag_init(&tags[num_tags++]);

	landlock_supervisor_tag_init(&tags[num_tags]);
	err = landlock_supervisor_tag_set_pid(&tags[num_tags], task_pid(current));
	if (!err)
		num_tags++;
	else
		landlock_supervisor_tag_destroy(&tags[num_tags]);

	exe_file = get_task_exe_file(current);
	if (exe_file) {
		landlock_supervisor_tag_init(&tags[num_tags]);
		err = landlock_supervisor_tag_set_exec_dentry(
			&tags[num_tags], exe_file->f_path.dentry);
		fput(exe_file);
		if (!err)
			num_tags++;
		else
			landlock_supervisor_tag_destroy(&tags[num_tags]);
	}

	err = landlock_super_table_gather_rulesets(domain->super_table, tags,
						  num_tags, &rulesets,
						  &num_rulesets);
	for (i = 0; i < num_tags; i++)
		landlock_supervisor_tag_destroy(&tags[i]);
	if (err)
		return ERR_PTR(err);

	if (!num_rulesets)
		return NULL;

	for (i = 0; i < num_rulesets; i++) {
		struct landlock_ruleset *new_dom;

		new_dom = landlock_merge_ruleset(dom, rulesets[i]);
		if (IS_ERR(new_dom)) {
			if (dom)
				landlock_put_ruleset(dom);
			dom = new_dom;
			break;
		}
		if (dom)
			landlock_put_ruleset(dom);
		dom = new_dom;
	}

	for (i = 0; i < num_rulesets; i++)
		landlock_put_ruleset(rulesets[i]);
	kfree(rulesets);
	return dom;
}

static struct landlock_supervisor_pending_event *
alloc_fs_event(const struct path *path, unsigned int access)
{
	struct landlock_supervisor_pending_event *event;
	char *buf;
	char *p;

	event = kzalloc(sizeof(*event), GFP_KERNEL_ACCOUNT);
	if (!event)
		return NULL;

	refcount_set(&event->usage, 1);
	atomic_set(&event->pending, 0);
	init_waitqueue_head(&event->wq);

	event->uapi.size = sizeof(event->uapi);
	event->uapi.type = LANDLOCK_SUPERVISOR_EVENT_FS;
	event->uapi.access = access;
	event->uapi.pid = task_pid_nr(current);
	event->uapi.tgid = task_tgid_nr(current);
	event->uapi.uid = from_kuid_munged(current_user_ns(), current_uid());
	event->uapi.id = 0;
	event->uapi.path[0] = '\0';

	if (!path)
		return event;

	buf = kmalloc(LANDLOCK_SUPERVISOR_PATH_MAX, GFP_KERNEL_ACCOUNT);
	if (!buf)
		return event;

	p = d_path(path, buf, LANDLOCK_SUPERVISOR_PATH_MAX);
	if (!IS_ERR(p))
		strscpy(event->uapi.path, p, sizeof(event->uapi.path));
	kfree(buf);
	return event;
}

static int notify_and_wait(struct landlock_ruleset **rulesets,
			   size_t num_rulesets,
			   struct landlock_supervisor_pending_event *event)
{
	static atomic64_t next_id = ATOMIC64_INIT(1);
	struct landlock_supervisor_listener **listeners = NULL;
	size_t num_listeners = 0;
	size_t i;
	int err = 0;
	int wait_ret;

	listeners = kcalloc(num_rulesets, sizeof(*listeners), GFP_KERNEL_ACCOUNT);
	if (!listeners)
		return -ENOMEM;

	/* Collect listeners and enforce unanimous allow. */
	for (i = 0; i < num_rulesets; i++) {
		struct landlock_supervisor_listener *listener;

		mutex_lock(&rulesets[i]->lock);
		listener = rulesets[i]->supervisor_listener;
		if (listener)
			listener_get(listener);
		mutex_unlock(&rulesets[i]->lock);

		if (!listener) {
			err = -EACCES;
			goto out_put_listeners;
		}

		/* Avoid deadlock by not supervising the supervisor itself. */
		if (listener->owner_pid == task_pid_nr(current)) {
			listener_put(listener);
			continue;
		}
		listeners[num_listeners++] = listener;
	}

	if (!num_listeners)
		goto out_put_listeners;

	event->uapi.id = atomic64_inc_return(&next_id);
	atomic_set(&event->pending, num_listeners);
	/* +1 ref for the waiter */
	event_get(event);

	for (i = 0; i < num_listeners; i++) {
		struct landlock_supervisor_queued_event *qe;

		qe = kzalloc(sizeof(*qe), GFP_KERNEL_ACCOUNT);
		if (!qe) {
			WRITE_ONCE(event->denied, true);
			while (i < num_listeners) {
				if (atomic_dec_and_test(&event->pending))
					wake_up_all(&event->wq);
				i++;
			}
			err = -ENOMEM;
			goto out_wait_ref;
		}
		qe->event = event;
		event_get(event);

		mutex_lock(&listeners[i]->lock);
		list_add_tail(&qe->list, &listeners[i]->pending);
		eventfd_signal_mask(listeners[i]->eventfd, EPOLLIN);
		mutex_unlock(&listeners[i]->lock);
	}

	wait_ret = wait_event_killable(event->wq,
				      atomic_read(&event->pending) == 0);
	if (wait_ret) {
		/* A killed/interrupted task results in a denial. */
		WRITE_ONCE(event->denied, true);
		err = wait_ret;
	}

	if (READ_ONCE(event->denied))
		err = err ? err : -EACCES;

out_wait_ref:
	event_put(event);

out_put_listeners:
	for (i = 0; i < num_listeners; i++)
		listener_put(listeners[i]);
	kfree(listeners);
	return err;
}

int landlock_supervisor_check_fs(const struct landlock_cred_security *subject,
				const struct path *path,
				unsigned int access)
{
	struct landlock_supervisor_tag tag;
	struct landlock_ruleset **rulesets = NULL;
	size_t num_rulesets = 0;
	struct landlock_supervisor_pending_event *event;
	int err;
	size_t i;
	struct file *exe_file;

	if (!subject || !subject->domain || !subject->domain->super_table)
		return 0;

	/*
	 * Fast-path: if there are EXEC_DENTRY-tagged supervisor rulesets that
	 * explicitly allow this access, then skip interactive supervision.
	 */
	exe_file = get_task_exe_file(current);
	if (exe_file) {
		landlock_supervisor_tag_init(&tag);
		err = landlock_supervisor_tag_set_exec_dentry(&tag,
						      exe_file->f_path.dentry);
		fput(exe_file);
		if (!err) {
			err = landlock_super_table_gather_rulesets(
				subject->domain->super_table, &tag, 1, &rulesets,
				&num_rulesets);
			if (err) {
				landlock_supervisor_tag_destroy(&tag);
				return err;
			}
		}
		landlock_supervisor_tag_destroy(&tag);
		if (!err && num_rulesets) {
			bool allowed = true;

			for (i = 0; i < num_rulesets; i++) {
				if (!landlock_is_fs_access_allowed(rulesets[i], path, access)) {
					allowed = false;
					break;
				}
			}
			for (i = 0; i < num_rulesets; i++)
				landlock_put_ruleset(rulesets[i]);
			kfree(rulesets);
			rulesets = NULL;
			num_rulesets = 0;

			/* If allowed by all matching allowlist rulesets, bypass prompts. */
			if (allowed)
				return 0;
		}
	}

	landlock_supervisor_tag_init(&tag);
	err = landlock_super_table_gather_rulesets(subject->domain->super_table,
						  &tag, 1, &rulesets,
						  &num_rulesets);
	if (err)
		return err;
	if (!num_rulesets)
		return 0;

	event = alloc_fs_event(path, access);
	if (!event) {
		for (i = 0; i < num_rulesets; i++)
			landlock_put_ruleset(rulesets[i]);
		kfree(rulesets);
		return -ENOMEM;
	}

	err = notify_and_wait(rulesets, num_rulesets, event);

	for (i = 0; i < num_rulesets; i++)
		landlock_put_ruleset(rulesets[i]);
	kfree(rulesets);
	event_put(event);
	return err;
}

int landlock_supervisor_check_signal(
	const struct landlock_cred_security *subject,
	const struct task_struct *target,
	int sig)
{
	struct landlock_supervisor_tag tag;
	struct landlock_ruleset **rulesets = NULL;
	size_t num_rulesets = 0;
	struct landlock_supervisor_pending_event *event;
	int err;
	size_t i;

	if (!subject || !subject->domain || !subject->domain->super_table)
		return 0;

	landlock_supervisor_tag_init(&tag);
	err = landlock_super_table_gather_rulesets(subject->domain->super_table,
						  &tag, 1, &rulesets,
						  &num_rulesets);
	if (err)
		return err;
	if (!num_rulesets)
		return 0;

	event = kzalloc(sizeof(*event), GFP_KERNEL_ACCOUNT);
	if (!event) {
		for (i = 0; i < num_rulesets; i++)
			landlock_put_ruleset(rulesets[i]);
		kfree(rulesets);
		return -ENOMEM;
	}
	refcount_set(&event->usage, 1);
	init_waitqueue_head(&event->wq);
	event->uapi.size = sizeof(event->uapi);
	event->uapi.type = LANDLOCK_SUPERVISOR_EVENT_SIGNAL;
	event->uapi.access = (unsigned int)sig;
	event->uapi.pid = task_pid_nr(current);
	event->uapi.tgid = task_tgid_nr(current);
	event->uapi.uid = from_kuid_munged(current_user_ns(), current_uid());
	event->uapi.id = 0;
	event->uapi.path[0] = '\0';
	if (target)
		snprintf(event->uapi.path, sizeof(event->uapi.path), "target_tgid=%d",
			 task_tgid_nr((struct task_struct *)target));

	err = notify_and_wait(rulesets, num_rulesets, event);

	for (i = 0; i < num_rulesets; i++)
		landlock_put_ruleset(rulesets[i]);
	kfree(rulesets);
	event_put(event);
	return err;
}
