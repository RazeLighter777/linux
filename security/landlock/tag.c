// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor tags
 */

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/lsm_audit.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include "audit.h"
#include "ruleset.h"
#include "tag.h"

#ifdef CONFIG_AUDIT

static void landlock_free_tag(struct landlock_tag *const tag)
{
	switch (tag->type) {
	case LANDLOCK_TAG_PIDFD:
		if (tag->u.pidfd.pidfd_file)
			fput(tag->u.pidfd.pidfd_file);
		break;
	case LANDLOCK_TAG_EXEC_DENTRY:
		if (tag->u.exec_dentry)
			dput(tag->u.exec_dentry);
		break;
	case LANDLOCK_TAG_COMPOSE_OR:
		landlock_put_tag(tag->u.compose_or.left);
		landlock_put_tag(tag->u.compose_or.right);
		break;
	case LANDLOCK_TAG_COMPOSE_AND:
		landlock_put_tag(tag->u.compose_and.left);
		landlock_put_tag(tag->u.compose_and.right);
		break;
	default:
		WARN_ON_ONCE(1);
		break;
	}
	{
		struct landlock_ruleset *ruleset = rcu_access_pointer(tag->ruleset);

		if (ruleset)
			landlock_put_ruleset(ruleset);
	}
	kfree(tag);
}

void landlock_put_tag(struct landlock_tag *tag)
{
	if (tag && refcount_dec_and_test(&tag->usage))
		landlock_free_tag(tag);
}

static const struct dentry *get_request_dentry(const struct landlock_request *const request)
{
	struct file *exe;
	struct dentry *dentry;

	switch (request->audit.type) {
	case LSM_AUDIT_DATA_TASK:
		if (!request->audit.u.tsk)
			return NULL;
		exe = get_task_exe_file(request->audit.u.tsk);
		if (!exe)
			return NULL;
		dentry = exe->f_path.dentry;
		fput(exe);
		return dentry;
	case LSM_AUDIT_DATA_PATH:
		return request->audit.u.path.dentry;
	case LSM_AUDIT_DATA_DENTRY:
		return request->audit.u.dentry;
	case LSM_AUDIT_DATA_FILE:
		if (!request->audit.u.file)
			return NULL;
		return request->audit.u.file->f_path.dentry;
	case LSM_AUDIT_DATA_IOCTL_OP:
		if (!request->audit.u.op)
			return NULL;
		return request->audit.u.op->path.dentry;
	default:
		return NULL;
	}
}

static bool landlock_tag_matches_request_depth(
		const struct landlock_tag *const tag,
		const struct landlock_request *const request, const int depth)
{
	struct task_struct *tsk;
	const struct dentry *dentry;
	struct pid *pid;

	if (!tag || !request)
		return false;

	if (WARN_ON_ONCE(depth > LANDLOCK_TAG_MATCH_MAX_DEPTH))
		return false;

	switch (tag->type) {
	case LANDLOCK_TAG_EMPTY:
		return true;
	case LANDLOCK_TAG_PIDFD:
		if (!tag->u.pidfd.pidfd_file)
			return false;
		if (request->audit.type != LSM_AUDIT_DATA_TASK)
			return false;
		tsk = request->audit.u.tsk;
		if (!tsk)
			return false;
		pid = pidfd_pid(tag->u.pidfd.pidfd_file);
		if (IS_ERR(pid) || !pid)
			return false;
		return pid_nr(pid) == task_tgid_nr(tsk);

	case LANDLOCK_TAG_EXEC_DENTRY:
		if (!tag->u.exec_dentry)
			return false;
		dentry = get_request_dentry(request);
		return dentry && dentry == tag->u.exec_dentry;

	case LANDLOCK_TAG_COMPOSE_OR:
		return landlock_tag_matches_request_depth(tag->u.compose_or.left,
						 request, depth + 1) ||
			landlock_tag_matches_request_depth(tag->u.compose_or.right,
						 request, depth + 1);

	case LANDLOCK_TAG_COMPOSE_AND:
		return landlock_tag_matches_request_depth(tag->u.compose_and.left,
						 request, depth + 1) &&
			landlock_tag_matches_request_depth(tag->u.compose_and.right,
						 request, depth + 1);
	}

	WARN_ON_ONCE(1);
	return false;
}

bool landlock_tag_matches_request(const struct landlock_tag *const tag,
				 const struct landlock_request *const request)
{
	return landlock_tag_matches_request_depth(tag, request, 0);
}

#ifdef CONFIG_SECURITY_LANDLOCK_KUNIT_TEST

#include <kunit/test.h>

static void test_tag_matches_exec_dentry(struct kunit *const test)
{
	struct dentry dentry1 = {}, dentry2 = {};
	struct landlock_request request = {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_DENTRY,
			.u.dentry = &dentry1,
		},
	};
	const struct landlock_tag tag_match = {
		.type = LANDLOCK_TAG_EXEC_DENTRY,
		.u.exec_dentry = &dentry1,
	};
	const struct landlock_tag tag_mismatch = {
		.type = LANDLOCK_TAG_EXEC_DENTRY,
		.u.exec_dentry = &dentry2,
	};

	KUNIT_EXPECT_TRUE(test, landlock_tag_matches_request(&tag_match, &request));
	KUNIT_EXPECT_FALSE(test,
			 landlock_tag_matches_request(&tag_mismatch, &request));
}

static void test_tag_matches_composition(struct kunit *const test)
{
	struct dentry dentry1 = {}, dentry2 = {};
	struct landlock_request request = {
		.type = LANDLOCK_REQUEST_FS_ACCESS,
		.audit = {
			.type = LSM_AUDIT_DATA_DENTRY,
			.u.dentry = &dentry1,
		},
	};
	const struct landlock_tag leaf_match = {
		.type = LANDLOCK_TAG_EXEC_DENTRY,
		.u.exec_dentry = &dentry1,
	};
	const struct landlock_tag leaf_mismatch = {
		.type = LANDLOCK_TAG_EXEC_DENTRY,
		.u.exec_dentry = &dentry2,
	};
	const struct landlock_tag tag_or = {
		.type = LANDLOCK_TAG_COMPOSE_OR,
		.u.compose_or = {
			.left = (struct landlock_tag *)&leaf_mismatch,
			.right = (struct landlock_tag *)&leaf_match,
		},
	};
	const struct landlock_tag tag_and = {
		.type = LANDLOCK_TAG_COMPOSE_AND,
		.u.compose_and = {
			.left = (struct landlock_tag *)&leaf_match,
			.right = (struct landlock_tag *)&leaf_mismatch,
		},
	};

	KUNIT_EXPECT_TRUE(test, landlock_tag_matches_request(&tag_or, &request));
	KUNIT_EXPECT_FALSE(test, landlock_tag_matches_request(&tag_and, &request));
}

static struct kunit_case tag_test_cases[] = {
	KUNIT_CASE(test_tag_matches_exec_dentry),
	KUNIT_CASE(test_tag_matches_composition),
	{}
};

static struct kunit_suite tag_test_suite = {
	.name = "landlock_tag",
	.test_cases = tag_test_cases,
};

kunit_test_suite(tag_test_suite);

#endif /* CONFIG_SECURITY_LANDLOCK_KUNIT_TEST */

#endif /* CONFIG_AUDIT */
