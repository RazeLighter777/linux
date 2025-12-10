// SPDX-License-Identifier: GPL-2.0
/*
 * Landlock tests - Supervisor functionality
 *
 * Copyright © 2025 Microsoft Corporation
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#ifndef LANDLOCK_CREATE_RULESET_SUPERVISED
#define LANDLOCK_CREATE_RULESET_SUPERVISED (1U << 2)
#endif

#ifndef LANDLOCK_ADD_RULE_SUPERVISED
#define LANDLOCK_ADD_RULE_SUPERVISED (1U << 2)
#endif

#ifndef LANDLOCK_DECISION_DENY
#define LANDLOCK_DECISION_DENY 0
#endif

#ifndef LANDLOCK_DECISION_ALLOW
#define LANDLOCK_DECISION_ALLOW 1
#endif

/* These structs may not be in the system headers yet */
struct landlock_supervisor_attr {
	struct landlock_ruleset_attr ruleset_attr;
	__s32 supervisor_fd;
	__u32 flags;
};

struct landlock_supervisor_request {
	__u64 id;
	__u32 pid;
	__u32 tgid;
	__u32 rule_type;
	__u32 flags;
	__u64 access_request;
	__u64 path_or_port;
};

struct landlock_supervisor_response {
	__u64 id;
	__s32 decision;
	__u32 flags;
};

FIXTURE(supervisor)
{
	char tmp_dir[PATH_MAX];
	char test_file[PATH_MAX];
};

FIXTURE_SETUP(supervisor)
{
	snprintf(self->tmp_dir, sizeof(self->tmp_dir), "%s/supervisor_XXXXXX",
		 TMP_DIR);
	ASSERT_NE(NULL, mkdtemp(self->tmp_dir));
	snprintf(self->test_file, sizeof(self->test_file), "%s/test_file",
		 self->tmp_dir);
	ASSERT_EQ(0, mknod(self->test_file, S_IFREG | 0644, 0));
}

FIXTURE_TEARDOWN(supervisor)
{
	unlink(self->test_file);
	rmdir(self->tmp_dir);
}

TEST_F(supervisor, create_supervised_ruleset)
{
	struct landlock_supervisor_attr attr = {
		.ruleset_attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
					     LANDLOCK_ACCESS_FS_WRITE_FILE,
		},
		.supervisor_fd = -1,
		.flags = 0,
	};
	int ruleset_fd;

	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			     LANDLOCK_CREATE_RULESET_SUPERVISED);
	if (ruleset_fd < 0 && errno == EINVAL) {
		/* Feature not supported */
		SKIP(return, "Supervised rulesets not supported");
	}
	ASSERT_LE(0, ruleset_fd);
	ASSERT_LE(0, attr.supervisor_fd);

	/* Verify we got two different file descriptors */
	ASSERT_NE(ruleset_fd, attr.supervisor_fd);

	EXPECT_EQ(0, close(attr.supervisor_fd));
	EXPECT_EQ(0, close(ruleset_fd));
}

TEST_F(supervisor, supervised_rule_requires_supervised_ruleset)
{
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
	};
	int ruleset_fd, dir_fd;

	/* Create a non-supervised ruleset */
	ruleset_fd =
		syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
	ASSERT_LE(0, ruleset_fd);

	dir_fd = open(self->tmp_dir, O_PATH | O_DIRECTORY);
	ASSERT_LE(0, dir_fd);

	path_attr.parent_fd = dir_fd;

	/* Adding a supervised rule to a non-supervised ruleset should fail */
	EXPECT_EQ(-1, syscall(__NR_landlock_add_rule, ruleset_fd,
			      LANDLOCK_RULE_PATH_BENEATH, &path_attr,
			      LANDLOCK_ADD_RULE_SUPERVISED));
	EXPECT_EQ(EINVAL, errno);

	EXPECT_EQ(0, close(dir_fd));
	EXPECT_EQ(0, close(ruleset_fd));
}

/*
 * Test basic supervisor functionality:
 * 1. Create supervised ruleset
 * 2. Add supervised rule
 * 3. Fork child process
 * 4. Child enforces ruleset and tries to access file
 * 5. Parent (supervisor) receives request and responds
 * 6. Child gets access result
 */
TEST_F(supervisor, basic_allow)
{
	struct landlock_supervisor_attr attr = {
		.ruleset_attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		.supervisor_fd = -1,
		.flags = 0,
	};
	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = 0, /* Deny all by default */
	};
	int ruleset_fd, supervisor_fd, dir_fd;
	pid_t child;
	int status;

	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			     LANDLOCK_CREATE_RULESET_SUPERVISED);
	if (ruleset_fd < 0 && errno == EINVAL) {
		SKIP(return, "Supervised rulesets not supported");
	}
	ASSERT_LE(0, ruleset_fd);
	supervisor_fd = attr.supervisor_fd;
	ASSERT_LE(0, supervisor_fd);

	dir_fd = open(self->tmp_dir, O_PATH | O_DIRECTORY);
	ASSERT_LE(0, dir_fd);

	path_attr.parent_fd = dir_fd;

	/* Add a supervised rule - access will be deferred to supervisor */
	ASSERT_EQ(0, syscall(__NR_landlock_add_rule, ruleset_fd,
			     LANDLOCK_RULE_PATH_BENEATH, &path_attr,
			     LANDLOCK_ADD_RULE_SUPERVISED));

	EXPECT_EQ(0, close(dir_fd));

	child = fork();
	ASSERT_LE(0, child);

	if (child == 0) {
		/* Child: enforce ruleset and try to access file */
		int fd;

		EXPECT_EQ(0, close(supervisor_fd));

		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		ASSERT_EQ(0, syscall(__NR_landlock_restrict_self, ruleset_fd, 0));
		EXPECT_EQ(0, close(ruleset_fd));

		/* This should block until supervisor responds */
		fd = open(self->test_file, O_RDONLY);
		if (fd >= 0) {
			close(fd);
			_exit(0); /* Success: access allowed */
		} else {
			_exit(1); /* Failure: access denied */
		}
	}

	/* Parent: act as supervisor */
	EXPECT_EQ(0, close(ruleset_fd));

	/* Wait for request from child */
	{
		struct pollfd pfd = {
			.fd = supervisor_fd,
			.events = POLLIN,
		};
		ASSERT_EQ(1, poll(&pfd, 1, 5000)); /* 5 second timeout */
	}

	/* Read the request */
	{
		struct landlock_supervisor_request req;
		struct landlock_supervisor_response resp;
		ssize_t ret;

		ret = read(supervisor_fd, &req, sizeof(req));
		ASSERT_EQ(sizeof(req), ret);

		EXPECT_EQ(child, (pid_t)req.pid);
		EXPECT_EQ(LANDLOCK_RULE_PATH_BENEATH, req.rule_type);

		/* Allow the access */
		resp.id = req.id;
		resp.decision = LANDLOCK_DECISION_ALLOW;
		resp.flags = 0;

		ret = write(supervisor_fd, &resp, sizeof(resp));
		ASSERT_EQ(sizeof(resp), ret);
	}

	/* Wait for child to exit */
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_TRUE(WIFEXITED(status));
	EXPECT_EQ(0, WEXITSTATUS(status)); /* Access was allowed */

	EXPECT_EQ(0, close(supervisor_fd));
}

TEST_F(supervisor, basic_deny)
{
	struct landlock_supervisor_attr attr = {
		.ruleset_attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		.supervisor_fd = -1,
		.flags = 0,
	};
	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = 0,
	};
	int ruleset_fd, supervisor_fd, dir_fd;
	pid_t child;
	int status;

	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			     LANDLOCK_CREATE_RULESET_SUPERVISED);
	if (ruleset_fd < 0 && errno == EINVAL) {
		SKIP(return, "Supervised rulesets not supported");
	}
	ASSERT_LE(0, ruleset_fd);
	supervisor_fd = attr.supervisor_fd;
	ASSERT_LE(0, supervisor_fd);

	dir_fd = open(self->tmp_dir, O_PATH | O_DIRECTORY);
	ASSERT_LE(0, dir_fd);

	path_attr.parent_fd = dir_fd;

	ASSERT_EQ(0, syscall(__NR_landlock_add_rule, ruleset_fd,
			     LANDLOCK_RULE_PATH_BENEATH, &path_attr,
			     LANDLOCK_ADD_RULE_SUPERVISED));

	EXPECT_EQ(0, close(dir_fd));

	child = fork();
	ASSERT_LE(0, child);

	if (child == 0) {
		int fd;

		EXPECT_EQ(0, close(supervisor_fd));

		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		ASSERT_EQ(0, syscall(__NR_landlock_restrict_self, ruleset_fd, 0));
		EXPECT_EQ(0, close(ruleset_fd));

		fd = open(self->test_file, O_RDONLY);
		if (fd >= 0) {
			close(fd);
			_exit(0);
		} else {
			_exit(1); /* Expected: denied */
		}
	}

	EXPECT_EQ(0, close(ruleset_fd));

	{
		struct pollfd pfd = {
			.fd = supervisor_fd,
			.events = POLLIN,
		};
		ASSERT_EQ(1, poll(&pfd, 1, 5000));
	}

	{
		struct landlock_supervisor_request req;
		struct landlock_supervisor_response resp;
		ssize_t ret;

		ret = read(supervisor_fd, &req, sizeof(req));
		ASSERT_EQ(sizeof(req), ret);

		/* Deny the access */
		resp.id = req.id;
		resp.decision = LANDLOCK_DECISION_DENY;
		resp.flags = 0;

		ret = write(supervisor_fd, &resp, sizeof(resp));
		ASSERT_EQ(sizeof(resp), ret);
	}

	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_TRUE(WIFEXITED(status));
	EXPECT_EQ(1, WEXITSTATUS(status)); /* Access was denied */

	EXPECT_EQ(0, close(supervisor_fd));
}

TEST_F(supervisor, supervisor_close_denies_pending)
{
	struct landlock_supervisor_attr attr = {
		.ruleset_attr = {
			.handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE,
		},
		.supervisor_fd = -1,
		.flags = 0,
	};
	struct landlock_path_beneath_attr path_attr = {
		.allowed_access = 0,
	};
	int ruleset_fd, supervisor_fd, dir_fd;
	pid_t child;
	int status;

	ruleset_fd = syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr),
			     LANDLOCK_CREATE_RULESET_SUPERVISED);
	if (ruleset_fd < 0 && errno == EINVAL) {
		SKIP(return, "Supervised rulesets not supported");
	}
	ASSERT_LE(0, ruleset_fd);
	supervisor_fd = attr.supervisor_fd;
	ASSERT_LE(0, supervisor_fd);

	dir_fd = open(self->tmp_dir, O_PATH | O_DIRECTORY);
	ASSERT_LE(0, dir_fd);

	path_attr.parent_fd = dir_fd;

	ASSERT_EQ(0, syscall(__NR_landlock_add_rule, ruleset_fd,
			     LANDLOCK_RULE_PATH_BENEATH, &path_attr,
			     LANDLOCK_ADD_RULE_SUPERVISED));

	EXPECT_EQ(0, close(dir_fd));

	child = fork();
	ASSERT_LE(0, child);

	if (child == 0) {
		int fd;

		EXPECT_EQ(0, close(supervisor_fd));

		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		ASSERT_EQ(0, syscall(__NR_landlock_restrict_self, ruleset_fd, 0));
		EXPECT_EQ(0, close(ruleset_fd));

		/* This should block and then be denied when supervisor closes */
		fd = open(self->test_file, O_RDONLY);
		if (fd >= 0) {
			close(fd);
			_exit(0);
		} else {
			_exit(1); /* Expected: denied */
		}
	}

	EXPECT_EQ(0, close(ruleset_fd));

	/* Wait for request to be pending */
	{
		struct pollfd pfd = {
			.fd = supervisor_fd,
			.events = POLLIN,
		};
		ASSERT_EQ(1, poll(&pfd, 1, 5000));
	}

	/* Close supervisor fd without responding - should deny all pending */
	EXPECT_EQ(0, close(supervisor_fd));

	/* Child should be denied */
	ASSERT_EQ(child, waitpid(child, &status, 0));
	EXPECT_TRUE(WIFEXITED(status));
	EXPECT_EQ(1, WEXITSTATUS(status));
}

TEST_HARNESS_MAIN
