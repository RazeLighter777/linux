// SPDX-License-Identifier: BSD-3-Clause
/*
 * Simple Landlock sandbox manager able to execute a process restricted by
 * user-defined file system and network access control policies.
 *
 * Copyright © 2017-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2020 ANSSI
 */

#define _GNU_SOURCE
#define __SANE_USERSPACE_TYPES__
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <linux/socket.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdbool.h>

#if defined(__GLIBC__)
#include <linux/prctl.h>
#endif

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
			const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
				    const enum landlock_rule_type rule_type,
				    const void *const rule_attr,
				    const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
		       flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
					 const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define ENV_FS_RO_NAME "LL_FS_RO"
#define ENV_FS_RW_NAME "LL_FS_RW"
#define ENV_FS_QUIET_NAME "LL_FS_QUIET"
#define ENV_FS_QUIET_ACCESS_NAME "LL_FS_QUIET_ACCESS"
#define ENV_FS_NO_INHERIT_NAME "LL_FS_NO_INHERIT"
#define ENV_TCP_BIND_NAME "LL_TCP_BIND"
#define ENV_TCP_CONNECT_NAME "LL_TCP_CONNECT"
#define ENV_NET_QUIET_NAME "LL_NET_QUIET"
#define ENV_NET_QUIET_ACCESS_NAME "LL_NET_QUIET_ACCESS"
#define ENV_SCOPED_NAME "LL_SCOPED"
#define ENV_SCOPED_QUIET_ACCESS_NAME "LL_SCOPED_QUIET_ACCESS"
#define ENV_FORCE_LOG_NAME "LL_FORCE_LOG"
#define ENV_DELIMITER ":"

struct ll_allow_rule {
	char *path;
	__u32 access;
};

struct ll_allow_entry {
	char *exe;
	struct ll_allow_rule *rules;
	size_t num_rules;
	size_t cap_rules;
	int ruleset_fd;
};

struct ll_allow_state {
	struct ll_allow_entry *entries;
	size_t num_entries;
	size_t cap_entries;
};

static void ll_allow_state_destroy(struct ll_allow_state *st)
{
	size_t i, j;

	if (!st)
		return;
	for (i = 0; i < st->num_entries; i++) {
		struct ll_allow_entry *e = &st->entries[i];

		for (j = 0; j < e->num_rules; j++)
			free(e->rules[j].path);
		free(e->rules);
		free(e->exe);
		if (e->ruleset_fd >= 0)
			close(e->ruleset_fd);
	}
	free(st->entries);
	memset(st, 0, sizeof(*st));
}

static char *ll_readlink_alloc(const char *path)
{
	char buf[4096];
	ssize_t n;

	n = readlink(path, buf, sizeof(buf) - 1);
	if (n < 0)
		return NULL;
	buf[n] = '\0';
	return strdup(buf);
}

static int ll_allow_get_entry(struct ll_allow_state *st, const char *exe,
			      struct ll_allow_entry **out)
{
	size_t i;

	for (i = 0; i < st->num_entries; i++) {
		if (strcmp(st->entries[i].exe, exe) == 0) {
			*out = &st->entries[i];
			return 0;
		}
	}

	if (st->num_entries == st->cap_entries) {
		size_t new_cap = st->cap_entries ? st->cap_entries * 2 : 4;
		void *p = realloc(st->entries, new_cap * sizeof(*st->entries));
		if (!p)
			return -1;
		st->entries = p;
		st->cap_entries = new_cap;
	}

	st->entries[st->num_entries] = (struct ll_allow_entry){
		.exe = strdup(exe),
		.ruleset_fd = -1,
	};
	if (!st->entries[st->num_entries].exe)
		return -1;

	*out = &st->entries[st->num_entries++];
	return 0;
}

static int ll_allow_entry_add_rule(struct ll_allow_entry *e,
				 const char *path, __u32 access)
{
	if (e->num_rules == e->cap_rules) {
		size_t new_cap = e->cap_rules ? e->cap_rules * 2 : 8;
		void *p = realloc(e->rules, new_cap * sizeof(*e->rules));
		if (!p)
			return -1;
		e->rules = p;
		e->cap_rules = new_cap;
	}
	e->rules[e->num_rules].path = strdup(path);
	if (!e->rules[e->num_rules].path)
		return -1;
	e->rules[e->num_rules].access = access;
	e->num_rules++;
	return 0;
}

static int ll_build_exec_allow_ruleset(const struct ll_allow_entry *e,
				     int *out_fd)
{
	const __u64 fs_all =
		LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_READ_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_DIR |
		LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR |
		LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG |
		LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO |
		LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM |
		LANDLOCK_ACCESS_FS_REFER |
		LANDLOCK_ACCESS_FS_TRUNCATE |
		LANDLOCK_ACCESS_FS_IOCTL_DEV;
	const __u64 fs_file_only =
		LANDLOCK_ACCESS_FS_EXECUTE |
		LANDLOCK_ACCESS_FS_WRITE_FILE |
		LANDLOCK_ACCESS_FS_READ_FILE |
		LANDLOCK_ACCESS_FS_TRUNCATE |
		LANDLOCK_ACCESS_FS_IOCTL_DEV;
	struct landlock_ruleset_attr attr = {
		.handled_access_fs = fs_all,
		.handled_access_net = 0,
		.scoped = 0,
		.quiet_access_fs = fs_all,
		.quiet_access_net = 0,
		.quiet_scoped = 0,
	};
	int fd;
	size_t i;
	int exec_fd = -1;
	struct landlock_supervisor_tag_attr tag = {
		.type = LANDLOCK_SUPERVISOR_TAG_EXEC_DENTRY,
		.exec_fd = -1,
	};
	struct landlock_supervisor_ruleset_tags_attr tags_attr = {
		.size = sizeof(tags_attr),
		.ruleset_fd = -1,
		.num_tags = 1,
		.tags = (__u64)(uintptr_t)&tag,
	};

	fd = landlock_create_ruleset(&attr, sizeof(attr), 0);
	if (fd < 0) {
		perror("landlock_create_ruleset(exec-allow)");
		return -1;
	}

	for (i = 0; i < e->num_rules; i++) {
		struct landlock_path_beneath_attr pb = {
			.parent_fd = -1,
			.allowed_access = e->rules[i].access,
		};
		struct stat st;

		pb.parent_fd = open(e->rules[i].path, O_PATH | O_CLOEXEC);
		if (pb.parent_fd < 0)
			continue;
		if (fstat(pb.parent_fd, &st) != 0) {
			close(pb.parent_fd);
			continue;
		}
		if (!S_ISDIR(st.st_mode))
			pb.allowed_access &= fs_file_only;
		if (landlock_add_rule(fd, LANDLOCK_RULE_PATH_BENEATH, &pb,
				      LANDLOCK_ADD_RULE_QUIET) != 0) {
			perror("landlock_add_rule(exec-allow)");
			close(pb.parent_fd);
			close(fd);
			return -1;
		}
		close(pb.parent_fd);
	}

	exec_fd = open(e->exe, O_PATH | O_CLOEXEC);
	if (exec_fd < 0) {
		fprintf(stderr, "Failed to open exe O_PATH '%s': %s\n",
			e->exe, strerror(errno));
		close(fd);
		return -1;
	}

	tag.exec_fd = exec_fd;
	tags_attr.ruleset_fd = fd;
	fprintf(stderr,
		"Installing exec-allow ruleset_fd=%d exec_fd=%d exe='%s'\n",
		fd, exec_fd, e->exe);
	if (ioctl(fd, LANDLOCK_IOC_SUPERVISOR_SET_TAGS, &tags_attr) != 0) {
		fprintf(stderr,
			"LANDLOCK_IOC_SUPERVISOR_SET_TAGS(exec-allow) failed: errno=%d (%s)\n",
			errno, strerror(errno));
		close(exec_fd);
		close(fd);
		return -1;
	}
	close(exec_fd);

	*out_fd = fd;
	return 0;
}

static int ll_install_exec_allow_ruleset(struct ll_allow_entry *e)
{
	int new_fd;

	if (ll_build_exec_allow_ruleset(e, &new_fd) != 0)
		return -1;

	if (e->ruleset_fd < 0) {
		e->ruleset_fd = new_fd;
		return 0;
	}

	{
		struct landlock_supervisor_ruleset_swap_attr swap = {
			.size = sizeof(swap),
			.old_ruleset_fd = e->ruleset_fd,
			.new_ruleset_fd = new_fd,
		};
		if (ioctl(e->ruleset_fd, LANDLOCK_IOC_SUPERVISOR_SWAP_RULESET, &swap) != 0) {
			fprintf(stderr,
				"LANDLOCK_IOC_SUPERVISOR_SWAP_RULESET(exec-allow) failed: errno=%d (%s)\n",
				errno, strerror(errno));
			close(new_fd);
			return -1;
		}
	}

	close(e->ruleset_fd);
	e->ruleset_fd = new_fd;
	return 0;
}

static int str2num(const char *numstr, __u64 *num_dst)
{
	char *endptr = NULL;
	int err = 0;
	__u64 num;

	errno = 0;
	num = strtoull(numstr, &endptr, 10);
	if (errno != 0)
		err = errno;
	/* Was the string empty, or not entirely parsed successfully? */
	else if ((*numstr == '\0') || (*endptr != '\0'))
		err = EINVAL;
	else
		*num_dst = num;

	return err;
}

static int parse_path(char *env_path, const char ***const path_list)
{
	int i, num_paths = 0;

	if (env_path) {
		num_paths++;
		for (i = 0; env_path[i]; i++) {
			if (env_path[i] == ENV_DELIMITER[0])
				num_paths++;
		}
	}
	*path_list = malloc(num_paths * sizeof(**path_list));
	if (!*path_list)
		return -1;

	for (i = 0; i < num_paths; i++)
		(*path_list)[i] = strsep(&env_path, ENV_DELIMITER);

	return num_paths;
}

/* clang-format off */

#define ACCESS_FILE ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

/* clang-format on */

static int populate_ruleset_fs(const char *const env_var, const int ruleset_fd,
			       const __u64 allowed_access, __u32 flags)
{
	int num_paths, i, ret = 1;
	char *env_path_name;
	const char **path_list = NULL;
	struct landlock_path_beneath_attr path_beneath = {
		.parent_fd = -1,
	};

	env_path_name = getenv(env_var);
	if (!env_path_name) {
		/* Prevents users to forget a setting. */
		fprintf(stderr, "Missing environment variable %s\n", env_var);
		return 1;
	}
	env_path_name = strdup(env_path_name);
	unsetenv(env_var);
	num_paths = parse_path(env_path_name, &path_list);
	if (num_paths < 0) {
		fprintf(stderr, "Failed to allocate memory\n");
		goto out_free_name;
	}
	if (num_paths == 1 && path_list[0][0] == '\0') {
		/*
		 * Allows to not use all possible restrictions (e.g. use
		 * LL_FS_RO without LL_FS_RW).
		 */
		ret = 0;
		goto out_free_name;
	}

	for (i = 0; i < num_paths; i++) {
		struct stat statbuf;

		path_beneath.parent_fd = open(path_list[i], O_PATH | O_CLOEXEC);
		if (path_beneath.parent_fd < 0) {
			fprintf(stderr, "Failed to open \"%s\": %s\n",
				path_list[i], strerror(errno));
			continue;
		}
		if (fstat(path_beneath.parent_fd, &statbuf)) {
			fprintf(stderr, "Failed to stat \"%s\": %s\n",
				path_list[i], strerror(errno));
			close(path_beneath.parent_fd);
			goto out_free_name;
		}
		path_beneath.allowed_access = allowed_access;
		if (!S_ISDIR(statbuf.st_mode))
			path_beneath.allowed_access &= ACCESS_FILE;
		if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				      &path_beneath, flags)) {
			fprintf(stderr,
				"Failed to update the ruleset with \"%s\": %s\n",
				path_list[i], strerror(errno));
			close(path_beneath.parent_fd);
			goto out_free_name;
		}
		close(path_beneath.parent_fd);
	}
	ret = 0;

out_free_name:
	free(path_list);
	free(env_path_name);
	return ret;
}

static int populate_ruleset_net(const char *const env_var, const int ruleset_fd,
				const __u64 allowed_access, __u32 flags)
{
	int ret = 1;
	char *env_port_name, *env_port_name_next, *strport;
	struct landlock_net_port_attr net_port = {
		.allowed_access = allowed_access,
	};

	env_port_name = getenv(env_var);
	if (!env_port_name)
		return 0;
	env_port_name = strdup(env_port_name);
	unsetenv(env_var);

	env_port_name_next = env_port_name;
	while ((strport = strsep(&env_port_name_next, ENV_DELIMITER))) {
		__u64 port;

		if (strcmp(strport, "") == 0)
			continue;

		if (str2num(strport, &port)) {
			fprintf(stderr, "Failed to parse port at \"%s\"\n",
				strport);
			goto out_free_name;
		}
		net_port.port = port;
		if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT,
				      &net_port, flags)) {
			fprintf(stderr,
				"Failed to update the ruleset with port \"%llu\": %s\n",
				net_port.port, strerror(errno));
			goto out_free_name;
		}
	}
	ret = 0;

out_free_name:
	free(env_port_name);
	return ret;
}

/* Returns true on error, false otherwise. */
static bool check_ruleset_scope(const char *const env_var,
				struct landlock_ruleset_attr *ruleset_attr)
{
	char *env_type_scope, *env_type_scope_next, *ipc_scoping_name;
	bool error = false;
	bool abstract_scoping = false;
	bool signal_scoping = false;

	/* Scoping is not supported by Landlock ABI */
	if (!(ruleset_attr->scoped &
	      (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL)))
		goto out_unset;

	env_type_scope = getenv(env_var);
	/* Scoping is not supported by the user */
	if (!env_type_scope || strcmp("", env_type_scope) == 0)
		goto out_unset;

	env_type_scope = strdup(env_type_scope);
	env_type_scope_next = env_type_scope;
	while ((ipc_scoping_name =
			strsep(&env_type_scope_next, ENV_DELIMITER))) {
		if (strcmp("a", ipc_scoping_name) == 0 && !abstract_scoping) {
			abstract_scoping = true;
		} else if (strcmp("s", ipc_scoping_name) == 0 &&
			   !signal_scoping) {
			signal_scoping = true;
		} else {
			fprintf(stderr, "Unknown or duplicate scope \"%s\"\n",
				ipc_scoping_name);
			error = true;
			goto out_free_name;
		}
	}

out_free_name:
	free(env_type_scope);

out_unset:
	if (!abstract_scoping)
		ruleset_attr->scoped &= ~LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
	if (!signal_scoping)
		ruleset_attr->scoped &= ~LANDLOCK_SCOPE_SIGNAL;

	unsetenv(env_var);
	return error;
}

/* clang-format off */

#define ACCESS_FS_ROUGHLY_READ ( \
	LANDLOCK_ACCESS_FS_EXECUTE | \
	LANDLOCK_ACCESS_FS_READ_FILE | \
	LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
	LANDLOCK_ACCESS_FS_WRITE_FILE | \
	LANDLOCK_ACCESS_FS_REMOVE_DIR | \
	LANDLOCK_ACCESS_FS_REMOVE_FILE | \
	LANDLOCK_ACCESS_FS_MAKE_CHAR | \
	LANDLOCK_ACCESS_FS_MAKE_DIR | \
	LANDLOCK_ACCESS_FS_MAKE_REG | \
	LANDLOCK_ACCESS_FS_MAKE_SOCK | \
	LANDLOCK_ACCESS_FS_MAKE_FIFO | \
	LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
	LANDLOCK_ACCESS_FS_MAKE_SYM | \
	LANDLOCK_ACCESS_FS_REFER | \
	LANDLOCK_ACCESS_FS_TRUNCATE | \
	LANDLOCK_ACCESS_FS_IOCTL_DEV)

/* clang-format on */

static int add_quiet_access(__u64 *const quiet_access,
			    const __u64 handled_access,
			    const char *const env_var, const bool default_all)
{
	char *env_quiet_access, *env_quiet_access_next, *str_access;

	if (default_all)
		*quiet_access = handled_access;
	else
		*quiet_access = 0;

	env_quiet_access = getenv(env_var);
	if (!env_quiet_access)
		return 0;

	env_quiet_access = strdup(env_quiet_access);
	env_quiet_access_next = env_quiet_access;
	unsetenv(env_var);
	*quiet_access = 0;

	while ((str_access = strsep(&env_quiet_access_next, ENV_DELIMITER))) {
		if (strcmp(str_access, "") == 0)
			continue;
		else if (strcmp(str_access, "r") == 0)
			*quiet_access |= ACCESS_FS_ROUGHLY_READ;
		else if (strcmp(str_access, "w") == 0)
			*quiet_access |= ACCESS_FS_ROUGHLY_WRITE;
		else if (strcmp(str_access, "b") == 0)
			*quiet_access |= LANDLOCK_ACCESS_NET_BIND_TCP;
		else if (strcmp(str_access, "c") == 0)
			*quiet_access |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
		else if (strcmp(str_access, "a") == 0)
			*quiet_access |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
		else if (strcmp(str_access, "s") == 0)
			*quiet_access |= LANDLOCK_SCOPE_SIGNAL;
		else {
			fprintf(stderr, "Unknown quiet access \"%s\"\n",
				str_access);
			free(env_quiet_access);
			return -1;
		}
	}

	free(env_quiet_access);
	*quiet_access &= handled_access;
	return 0;
}

#define LANDLOCK_ABI_LAST 8

#define XSTR(s) #s
#define STR(s) XSTR(s)

/* clang-format off */

static const char help[] =
	"usage: " ENV_FS_RO_NAME "=\"...\" " ENV_FS_RW_NAME "=\"...\" "
	"[other environment variables] %1$s <cmd> [args]...\n"
	"\n"
	"Execute the given command in a restricted environment.\n"
	"Multi-valued settings (lists of ports, paths, scopes) are colon-delimited.\n"
	"\n"
	"Mandatory settings:\n"
	"* " ENV_FS_RO_NAME ": paths allowed to be used in a read-only way\n"
	"* " ENV_FS_RW_NAME ": paths allowed to be used in a read-write way\n"
	"\n"
	"Optional settings (when not set, their associated access check "
	"is always allowed, which is different from an empty string which "
	"means an empty list):\n"
	"* " ENV_TCP_BIND_NAME ": ports allowed to bind (server)\n"
	"* " ENV_TCP_CONNECT_NAME ": ports allowed to connect (client)\n"
	"* " ENV_SCOPED_NAME ": actions denied on the outside of the landlock domain\n"
	"  - \"a\" to restrict opening abstract unix sockets\n"
	"  - \"s\" to restrict sending signals\n"
	"\n"
	"A sandboxer should not log denied access requests to avoid spamming logs, "
	"but to test audit we can set " ENV_FORCE_LOG_NAME "=1\n"
	ENV_FS_QUIET_NAME " and " ENV_NET_QUIET_NAME ", both optional, can then be used "
	"to make access to some denied paths or network ports not trigger audit logging.\n"
	ENV_FS_NO_INHERIT_NAME " can be used to suppress access right propagation (ABI >= 8).\n"
	ENV_FS_QUIET_ACCESS_NAME " and " ENV_NET_QUIET_ACCESS_NAME " can be used to specify "
	"which accesses should be quieted (defaults to all):\n"
	"* " ENV_FS_QUIET_ACCESS_NAME ": file system accesses to quiet\n"
	"  - \"r\" to quiet all file/dir read accesses\n"
	"  - \"w\" to quiet all file/dir write accesses\n"
	"* " ENV_NET_QUIET_ACCESS_NAME ": network accesses to quiet\n"
	"  - \"b\" to quiet bind denials\n"
	"  - \"c\" to quiet connect denials\n"
	"In addition, " ENV_SCOPED_QUIET_ACCESS_NAME " can be set to quiet all denials for "
	"scoped actions (defaults to none).\n"
	"  - \"a\" to quiet abstract unix socket denials\n"
	"  - \"s\" to quiet signal denials\n"
	"\n"
	"Example:\n"
	ENV_FS_RO_NAME "=\"${PATH}:/lib:/usr:/proc:/etc:/dev/urandom\" "
	ENV_FS_RW_NAME "=\"/dev/null:/dev/full:/dev/zero:/dev/pts:/tmp\" "
	ENV_TCP_BIND_NAME "=\"9418\" "
	ENV_TCP_CONNECT_NAME "=\"80:443\" "
	ENV_SCOPED_NAME "=\"a:s\" "
	"%1$s bash -i\n"
	"\n"
	"This sandboxer can use Landlock features up to ABI version "
	STR(LANDLOCK_ABI_LAST) ".\n";

/* clang-format on */

int main(const int argc, char *const argv[], char *const *const envp)
{
	const char *cmd_path;
	char *const *cmd_argv;
	int ruleset_fd, abi;
	int cmd_index = 1;
	bool supervise = false;
	char *env_port_name, *env_force_log;
	__u64 access_fs_ro = ACCESS_FS_ROUGHLY_READ,
	      access_fs_rw = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE;

	struct landlock_ruleset_attr ruleset_attr = {
		.handled_access_fs = access_fs_rw,
		.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP |
				      LANDLOCK_ACCESS_NET_CONNECT_TCP,
		.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
			  LANDLOCK_SCOPE_SIGNAL,
		.quiet_access_fs = 0,
		.quiet_access_net = 0,
		.quiet_scoped = 0,
	};

	bool quiet_supported = true;
	bool no_inherit_supported = true;
	int supported_restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
	int set_restrict_flags = 0;

	if (argc >= 2 && strcmp(argv[1], "--supervise") == 0) {
		supervise = true;
		cmd_index++;
	}

	if (argc <= cmd_index) {
		fprintf(stderr, help, argv[0]);
		return 1;
	}

	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		const int err = errno;

		perror("Failed to check Landlock compatibility");
		switch (err) {
		case ENOSYS:
			fprintf(stderr,
				"Hint: Landlock is not supported by the current kernel. "
				"To support it, build the kernel with "
				"CONFIG_SECURITY_LANDLOCK=y and prepend "
				"\"landlock,\" to the content of CONFIG_LSM.\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr,
				"Hint: Landlock is currently disabled. "
				"It can be enabled in the kernel configuration by "
				"prepending \"landlock,\" to the content of CONFIG_LSM, "
				"or at boot time by setting the same content to the "
				"\"lsm\" kernel parameter.\n");
			break;
		}
		return 1;
	}

	/* Best-effort security. */
	switch (abi) {
	case 1:
		/*
		 * Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2
		 *
		 * Note: The "refer" operations (file renaming and linking
		 * across different directories) are always forbidden when using
		 * Landlock with ABI 1.
		 *
		 * If only ABI 1 is available, this sandboxer knowingly forbids
		 * refer operations.
		 *
		 * If a program *needs* to do refer operations after enabling
		 * Landlock, it can not use Landlock at ABI level 1.  To be
		 * compatible with different kernel versions, such programs
		 * should then fall back to not restrict themselves at all if
		 * the running kernel only supports ABI 1.
		 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
		__attribute__((fallthrough));
	case 2:
		/* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
		__attribute__((fallthrough));
	case 3:
		/* Removes network support for ABI < 4 */
		ruleset_attr.handled_access_net &=
			~(LANDLOCK_ACCESS_NET_BIND_TCP |
			  LANDLOCK_ACCESS_NET_CONNECT_TCP);
		__attribute__((fallthrough));
	case 4:
		/* Removes LANDLOCK_ACCESS_FS_IOCTL_DEV for ABI < 5 */
		ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;

		__attribute__((fallthrough));
	case 5:
		/* Removes LANDLOCK_SCOPE_* for ABI < 6 */
		ruleset_attr.scoped &= ~(LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET |
					 LANDLOCK_SCOPE_SIGNAL);
		__attribute__((fallthrough));
	case 6:
		/* Removes LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON for ABI < 7 */
		supported_restrict_flags &=
			~LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;

		/* Must be printed for any ABI < LANDLOCK_ABI_LAST. */
		fprintf(stderr,
			"Hint: You should update the running kernel "
			"to leverage Landlock features "
			"provided by ABI version %d (instead of %d).\n",
			LANDLOCK_ABI_LAST, abi);
		__attribute__((fallthrough));
	case 7:
		/* Don't add quiet/no_inherit flags for ABI < 8 later on. */
		quiet_supported = false;
		no_inherit_supported = false;

		__attribute__((fallthrough));
	case LANDLOCK_ABI_LAST:
		break;
	default:
		fprintf(stderr,
			"Hint: You should update this sandboxer "
			"to leverage Landlock features "
			"provided by ABI version %d (instead of %d).\n",
			abi, LANDLOCK_ABI_LAST);
	}
	access_fs_ro &= ruleset_attr.handled_access_fs;
	access_fs_rw &= ruleset_attr.handled_access_fs;

	/* Removes bind access attribute if not supported by a user. */
	env_port_name = getenv(ENV_TCP_BIND_NAME);
	if (!env_port_name) {
		ruleset_attr.handled_access_net &=
			~LANDLOCK_ACCESS_NET_BIND_TCP;
	}
	/* Removes connect access attribute if not supported by a user. */
	env_port_name = getenv(ENV_TCP_CONNECT_NAME);
	if (!env_port_name) {
		ruleset_attr.handled_access_net &=
			~LANDLOCK_ACCESS_NET_CONNECT_TCP;
	}

	if (check_ruleset_scope(ENV_SCOPED_NAME, &ruleset_attr))
		return 1;

	/* Enables optional logs. */
	env_force_log = getenv(ENV_FORCE_LOG_NAME);
	if (env_force_log) {
		if (strcmp(env_force_log, "1") != 0) {
			fprintf(stderr, "Unknown value for " ENV_FORCE_LOG_NAME
					" (only \"1\" is handled)\n");
			return 1;
		}
		if (!(supported_restrict_flags &
		      LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON)) {
			fprintf(stderr,
				"Audit logs not supported by current kernel\n");
			return 1;
		}
		set_restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
		unsetenv(ENV_FORCE_LOG_NAME);
	}

	/*
	 * Add quiet for fs/net handled access bits.  Doing this alone has no
	 * effect unless we later add quiet rules per FS_QUIET/NET_QUIET.
	 */
	if (quiet_supported) {
		if (add_quiet_access(&ruleset_attr.quiet_access_fs,
				     ruleset_attr.handled_access_fs,
				     ENV_FS_QUIET_ACCESS_NAME, true))
			return 1;
		if (add_quiet_access(&ruleset_attr.quiet_access_net,
				     ruleset_attr.handled_access_net,
				     ENV_NET_QUIET_ACCESS_NAME, true))
			return 1;
		if (add_quiet_access(&ruleset_attr.quiet_scoped,
				     ruleset_attr.scoped,
				     ENV_SCOPED_QUIET_ACCESS_NAME, false))
			return 1;
	}

	ruleset_fd =
		landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		perror("Failed to create a ruleset");
		return 1;
	}

	if (populate_ruleset_fs(ENV_FS_RO_NAME, ruleset_fd, access_fs_ro, 0))
		goto err_close_ruleset;
	if (populate_ruleset_fs(ENV_FS_RW_NAME, ruleset_fd, access_fs_rw, 0))
		goto err_close_ruleset;

	/* Don't require this env to be present. */
	if (quiet_supported && getenv(ENV_FS_QUIET_NAME)) {
		if (populate_ruleset_fs(ENV_FS_QUIET_NAME, ruleset_fd, 0,
					LANDLOCK_ADD_RULE_QUIET))
			goto err_close_ruleset;
	}

	/* Don't require this env to be present. */
	if (no_inherit_supported && getenv(ENV_FS_NO_INHERIT_NAME)) {
		if (populate_ruleset_fs(ENV_FS_NO_INHERIT_NAME, ruleset_fd, 0,
					LANDLOCK_ADD_RULE_NO_INHERIT))
			goto err_close_ruleset;
	}

	if (populate_ruleset_net(ENV_TCP_BIND_NAME, ruleset_fd,
				 LANDLOCK_ACCESS_NET_BIND_TCP, 0)) {
		goto err_close_ruleset;
	}
	if (populate_ruleset_net(ENV_TCP_CONNECT_NAME, ruleset_fd,
				 LANDLOCK_ACCESS_NET_CONNECT_TCP, 0)) {
		goto err_close_ruleset;
	}

	/* Don't require this env to be present. */
	if (quiet_supported && getenv(ENV_NET_QUIET_NAME)) {
		if (populate_ruleset_net(ENV_NET_QUIET_NAME, ruleset_fd, 0,
					 LANDLOCK_ADD_RULE_QUIET)) {
			goto err_close_ruleset;
		}
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Failed to restrict privileges");
		goto err_close_ruleset;
	}
	if (landlock_restrict_self(ruleset_fd, set_restrict_flags)) {
		perror("Failed to enforce ruleset");
		goto err_close_ruleset;
	}

	cmd_path = argv[cmd_index];
	cmd_argv = argv + cmd_index;

	if (!supervise) {
		close(ruleset_fd);
		fprintf(stderr, "Executing the sandboxed command...\n");
		execvpe(cmd_path, cmd_argv, envp);
		fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
			strerror(errno));
		fprintf(stderr,
			"Hint: access to the binary, the interpreter or "
			"shared libraries may be denied.\n");
		return 1;
	}

	/* Supervise mode: match everything with TAG_NONE and ask per access. */
	{
		int efd;
		pid_t child;
		int child_status = 0;
		struct landlock_supervisor_tag_attr tag = {
			.type = LANDLOCK_SUPERVISOR_TAG_NONE,
		};
		struct landlock_supervisor_ruleset_tags_attr tags_attr = {
			.size = sizeof(tags_attr),
			.ruleset_fd = ruleset_fd,
			.num_tags = 1,
			.tags = (__u64)(uintptr_t)&tag,
		};
		struct landlock_supervisor_listen_attr listen_attr = {
			.size = sizeof(listen_attr),
			.event_fd = -1,
		};

		efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (efd < 0) {
			perror("eventfd");
			goto err_close_ruleset;
		}
		listen_attr.event_fd = efd;
		if (ioctl(ruleset_fd, LANDLOCK_IOC_SUPERVISOR_LISTEN, &listen_attr)) {
			perror("LANDLOCK_IOC_SUPERVISOR_LISTEN");
			close(efd);
			goto err_close_ruleset;
		}
		if (ioctl(ruleset_fd, LANDLOCK_IOC_SUPERVISOR_SET_TAGS, &tags_attr)) {
			perror("LANDLOCK_IOC_SUPERVISOR_SET_TAGS");
			close(efd);
			goto err_close_ruleset;
		}

		child = fork();
		if (child < 0) {
			perror("fork");
			close(efd);
			goto err_close_ruleset;
		}
		if (child == 0) {
			fprintf(stderr, "Executing the sandboxed command (supervised)...\n");
			execvpe(cmd_path, cmd_argv, envp);
			fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
				strerror(errno));
			_exit(127);
		}

		{
			struct ll_allow_state allow_state = {
				.entries = NULL,
				.num_entries = 0,
				.cap_entries = 0,
			};

			for (;;) {
			struct pollfd pfd = {
				.fd = efd,
				.events = POLLIN,
			};
			int status;
			int pret;
			__u64 n;
			ssize_t r;

			if (waitpid(child, &status, WNOHANG) == child) {
				child_status = status;
				break;
			}

			pret = poll(&pfd, 1, 250);
			if (pret < 0) {
				if (errno == EINTR)
					continue;
				perror("poll(eventfd)");
				goto out_kill_child;
			}
			if (pret == 0)
				continue;
			if (!(pfd.revents & POLLIN))
				continue;

			r = read(efd, &n, sizeof(n));
			if (r < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				perror("read(eventfd)");
				goto out_kill_child;
			}
			while (n--) {
				struct landlock_supervisor_event ev = {
					.size = sizeof(ev),
				};
				struct landlock_supervisor_decide_attr dec = {
					.size = sizeof(dec),
					.decision = LANDLOCK_SUPERVISOR_DECISION_DENY,
				};
				char line[16];
				bool allow = false;
				bool persist_allow = false;

				if (ioctl(ruleset_fd, LANDLOCK_IOC_SUPERVISOR_RECV, &ev)) {
					if (errno == EAGAIN)
						break;
					perror("LANDLOCK_IOC_SUPERVISOR_RECV");
					break;
				}

				if (ev.type == LANDLOCK_SUPERVISOR_EVENT_FS) {
					fprintf(stderr,
						"Allow FS access 0x%x on %s (pid=%u)? [y/N/a] ",
						ev.access,
						ev.path[0] ? ev.path : "<unknown>",
						ev.pid);
				} else if (ev.type == LANDLOCK_SUPERVISOR_EVENT_SIGNAL) {
					fprintf(stderr,
						"Allow SIGNAL %u %s (pid=%u)? [y/N] ",
						ev.access,
						ev.path[0] ? ev.path : "",
						ev.pid);
				} else {
					fprintf(stderr,
						"Allow event type=%u access=0x%x (pid=%u)? [y/N] ",
						ev.type, ev.access, ev.pid);
				}
				fflush(stderr);

				if (fgets(line, sizeof(line), stdin)) {
					allow = (line[0] == 'y' || line[0] == 'Y');
					persist_allow = (line[0] == 'a' || line[0] == 'A');
					if (persist_allow)
						allow = true;
				}

				if (persist_allow && ev.type == LANDLOCK_SUPERVISOR_EVENT_FS &&
					ev.path[0]) {
					char proc_exe[64];
					char *exe = NULL;
					struct ll_allow_entry *entry;
					bool is_exec = !!(ev.access & LANDLOCK_ACCESS_FS_EXECUTE);

					/*
					 * For execve-related events, the requesting task may still be
					 * running landlock-sandboxer, so tag by the target executable.
					 * Otherwise tag by the requesting task executable.
					 */
					if (is_exec) {
						exe = strdup(ev.path);
					} else {
						snprintf(proc_exe, sizeof(proc_exe), "/proc/%u/exe", ev.pid);
						exe = ll_readlink_alloc(proc_exe);
					}
					if (!exe) {
						fprintf(stderr,
							"Failed to resolve exe tag: %s\n",
							strerror(errno));
					} else if (ll_allow_get_entry(&allow_state, exe, &entry) != 0) {
						fprintf(stderr, "Failed to allocate allowlist entry\n");
						free(exe);
					} else {
						if (ll_allow_entry_add_rule(entry, ev.path, ev.access) != 0) {
							fprintf(stderr, "Failed to record allow rule\n");
						} else if (ll_install_exec_allow_ruleset(entry) != 0) {
							fprintf(stderr,
								"Failed to install exec allow ruleset for %s\n",
								exe);
						}
						free(exe);
					}
				}

				dec.id = ev.id;
				dec.decision = allow ? LANDLOCK_SUPERVISOR_DECISION_ALLOW
						    : LANDLOCK_SUPERVISOR_DECISION_DENY;
				if (ioctl(ruleset_fd, LANDLOCK_IOC_SUPERVISOR_DECIDE, &dec)) {
					perror("LANDLOCK_IOC_SUPERVISOR_DECIDE");
					goto out_kill_child;
				}
			}
		}
		ll_allow_state_destroy(&allow_state);
		}
		close(efd);
		close(ruleset_fd);
		if (WIFEXITED(child_status))
			return WEXITSTATUS(child_status);
		if (WIFSIGNALED(child_status))
			return 128 + WTERMSIG(child_status);
		return 1;

out_kill_child:
		kill(child, SIGKILL);
		waitpid(child, &child_status, 0);
		close(efd);
	}

	close(ruleset_fd);
	return 1;

err_close_ruleset:
	close(ruleset_fd);
	return 1;
}
