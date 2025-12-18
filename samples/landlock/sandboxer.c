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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <poll.h>
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

#define ENV_SUPERVISE_NAME "LL_SUPERVISE"
#define ENV_SUPERVISE_DEFAULT_NAME "LL_SUPERVISE_DEFAULT"
#define ENV_SUPERVISE_PROMPT_ONCE_NAME "LL_SUPERVISE_PROMPT_ONCE"

enum supervise_default {
	SUP_DEFAULT_ASK = 0,
	SUP_DEFAULT_ALLOW,
	SUP_DEFAULT_DENY,
};

struct fs_rule_record {
	char *path;
	__u64 allowed_access;
	__u32 flags;
};

struct net_rule_record {
	__u64 port;
	__u64 allowed_access;
	__u32 flags;
};

struct rule_records {
	struct fs_rule_record *fs;
	size_t fs_len;
	size_t fs_cap;
	struct net_rule_record *net;
	size_t net_len;
	size_t net_cap;
};

static void free_rule_records(struct rule_records *records)
{
	size_t i;

	if (!records)
		return;

	for (i = 0; i < records->fs_len; i++)
		free(records->fs[i].path);
	free(records->fs);
	free(records->net);
	memset(records, 0, sizeof(*records));
}

static int push_fs_rule(struct rule_records *records, const char *path,
			__u64 allowed_access, __u32 flags)
{
	struct fs_rule_record *new_fs;

	if (!records)
		return 0;

	if (records->fs_len == records->fs_cap) {
		size_t new_cap = records->fs_cap ? records->fs_cap * 2 : 8;

		new_fs = realloc(records->fs, new_cap * sizeof(*new_fs));
		if (!new_fs)
			return -1;
		records->fs = new_fs;
		records->fs_cap = new_cap;
	}

	records->fs[records->fs_len].path = strdup(path);
	if (!records->fs[records->fs_len].path)
		return -1;
	records->fs[records->fs_len].allowed_access = allowed_access;
	records->fs[records->fs_len].flags = flags;
	records->fs_len++;
	return 0;
}

static int push_net_rule(struct rule_records *records, __u64 port,
			 __u64 allowed_access, __u32 flags)
{
	struct net_rule_record *new_net;

	if (!records)
		return 0;

	if (records->net_len == records->net_cap) {
		size_t new_cap = records->net_cap ? records->net_cap * 2 : 8;

		new_net = realloc(records->net, new_cap * sizeof(*new_net));
		if (!new_net)
			return -1;
		records->net = new_net;
		records->net_cap = new_cap;
	}

	records->net[records->net_len].port = port;
	records->net[records->net_len].allowed_access = allowed_access;
	records->net[records->net_len].flags = flags;
	records->net_len++;
	return 0;
}

static int send_fd(int sock, int fd)
{
	struct msghdr msg = {};
	struct iovec iov;
	char buf = 'F';
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;

	iov.iov_base = &buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));
	msg.msg_controllen = cmsg->cmsg_len;

	return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

static int recv_fd(int sock)
{
	struct msghdr msg = {};
	struct iovec iov;
	char buf;
	char cmsgbuf[CMSG_SPACE(sizeof(int))];
	struct cmsghdr *cmsg;
	int fd = -1;

	iov.iov_base = &buf;
	iov.iov_len = sizeof(buf);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);

	if (recvmsg(sock, &msg, 0) < 0)
		return -1;

	cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
		return -1;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}

static enum supervise_default parse_supervise_default(void)
{
	const char *val = getenv(ENV_SUPERVISE_DEFAULT_NAME);

	if (!val || strcmp(val, "") == 0)
		return SUP_DEFAULT_ASK;
	if (strcmp(val, "ask") == 0)
		return SUP_DEFAULT_ASK;
	if (strcmp(val, "allow") == 0)
		return SUP_DEFAULT_ALLOW;
	if (strcmp(val, "deny") == 0)
		return SUP_DEFAULT_DENY;
	return SUP_DEFAULT_ASK;
}

static int prompt_yes_no(const char *prompt, bool default_no)
{
	char line[32];

	fprintf(stderr, "%s [%c/%c]: ", prompt, default_no ? 'y' : 'Y', default_no ? 'N' : 'n');
	fflush(stderr);
	if (!fgets(line, sizeof(line), stdin))
		return default_no ? 0 : 1;
	if (line[0] == 'y' || line[0] == 'Y')
		return 1;
	if (line[0] == 'n' || line[0] == 'N')
		return 0;
	return default_no ? 0 : 1;
}

static void print_supervisor_event(const struct landlock_supervisor_event *event)
{
	if (!event)
		return;

	fprintf(stderr,
		"Landlock event: cookie=%llu tgid=%u req=%u rule=%u access=0x%llx",
		(unsigned long long)event->cookie,
		(unsigned int)event->tgid,
		(unsigned int)event->request_type,
		(unsigned int)event->rule_type,
		(unsigned long long)event->access);
	if (event->ino)
		fprintf(stderr, " ino=%llu", (unsigned long long)event->ino);
	if (event->port)
		fprintf(stderr, " port=%llu", (unsigned long long)event->port);
	fprintf(stderr, "\n");
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
			       const __u64 allowed_access, __u32 flags,
			       struct rule_records *records)
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
		__u64 effective_access;

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
		effective_access = allowed_access;
		if (!S_ISDIR(statbuf.st_mode))
			effective_access &= ACCESS_FILE;
		path_beneath.allowed_access = effective_access;
		if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
				      &path_beneath, flags)) {
			fprintf(stderr,
				"Failed to update the ruleset with \"%s\": %s\n",
				path_list[i], strerror(errno));
			close(path_beneath.parent_fd);
			goto out_free_name;
		}
		if (push_fs_rule(records, path_list[i], effective_access, flags) < 0) {
			fprintf(stderr, "Failed to allocate memory\n");
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
				const __u64 allowed_access, __u32 flags,
				struct rule_records *records)
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
		if (push_net_rule(records, port, allowed_access, flags) < 0) {
			fprintf(stderr, "Failed to allocate memory\n");
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
	bool supervise_mode = false;
	struct rule_records records = {};
	enum supervise_default supervise_default = SUP_DEFAULT_ASK;
	bool prompt_once = false;

	if (argc < 2) {
		fprintf(stderr, help, argv[0]);
		return 1;
	}

	if (getenv(ENV_SUPERVISE_NAME) && strcmp(getenv(ENV_SUPERVISE_NAME), "1") == 0) {
		supervise_mode = true;
		unsetenv(ENV_SUPERVISE_NAME);
		supervise_default = parse_supervise_default();
		if (getenv(ENV_SUPERVISE_PROMPT_ONCE_NAME) &&
		    strcmp(getenv(ENV_SUPERVISE_PROMPT_ONCE_NAME), "1") == 0) {
			prompt_once = true;
			unsetenv(ENV_SUPERVISE_PROMPT_ONCE_NAME);
		}
		unsetenv(ENV_SUPERVISE_DEFAULT_NAME);
		/* Supervisor mode requires audit/supervise support in the kernel. */
		supported_restrict_flags |= LANDLOCK_RESTRICT_SELF_SUPERVISE;
		set_restrict_flags |= LANDLOCK_RESTRICT_SELF_SUPERVISE;
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

	if (populate_ruleset_fs(ENV_FS_RO_NAME, ruleset_fd, access_fs_ro, 0,
				 supervise_mode ? &records : NULL))
		goto err_close_ruleset;
	if (populate_ruleset_fs(ENV_FS_RW_NAME, ruleset_fd, access_fs_rw, 0,
				 supervise_mode ? &records : NULL))
		goto err_close_ruleset;

	/* Don't require this env to be present. */
	if (quiet_supported && getenv(ENV_FS_QUIET_NAME)) {
		if (populate_ruleset_fs(ENV_FS_QUIET_NAME, ruleset_fd, 0,
				LANDLOCK_ADD_RULE_QUIET,
				supervise_mode ? &records : NULL))
			goto err_close_ruleset;
	}

	/* Don't require this env to be present. */
	if (no_inherit_supported && getenv(ENV_FS_NO_INHERIT_NAME)) {
		if (populate_ruleset_fs(ENV_FS_NO_INHERIT_NAME, ruleset_fd, 0,
				LANDLOCK_ADD_RULE_NO_INHERIT,
				supervise_mode ? &records : NULL))
			goto err_close_ruleset;
	}

	if (populate_ruleset_net(ENV_TCP_BIND_NAME, ruleset_fd,
			 LANDLOCK_ACCESS_NET_BIND_TCP, 0,
			 supervise_mode ? &records : NULL)) {
		goto err_close_ruleset;
	}
	if (populate_ruleset_net(ENV_TCP_CONNECT_NAME, ruleset_fd,
			 LANDLOCK_ACCESS_NET_CONNECT_TCP, 0,
			 supervise_mode ? &records : NULL)) {
		goto err_close_ruleset;
	}

	/* Don't require this env to be present. */
	if (quiet_supported && getenv(ENV_NET_QUIET_NAME)) {
		if (populate_ruleset_net(ENV_NET_QUIET_NAME, ruleset_fd, 0,
				 LANDLOCK_ADD_RULE_QUIET,
				 supervise_mode ? &records : NULL)) {
			goto err_close_ruleset;
		}
	}

	cmd_path = argv[1];
	cmd_argv = argv + 1;

	if (!supervise_mode) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			perror("Failed to restrict privileges");
			goto err_close_ruleset;
		}
		if (landlock_restrict_self(ruleset_fd, set_restrict_flags)) {
			perror("Failed to enforce ruleset");
			goto err_close_ruleset;
		}
		close(ruleset_fd);
		fprintf(stderr, "Executing the sandboxed command...\n");
		execvpe(cmd_path, cmd_argv, envp);
		fprintf(stderr, "Failed to execute \"%s\": %s\n", cmd_path,
			strerror(errno));
		fprintf(stderr, "Hint: access to the binary, the interpreter or "
				"shared libraries may be denied.\n");
		return 1;
	}

	/* Supervisor mode: fork a supervised child and keep running as supervisor. */
	{
		int sv[2];
		pid_t child;
		int supervisor_fd = -1;
		char ready = 'R';
		int child_status = 0;
		int allow_all = -1;
		size_t i;

		if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) {
			perror("Failed to create socketpair");
			goto err_close_ruleset;
		}

		child = fork();
		if (child < 0) {
			perror("Failed to fork");
			close(sv[0]);
			close(sv[1]);
			goto err_close_ruleset;
		}
		if (child == 0) {
			/* Child: become sandboxed and exec. */
			close(sv[0]);
			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
				perror("Failed to restrict privileges");
				_exit(1);
			}
			supervisor_fd = landlock_restrict_self(ruleset_fd, set_restrict_flags);
			if (supervisor_fd < 0) {
				perror("Failed to enforce ruleset (supervise)");
				_exit(1);
			}
			/* Send supervisor FD to parent, then wait for parent ack. */
			if (send_fd(sv[1], supervisor_fd) != 0) {
				perror("Failed to send supervisor FD");
				_exit(1);
			}
			if (read(sv[1], &ready, 1) != 1) {
				perror("Failed to wait for supervisor");
				_exit(1);
			}
			close(sv[1]);
			close(supervisor_fd);
			close(ruleset_fd);
			execvpe(cmd_path, cmd_argv, envp);
			perror("Failed to execute supervised command");
			_exit(1);
		}

		/* Parent: supervisor. */
		close(sv[1]);
		supervisor_fd = recv_fd(sv[0]);
		if (supervisor_fd < 0) {
			perror("Failed to receive supervisor FD");
			close(sv[0]);
			goto err_close_ruleset;
		}

		fprintf(stderr, "Supervisor mode enabled for pid %d.\n", child);
		fprintf(stderr, "Attaching per-rule subrulesets (stdin prompts)...\n");

		if (prompt_once && supervise_default == SUP_DEFAULT_ASK) {
			allow_all = prompt_yes_no(
				"Allow subrules identical to the base rules?", true);
		}

		/* Attach a subruleset to each configured rule (initial policy). */
		for (i = 0; i < records.fs_len; i++) {
			int subruleset_fd;
			struct landlock_ruleset_attr sub_attr = ruleset_attr;
			struct landlock_supervisor_set_subruleset_attr sup = {
				.ruleset_fd = ruleset_fd,
				.subruleset_fd = -1,
				.rule_type = LANDLOCK_RULE_PATH_BENEATH,
				.flags = 0,
			};
			struct landlock_tag_expr nodes[1];
			struct landlock_tag_tree_attr tree = {
				.nodes = 0,
				.nodes_len = 0,
				.root = 0,
			};
			int execfd = -1;
			struct landlock_path_beneath_attr path_beneath = {
				.allowed_access = records.fs[i].allowed_access,
				.parent_fd = -1,
			};
			int allow;

			if (supervise_default == SUP_DEFAULT_ALLOW)
				allow = 1;
			else if (supervise_default == SUP_DEFAULT_DENY)
				allow = 0;
			else if (allow_all != -1)
				allow = allow_all;
			else {
				char prompt[512];
				snprintf(prompt, sizeof(prompt),
					 "Allow subrules for path rule: %s ?",
					 records.fs[i].path);
				allow = prompt_yes_no(prompt, true);
			}

			subruleset_fd =
				landlock_create_ruleset(&sub_attr, sizeof(sub_attr), 0);
			if (subruleset_fd < 0) {
				perror("Failed to create subruleset");
				close(supervisor_fd);
				close(sv[0]);
				goto err_close_ruleset;
			}

			if (allow) {
				path_beneath.parent_fd =
					open(records.fs[i].path, O_PATH | O_CLOEXEC);
				if (path_beneath.parent_fd < 0) {
					perror("Failed to open path for subrule");
					close(subruleset_fd);
					close(supervisor_fd);
					close(sv[0]);
					goto err_close_ruleset;
				}
				if (landlock_add_rule(subruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
						      &path_beneath, records.fs[i].flags)) {
					perror("Failed to add subrule");
					close(path_beneath.parent_fd);
					close(subruleset_fd);
					close(supervisor_fd);
					close(sv[0]);
					goto err_close_ruleset;
				}
				close(path_beneath.parent_fd);
			}

			sup.subruleset_fd = subruleset_fd;

			/* Tag matcher: EXEC_FD(cmd) (matches exec'd children too). */
			execfd = open(cmd_path, O_PATH | O_CLOEXEC);
			memset(nodes, 0, sizeof(nodes));
			if (execfd >= 0) {
				nodes[0].op = LANDLOCK_TAG_EXPR_EXEC_FD;
				nodes[0].fd = execfd;
				tree.nodes = (unsigned long long)(uintptr_t)nodes;
				tree.nodes_len = 1;
				tree.root = 0;
			} else {
				/* Fall back to empty tag (matches all requests). */
				tree.nodes = 0;
				tree.nodes_len = 0;
				tree.root = 0;
			}
			sup.tag_tree = tree;

			sup.rule_attr.path_beneath = path_beneath;
			/* For lookup, kernel uses parent_fd; open a fresh one for ioctl. */
			sup.rule_attr.path_beneath.parent_fd =
				open(records.fs[i].path, O_PATH | O_CLOEXEC);
			if (sup.rule_attr.path_beneath.parent_fd < 0) {
				perror("Failed to open path for ioctl");
				if (execfd >= 0)
					close(execfd);
				close(subruleset_fd);
				close(supervisor_fd);
				close(sv[0]);
				goto err_close_ruleset;
			}
			if (ioctl(supervisor_fd, LANDLOCK_SUPERVISOR_SET_SUBRULESET, &sup) != 0) {
				perror("Failed to set subruleset (path)");
				close(sup.rule_attr.path_beneath.parent_fd);
				if (execfd >= 0)
					close(execfd);
				close(subruleset_fd);
				close(supervisor_fd);
				close(sv[0]);
				goto err_close_ruleset;
			}
			close(sup.rule_attr.path_beneath.parent_fd);
			if (execfd >= 0)
				close(execfd);
			close(subruleset_fd);
		}

		for (i = 0; i < records.net_len; i++) {
			int subruleset_fd;
			struct landlock_ruleset_attr sub_attr = ruleset_attr;
			struct landlock_supervisor_set_subruleset_attr sup = {
				.ruleset_fd = ruleset_fd,
				.subruleset_fd = -1,
				.rule_type = LANDLOCK_RULE_NET_PORT,
				.flags = 0,
			};
			struct landlock_tag_expr nodes[1];
			struct landlock_tag_tree_attr tree = {
				.nodes = 0,
				.nodes_len = 0,
				.root = 0,
			};
			int execfd = -1;
			struct landlock_net_port_attr net_port = {
				.allowed_access = records.net[i].allowed_access,
				.port = records.net[i].port,
			};
			int allow;

			if (supervise_default == SUP_DEFAULT_ALLOW)
				allow = 1;
			else if (supervise_default == SUP_DEFAULT_DENY)
				allow = 0;
			else if (allow_all != -1)
				allow = allow_all;
			else {
				char prompt[256];
				snprintf(prompt, sizeof(prompt),
					 "Allow subrules for TCP port rule: %llu ?",
					 (unsigned long long)records.net[i].port);
				allow = prompt_yes_no(prompt, true);
			}

			subruleset_fd =
				landlock_create_ruleset(&sub_attr, sizeof(sub_attr), 0);
			if (subruleset_fd < 0) {
				perror("Failed to create subruleset");
				close(supervisor_fd);
				close(sv[0]);
				goto err_close_ruleset;
			}
			if (allow) {
				if (landlock_add_rule(subruleset_fd, LANDLOCK_RULE_NET_PORT,
						      &net_port, records.net[i].flags)) {
					perror("Failed to add subrule");
					close(subruleset_fd);
					close(supervisor_fd);
					close(sv[0]);
					goto err_close_ruleset;
				}
			}
			sup.subruleset_fd = subruleset_fd;

			/* Tag matcher: EXEC_FD(cmd) (matches exec'd children too). */
			execfd = open(cmd_path, O_PATH | O_CLOEXEC);
			memset(nodes, 0, sizeof(nodes));
			if (execfd >= 0) {
				nodes[0].op = LANDLOCK_TAG_EXPR_EXEC_FD;
				nodes[0].fd = execfd;
				tree.nodes = (unsigned long long)(uintptr_t)nodes;
				tree.nodes_len = 1;
				tree.root = 0;
			} else {
				/* Fall back to empty tag (matches all requests). */
				tree.nodes = 0;
				tree.nodes_len = 0;
				tree.root = 0;
			}
			sup.tag_tree = tree;

			sup.rule_attr.net_port = net_port;
			if (ioctl(supervisor_fd, LANDLOCK_SUPERVISOR_SET_SUBRULESET, &sup) != 0) {
				perror("Failed to set subruleset (net)");
				if (execfd >= 0)
					close(execfd);
				close(subruleset_fd);
				close(supervisor_fd);
				close(sv[0]);
				goto err_close_ruleset;
			}
			if (execfd >= 0)
				close(execfd);
			close(subruleset_fd);
		}

		/* Register eventfd before letting the child exec (avoid missed prompts). */
		{
			int efd;
			struct landlock_supervisor_eventfd_attr eattr = {
				.event_fd = -1,
				.flags = 0,
			};
			struct pollfd pfd;
			int have_allow_all = 0;
			int allow_all_value = 0;

			efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			if (efd < 0) {
				perror("eventfd");
				close(supervisor_fd);
				close(ruleset_fd);
				free_rule_records(&records);
				goto wait_child;
			}
			eattr.event_fd = efd;
			if (ioctl(supervisor_fd, LANDLOCK_SUPERVISOR_SET_EVENTFD, &eattr) != 0) {
				perror("Failed to set supervisor eventfd");
				close(efd);
				close(supervisor_fd);
				close(ruleset_fd);
				free_rule_records(&records);
				goto wait_child;
			}

			/* Let the supervised child exec now. */
			if (write(sv[0], &ready, 1) != 1)
				perror("Failed to signal supervised child");
			close(sv[0]);

			pfd.fd = efd;
			pfd.events = POLLIN;

			/* Parent remains supervisor until the child exits. */
			for (;;) {
				int w;
				int pr;

				w = waitpid(child, &child_status, WNOHANG);
				if (w == child)
					break;
				if (w < 0) {
					perror("waitpid failed");
					break;
				}

				pr = poll(&pfd, 1, 250);
				if (pr < 0) {
					if (errno == EINTR)
						continue;
					perror("poll");
					break;
				}
				if (pr == 0)
					continue;
				if (pfd.revents & POLLIN) {
					/* Drain the eventfd counter. */
					for (;;) {
						unsigned long long cnt;
						ssize_t r = read(efd, &cnt, sizeof(cnt));
						if (r == (ssize_t)sizeof(cnt))
							continue;
						if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
							break;
						if (r < 0 && errno == EINTR)
							continue;
						break;
					}

					/* Receive all queued events and decide. */
					for (;;) {
						struct landlock_supervisor_event ev = {};
						struct landlock_supervisor_decide_attr d = {
							.cookie = 0,
							.allow = 0,
							.flags = 0,
						};
						int allow = 0;

						if (ioctl(supervisor_fd, LANDLOCK_SUPERVISOR_RECV_EVENT, &ev) != 0) {
							if (errno == EAGAIN)
								break;
							if (errno == EINTR)
								continue;
							perror("Failed to recv supervisor event");
							break;
						}

						print_supervisor_event(&ev);

						if (supervise_default == SUP_DEFAULT_ALLOW)
							allow = 1;
						else if (supervise_default == SUP_DEFAULT_DENY)
							allow = 0;
						else if (prompt_once && have_allow_all)
							allow = allow_all_value;
						else {
							char prompt[256];
							snprintf(prompt, sizeof(prompt),
								 "Allow this request? (cookie=%llu)",
								 (unsigned long long)ev.cookie);
							allow = prompt_yes_no(prompt, true);
							if (prompt_once && !have_allow_all) {
								have_allow_all = 1;
								allow_all_value = prompt_yes_no(
									"Use this decision for all future requests?", false)
									? allow
									: allow_all_value;
								if (!prompt_yes_no(
									"Apply decision globally?", true)) {
									have_allow_all = 0;
								}
							}
						}

						d.cookie = ev.cookie;
						d.allow = allow ? 1 : 0;
						if (ioctl(supervisor_fd, LANDLOCK_SUPERVISOR_DECIDE, &d) != 0) {
							perror("Failed to decide supervisor event");
							break;
						}
					}
				}
			}

			close(efd);
		}

		close(supervisor_fd);
		close(ruleset_fd);
		free_rule_records(&records);

wait_child:
		if (waitpid(child, &child_status, 0) < 0) {
			perror("waitpid failed");
			return 1;
		}
		if (WIFEXITED(child_status))
			return WEXITSTATUS(child_status);
		if (WIFSIGNALED(child_status))
			return 128 + WTERMSIG(child_status);
		return 1;
	}

err_close_ruleset:
	free_rule_records(&records);
	close(ruleset_fd);
	return 1;
}
