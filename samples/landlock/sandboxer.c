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
#include <linux/limits.h>
#include <linux/socket.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static inline int
landlock_create_ruleset_supervised(struct landlock_supervisor_attr *const attr,
				   const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size,
		       flags | LANDLOCK_CREATE_RULESET_SUPERVISED);
}

/* Access type names for human-readable output */
static const char *get_fs_access_name(__u64 access)
{
	switch (access) {
	case LANDLOCK_ACCESS_FS_EXECUTE:
		return "execute";
	case LANDLOCK_ACCESS_FS_WRITE_FILE:
		return "write_file";
	case LANDLOCK_ACCESS_FS_READ_FILE:
		return "read_file";
	case LANDLOCK_ACCESS_FS_READ_DIR:
		return "read_dir";
	case LANDLOCK_ACCESS_FS_REMOVE_DIR:
		return "remove_dir";
	case LANDLOCK_ACCESS_FS_REMOVE_FILE:
		return "remove_file";
	case LANDLOCK_ACCESS_FS_MAKE_CHAR:
		return "make_char";
	case LANDLOCK_ACCESS_FS_MAKE_DIR:
		return "make_dir";
	case LANDLOCK_ACCESS_FS_MAKE_REG:
		return "make_reg";
	case LANDLOCK_ACCESS_FS_MAKE_SOCK:
		return "make_sock";
	case LANDLOCK_ACCESS_FS_MAKE_FIFO:
		return "make_fifo";
	case LANDLOCK_ACCESS_FS_MAKE_BLOCK:
		return "make_block";
	case LANDLOCK_ACCESS_FS_MAKE_SYM:
		return "make_sym";
	case LANDLOCK_ACCESS_FS_REFER:
		return "refer";
	case LANDLOCK_ACCESS_FS_TRUNCATE:
		return "truncate";
	case LANDLOCK_ACCESS_FS_IOCTL_DEV:
		return "ioctl_dev";
	default:
		return "unknown";
	}
}

static void print_fs_access_mask(__u64 mask)
{
	int first = 1;
	__u64 bit;

	for (bit = 1; bit && bit <= mask; bit <<= 1) {
		if (mask & bit) {
			if (!first)
				fprintf(stderr, "|");
			fprintf(stderr, "%s", get_fs_access_name(bit));
			first = 0;
		}
	}
}

static const char *get_net_access_name(__u64 access)
{
	switch (access) {
	case LANDLOCK_ACCESS_NET_BIND_TCP:
		return "bind_tcp";
	case LANDLOCK_ACCESS_NET_CONNECT_TCP:
		return "connect_tcp";
	default:
		return "unknown";
	}
}

static void print_net_access_mask(__u64 mask)
{
	int first = 1;
	__u64 bit;

	for (bit = 1; bit && bit <= mask; bit <<= 1) {
		if (mask & bit) {
			if (!first)
				fprintf(stderr, "|");
			fprintf(stderr, "%s", get_net_access_name(bit));
			first = 0;
		}
	}
}

/*
 * Get the path string from an O_PATH file descriptor using /proc/self/fd.
 * Returns the path in the provided buffer, or an error message.
 */
static void get_path_from_fd(int fd, char *buf, size_t buf_size)
{
	char proc_path[64];
	ssize_t len;

	if (fd < 0) {
		snprintf(buf, buf_size, "(no fd)");
		return;
	}

	snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
	len = readlink(proc_path, buf, buf_size - 1);
	if (len < 0) {
		snprintf(buf, buf_size, "(error: %s)", strerror(errno));
		return;
	}
	buf[len] = '\0';
}

/*
 * Supervisor loop: reads access requests from supervisor_fd and prompts
 * the user for decisions via stdin/stderr.
 */
static int run_supervisor(int supervisor_fd, pid_t child_pid)
{
	struct landlock_supervisor_request req;
	struct landlock_supervisor_response resp;
	struct pollfd pfds[1];
	int status;
	char input[16];

	fprintf(stderr, "\n=== Landlock Supervisor Active ===\n");
	fprintf(stderr, "Child process PID: %d\n", child_pid);
	fprintf(stderr, "Waiting for access requests...\n\n");

	pfds[0].fd = supervisor_fd;
	pfds[0].events = POLLIN;

	while (1) {
		int ret;

		/* Check if child is still alive */
		ret = waitpid(child_pid, &status, WNOHANG);
		if (ret > 0) {
			fprintf(stderr, "\nChild process exited");
			if (WIFEXITED(status))
				fprintf(stderr, " with status %d\n",
					WEXITSTATUS(status));
			else if (WIFSIGNALED(status))
				fprintf(stderr, " due to signal %d\n",
					WTERMSIG(status));
			else
				fprintf(stderr, "\n");
			break;
		}

		ret = poll(pfds, 1, 500); /* 500ms timeout */
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("poll failed");
			return 1;
		}

		if (ret == 0)
			continue; /* Timeout, check child again */

		if (!(pfds[0].revents & POLLIN)) {
			if (pfds[0].revents & (POLLERR | POLLHUP)) {
				fprintf(stderr,
					"Supervisor fd closed or error\n");
				break;
			}
			continue;
		}

		/* Read the request */
		ret = read(supervisor_fd, &req, sizeof(req));
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			perror("Failed to read supervisor request");
			return 1;
		}
		if (ret == 0) {
			fprintf(stderr, "Supervisor fd EOF\n");
			break;
		}
		if (ret != sizeof(req)) {
			fprintf(stderr, "Short read: got %d, expected %zu\n",
				ret, sizeof(req));
			continue;
		}

		/* Variables for filesystem requests - used in caching prompts */
		struct landlock_supervisor_recv_fd recv_fd = {
			.id = req.id,
			.fd = -1,
			.reserved = 0,
		};
		char path_buf[PATH_MAX] = "";
		bool has_fd = false;

		/* Display the request to the user */
		fprintf(stderr, "\n--- Access Request ---\n");
		fprintf(stderr, "Request ID: %llu\n",
			(unsigned long long)req.id);
		fprintf(stderr, "PID: %u, TGID: %u\n", req.pid, req.tgid);

		if (req.rule_type == LANDLOCK_RULE_PATH_BENEATH) {
			fprintf(stderr, "Type: Filesystem access\n");
			fprintf(stderr, "Access: ");
			print_fs_access_mask(req.access_request);
			fprintf(stderr, " (0x%llx)\n",
				(unsigned long long)req.access_request);

			/* Get O_PATH fd for the actual subject if it exists */
			ret = ioctl(supervisor_fd,
				    LANDLOCK_IOCTL_SUPERVISOR_RECV_FD,
				    &recv_fd);
			if (ret < 0) {
				fprintf(stderr,
					"Warning: Failed to get subject fd: %s\n",
					strerror(errno));
			} else if (recv_fd.fd >= 0) {
				get_path_from_fd(recv_fd.fd, path_buf,
						 sizeof(path_buf));
				fprintf(stderr, "Subject: %s\n", path_buf);
				has_fd = true;
			}

			/* If we didn't get an fd, the subject may not exist yet */
			if (!has_fd) {
				fprintf(stderr, "Subject: (unavailable)\n");
			}

			/* Clean up fd */
			if (has_fd)
				close(recv_fd.fd);
		} else if (req.rule_type == LANDLOCK_RULE_NET_PORT) {
			fprintf(stderr, "Type: Network access\n");
			fprintf(stderr, "Access: ");
			print_net_access_mask(req.access_request);
			fprintf(stderr, " (0x%llx)\n",
				(unsigned long long)req.access_request);
			fprintf(stderr, "Port: %llu\n",
				(unsigned long long)req.port);
		} else {
			fprintf(stderr, "Type: Unknown (%u)\n", req.rule_type);
			fprintf(stderr, "Access: 0x%llx\n",
				(unsigned long long)req.access_request);
		}

		/* Prompt user for decision */
		fprintf(stderr,
			"\nAllow this access? [y/n/c(cache allow)/C(cache deny)]: ");
		fflush(stderr);

		if (fgets(input, sizeof(input), stdin) == NULL) {
			fprintf(stderr, "EOF on stdin, denying request\n");
			resp.decision = LANDLOCK_DECISION_DENY;
			resp.flags = 0;
			resp.cache_key_types = 0;
		} else {
			switch (input[0]) {
			case 'y':
			case 'Y':
				resp.decision = LANDLOCK_DECISION_ALLOW;
				resp.flags = 0;
				resp.cache_key_types = 0;
				fprintf(stderr, "-> Allowing access\n");
				break;
			case 'c':
			case 'C': {
				/* Ask for cache key type */
				char cache_input[32];
				char key_info[512] = "";
				
				resp.decision = (input[0] == 'c') ?
					LANDLOCK_DECISION_ALLOW :
					LANDLOCK_DECISION_DENY;
				resp.flags = LANDLOCK_DECISION_FLAG_CACHE;
				resp.cache_key_types = 0;
				
				fprintf(stderr, "Cache by:\n");
				if (has_fd) {
					fprintf(stderr, "  [i] Inode (inode of %s)\n", path_buf);
				} else {
					fprintf(stderr, "  [i] Inode (default - file doesn't exist yet)\n");
				}
				if (has_fd) {
					fprintf(stderr, "  [p] Path string (path: %s)\n", path_buf);
				} else {
					fprintf(stderr, "  [p] Path string\n");
				}
				fprintf(stderr, "  [d] Process ID (PID: %u, TGID: %u)\n",
					req.pid, req.tgid);
				fprintf(stderr, "  [m] Multiple (e.g., 'ip' for inode+path)\n");
				fprintf(stderr, "Choice: ");
				fflush(stderr);
				
				if (fgets(cache_input, sizeof(cache_input), stdin) != NULL) {
					int j;
					int key_count = 0;
					for (j = 0; cache_input[j] && cache_input[j] != '\n'; j++) {
						switch (cache_input[j]) {
						case 'i':
							resp.cache_key_types |= LANDLOCK_CACHE_KEY_INODE;
							if (key_count++ > 0) strcat(key_info, " + ");
							strcat(key_info, has_fd ? path_buf : "inode");
							break;
						case 'p':
							resp.cache_key_types |= LANDLOCK_CACHE_KEY_PATH;
							if (key_count++ > 0) strcat(key_info, " + ");
							strcat(key_info, has_fd ? path_buf : "path");
							break;
						case 'd':
							resp.cache_key_types |= LANDLOCK_CACHE_KEY_PID;
							if (key_count++ > 0) strcat(key_info, " + ");
							snprintf(key_info + strlen(key_info), 
								sizeof(key_info) - strlen(key_info),
								"PID %u", req.tgid);
							break;
						}
					}
				}
				
				/* Default to inode if nothing specified */
				if (resp.cache_key_types == 0) {
					resp.cache_key_types = LANDLOCK_CACHE_KEY_INODE;
					snprintf(key_info, sizeof(key_info), "%s",
						has_fd ? path_buf : "inode");
				}
				
				fprintf(stderr, "-> %s access (cached by: %s)\n",
					(resp.decision == LANDLOCK_DECISION_ALLOW) ?
						"Allowing" : "Denying",
					key_info);
				break;
			}
			case 'n':
			case 'N':
			default:
				resp.decision = LANDLOCK_DECISION_DENY;
				resp.flags = 0;
				resp.cache_key_types = 0;
				fprintf(stderr, "-> Denying access\n");
				break;
			}
		}

		resp.id = req.id;

		/* Send response */
		ret = write(supervisor_fd, &resp, sizeof(resp));
		if (ret < 0) {
			perror("Failed to write supervisor response");
			return 1;
		}
		if (ret != sizeof(resp)) {
			fprintf(stderr, "Short write: wrote %d, expected %zu\n",
				ret, sizeof(resp));
			return 1;
		}
	}

	/* Wait for child to finish if not already done */
	if (waitpid(child_pid, &status, 0) < 0 && errno != ECHILD)
		perror("waitpid");

	close(supervisor_fd);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 1;
}

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
#define ENV_SUPERVISED_NAME "LL_SUPERVISED"
#define ENV_FS_SUPERVISED_NAME "LL_FS_SUPERVISED"
#define ENV_NET_SUPERVISED_NAME "LL_NET_SUPERVISED"
#define ENV_DELIMITER ":"

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
	char *supervised_paths = NULL;
	const char **supervised_list = NULL;
	int num_supervised = 0;

	/* Check if we should add supervised flag to any paths */
	if (!(flags & LANDLOCK_ADD_RULE_SUPERVISED)) {
		supervised_paths = getenv(ENV_FS_SUPERVISED_NAME);
		if (supervised_paths) {
			supervised_paths = strdup(supervised_paths);
			num_supervised = parse_path(supervised_paths, &supervised_list);
		}
	}

	env_path_name = getenv(env_var);
	if (!env_path_name) {
		/* Prevents users to forget a setting. */
		fprintf(stderr, "Missing environment variable %s\n", env_var);
		if (supervised_paths) {
			free(supervised_paths);
			free((void *)supervised_list);
		}
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
		__u32 path_flags = flags;
		int j;

		/* Check if this path is also in the supervised list */
		if (num_supervised > 0 && supervised_list) {
			for (j = 0; j < num_supervised; j++) {
				if (strcmp(path_list[i], supervised_list[j]) == 0) {
					path_flags |= LANDLOCK_ADD_RULE_SUPERVISED;
					break;
				}
			}
		}

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
				      &path_beneath, path_flags)) {
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
	if (supervised_paths) {
		free(supervised_paths);
		free((void *)supervised_list);
	}
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
	"Supervised mode (requires ABI >= 9):\n"
	"* " ENV_SUPERVISED_NAME "=1: Enable supervised mode. The sandboxer forks and the\n"
	"    parent process becomes a supervisor that receives access requests for\n"
	"    paths/ports marked as supervised. The user is prompted on stdin to\n"
	"    allow or deny each access request.\n"
	"* " ENV_FS_SUPERVISED_NAME ": paths to mark as supervised (prompts user on access)\n"
	"* " ENV_NET_SUPERVISED_NAME ": ports to mark as supervised (prompts user on access)\n"
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
	"Supervised example:\n"
	ENV_FS_RO_NAME "=\"${PATH}:/lib:/usr:/proc:/etc\" "
	ENV_FS_RW_NAME "=\"/tmp\" "
	ENV_SUPERVISED_NAME "=1 "
	ENV_FS_SUPERVISED_NAME "=\"/home\" "
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
	char *env_port_name, *env_force_log, *env_supervised;
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

	struct landlock_supervisor_attr supervisor_attr;
	bool supervised_mode = false;
	bool supervised_supported = true;
	int supervisor_fd = -1;

	bool quiet_supported = true;
	bool no_inherit_supported = true;
	int supported_restrict_flags = LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
	int set_restrict_flags = 0;

	if (argc < 2) {
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
		/* Don't add quiet/no_inherit/supervised flags for ABI < 8 */
		quiet_supported = false;
		no_inherit_supported = false;
		supervised_supported = false;

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

	/* Check for supervised mode */
	env_supervised = getenv(ENV_SUPERVISED_NAME);
	if (env_supervised && strcmp(env_supervised, "1") == 0) {
		if (!supervised_supported) {
			fprintf(stderr,
				"Supervised mode not supported by current kernel (requires ABI >= 8)\n");
			return 1;
		}
		supervised_mode = true;
		unsetenv(ENV_SUPERVISED_NAME);
	}

	if (supervised_mode) {
		/* Create supervised ruleset */
		memset(&supervisor_attr, 0, sizeof(supervisor_attr));
		supervisor_attr.ruleset_attr = ruleset_attr;
		supervisor_attr.flags = 0;

		ruleset_fd = landlock_create_ruleset_supervised(
			&supervisor_attr, sizeof(supervisor_attr), 0);
		if (ruleset_fd < 0) {
			perror("Failed to create supervised ruleset");
			return 1;
		}
		supervisor_fd = supervisor_attr.supervisor_fd;
		fprintf(stderr, "Created supervised ruleset (supervisor_fd=%d)\n",
			supervisor_fd);
	} else {
		ruleset_fd = landlock_create_ruleset(&ruleset_attr,
						     sizeof(ruleset_attr), 0);
		if (ruleset_fd < 0) {
			perror("Failed to create a ruleset");
			return 1;
		}
	}
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

	/* Add supervised rules if in supervised mode */
	/* Note: Paths that appear in both LL_FS_RW/LL_FS_RO and 
	 * LL_FS_SUPERVISED have already been added with the supervised flag,
	 * so we don't need to add them again here. We only process paths
	 * that are ONLY in LL_FS_SUPERVISED.
	 */
	if (supervised_mode && getenv(ENV_FS_SUPERVISED_NAME)) {
		/* The supervised paths that match RW/RO paths were already
		 * added above with the supervised flag, so we skip this.
		 * This would only add standalone supervised paths.
		 */
		char *fs_supervised = getenv(ENV_FS_SUPERVISED_NAME);
		char *fs_rw = getenv(ENV_FS_RW_NAME);
		char *fs_ro = getenv(ENV_FS_RO_NAME);
		bool already_added = false;
		
		/* Check if supervised path was already added via RW or RO */
		if (fs_rw && strcmp(fs_supervised, fs_rw) == 0)
			already_added = true;
		if (fs_ro && strcmp(fs_supervised, fs_ro) == 0)
			already_added = true;
		
		if (!already_added) {
			if (populate_ruleset_fs(ENV_FS_SUPERVISED_NAME, ruleset_fd,
						access_fs_rw,
						LANDLOCK_ADD_RULE_SUPERVISED))
				goto err_close_ruleset;
		}
	}

	if (supervised_mode && getenv(ENV_NET_SUPERVISED_NAME)) {
		if (populate_ruleset_net(
			    ENV_NET_SUPERVISED_NAME, ruleset_fd,
			    LANDLOCK_ACCESS_NET_BIND_TCP |
				    LANDLOCK_ACCESS_NET_CONNECT_TCP,
			    LANDLOCK_ADD_RULE_SUPERVISED)) {
			goto err_close_ruleset;
		}
	}

	cmd_path = argv[1];
	cmd_argv = argv + 1;

	if (supervised_mode) {
		/*
		 * For supervised mode, fork BEFORE restricting so the parent
		 * (supervisor) remains unsandboxed and can access the supervisor fd.
		 * Only the child process gets sandboxed.
		 */
		pid_t pid = fork();

		if (pid < 0) {
			perror("Failed to fork");
			goto err_close_ruleset;
		}

		if (pid == 0) {
			/* Child process: apply sandbox and exec */
			close(supervisor_fd);

			if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
				perror("Failed to restrict privileges");
				close(ruleset_fd);
				_exit(1);
			}
			if (landlock_restrict_self(ruleset_fd, set_restrict_flags)) {
				perror("Failed to enforce ruleset");
				close(ruleset_fd);
				_exit(1);
			}
			close(ruleset_fd);

			fprintf(stderr, "Child: Executing sandboxed command...\n");
			execvpe(cmd_path, cmd_argv, envp);
			fprintf(stderr, "Failed to execute \"%s\": %s\n",
				cmd_path, strerror(errno));
			fprintf(stderr,
				"Hint: access to the binary, the interpreter or "
				"shared libraries may be denied.\n");
			_exit(1);
		}

		/* Parent process: close ruleset fd and run the supervisor */
		close(ruleset_fd);
		return run_supervisor(supervisor_fd, pid);
	}

	/* Non-supervised mode: apply sandbox and exec directly */
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

err_close_ruleset:
	close(ruleset_fd);
	if (supervisor_fd >= 0)
		close(supervisor_fd);
	return 1;
}
