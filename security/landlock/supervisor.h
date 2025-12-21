/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

struct landlock_cred_security;
struct landlock_ruleset;
struct landlock_supervisor_decide_attr;
struct landlock_supervisor_event;
struct landlock_supervisor_listen_attr;
struct path;
struct task_struct;

/*
 * Returns a newly allocated ruleset domain representing the intersection of
 * all supervisor rulesets matching the current task, or NULL if none match.
 */
struct landlock_ruleset *
landlock_supervisor_resolve_current(struct landlock_ruleset *domain);

int landlock_supervisor_ruleset_listen(struct landlock_ruleset *ruleset,
				      const struct landlock_supervisor_listen_attr *attr);

int landlock_supervisor_ruleset_recv(struct landlock_ruleset *ruleset,
				    struct landlock_supervisor_event *event);

int landlock_supervisor_ruleset_decide(struct landlock_ruleset *ruleset,
				      const struct landlock_supervisor_decide_attr *attr);

void landlock_supervisor_ruleset_cleanup(struct landlock_ruleset *ruleset);

int landlock_supervisor_check_fs(const struct landlock_cred_security *subject,
				const struct path *path,
				unsigned int access);

int landlock_supervisor_check_signal(
	const struct landlock_cred_security *subject,
	const struct task_struct *target,
	int sig);

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
