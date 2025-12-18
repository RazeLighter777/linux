/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock - Supervisor support
 */

#ifndef _SECURITY_LANDLOCK_SUPERVISOR_H
#define _SECURITY_LANDLOCK_SUPERVISOR_H

#include "ruleset.h"

struct path;
struct landlock_supervisor;

#ifdef CONFIG_AUDIT
int landlock_create_supervisor_fd(struct landlock_ruleset *domain);

/* Called by landlock_put_hierarchy(). */
void landlock_put_supervisor(struct landlock_supervisor *supervisor);

int landlock_supervisor_enforce_fs(const struct landlock_ruleset *domain,
				  const struct path *path,
				  access_mask_t access_request);

#if IS_ENABLED(CONFIG_INET)
int landlock_supervisor_enforce_net(const struct landlock_ruleset *domain,
				   u16 port,
				   access_mask_t access_request);
#endif /* IS_ENABLED(CONFIG_INET) */
#endif /* CONFIG_AUDIT */

#endif /* _SECURITY_LANDLOCK_SUPERVISOR_H */
