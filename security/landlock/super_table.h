/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SECURITY_LANDLOCK_SUPER_TABLE_H
#define _SECURITY_LANDLOCK_SUPER_TABLE_H

#include <linux/stddef.h>
#include <linux/types.h>

struct landlock_ruleset;
struct landlock_supervisor_tag;
struct landlock_super_table;

struct landlock_super_table *landlock_super_table_create(void);

void landlock_super_table_get(struct landlock_super_table *table);
void landlock_super_table_put(struct landlock_super_table *table);

int landlock_super_table_add(struct landlock_super_table *table,
			     const struct landlock_supervisor_tag *tag,
			     struct landlock_ruleset *ruleset);

int landlock_super_table_del(struct landlock_super_table *table,
			     const struct landlock_supervisor_tag *tag,
			     struct landlock_ruleset *ruleset);

bool landlock_super_table_contains_ruleset(struct landlock_super_table *table,
					  struct landlock_ruleset *ruleset);

int landlock_super_table_swap_ruleset(struct landlock_super_table *table,
				      struct landlock_ruleset *old_ruleset,
				      struct landlock_ruleset *new_ruleset,
				      const struct landlock_supervisor_tag *new_tags,
				      size_t new_num_tags);

struct landlock_ruleset *
landlock_super_table_resolve(struct landlock_super_table *table,
			    const struct landlock_supervisor_tag *tag);

int landlock_super_table_gather_rulesets(
	struct landlock_super_table *table,
	const struct landlock_supervisor_tag *tags,
	u32 num_tags,
	struct landlock_ruleset ***rulesets_out,
	size_t *num_rulesets_out);

#endif /* _SECURITY_LANDLOCK_SUPER_TABLE_H */
