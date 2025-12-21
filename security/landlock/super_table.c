// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock - Supervisor table
 *
 * Correlates supervisor tags to (mutable) rulesets.  A single tag may match
 * multiple rulesets; resolving a tag returns the merged ruleset.
 */

#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sort.h>
#include <linux/slab.h>

#include "ruleset.h"
#include "super_table.h"
#include "tag.h"

#define LANDLOCK_SUPER_TABLE_BITS 6

struct landlock_super_table_link {
	struct list_head list;
	struct landlock_ruleset *ruleset;
};

struct landlock_super_table_entry {
	struct hlist_node node;
	struct landlock_supervisor_tag tag;
	struct list_head rulesets;
};

struct landlock_super_table {
	refcount_t usage;
	struct mutex lock;
	DECLARE_HASHTABLE(buckets, LANDLOCK_SUPER_TABLE_BITS);
};

static struct landlock_super_table_entry *
find_entry(struct landlock_super_table *table,
	   const struct landlock_supervisor_tag *tag, const u32 key)
{
	struct landlock_super_table_entry *entry;

	hash_for_each_possible(table->buckets, entry, node, key) {
		if (landlock_supervisor_tag_equal(&entry->tag, tag))
			return entry;
	}
	return NULL;
}

struct landlock_super_table *landlock_super_table_create(void)
{
	struct landlock_super_table *table;

	table = kzalloc(sizeof(*table), GFP_KERNEL_ACCOUNT);
	if (!table)
		return NULL;

	refcount_set(&table->usage, 1);
	mutex_init(&table->lock);
	hash_init(table->buckets);
	return table;
}

void landlock_super_table_get(struct landlock_super_table *table)
{
	if (table)
		refcount_inc(&table->usage);
}

static void landlock_super_table_destroy(struct landlock_super_table *table)
{
	struct landlock_super_table_entry *entry;
	struct hlist_node *tmp;
	int bkt;

	if (!table)
		return;

	mutex_lock(&table->lock);
	hash_for_each_safe(table->buckets, bkt, tmp, entry, node) {
		struct landlock_super_table_link *link, *link_tmp;

		hash_del(&entry->node);
		list_for_each_entry_safe(link, link_tmp, &entry->rulesets, list) {
			list_del(&link->list);
			landlock_put_ruleset(link->ruleset);
			kfree(link);
		}
		landlock_supervisor_tag_destroy(&entry->tag);
		kfree(entry);
	}
	mutex_unlock(&table->lock);

	kfree(table);
}

void landlock_super_table_put(struct landlock_super_table *table)
{
	if (table && refcount_dec_and_test(&table->usage))
		landlock_super_table_destroy(table);
}

int landlock_super_table_add(struct landlock_super_table *table,
			     const struct landlock_supervisor_tag *tag,
			     struct landlock_ruleset *ruleset)
{
	struct landlock_super_table_entry *entry;
	struct landlock_super_table_link *link;
	u32 key;
	int err;

	if (!table || !tag || !ruleset)
		return -EINVAL;
	if (WARN_ON_ONCE(ruleset->num_layers != 1))
		return -EINVAL;

	key = landlock_supervisor_tag_hash(tag, 0);

	mutex_lock(&table->lock);
	entry = find_entry(table, tag, key);
	if (!entry) {
		entry = kzalloc(sizeof(*entry), GFP_KERNEL_ACCOUNT);
		if (!entry) {
			err = -ENOMEM;
			goto out_unlock;
		}

		INIT_LIST_HEAD(&entry->rulesets);
		err = landlock_supervisor_tag_clone(&entry->tag, tag);
		if (err) {
			kfree(entry);
			goto out_unlock;
		}

		hash_add(table->buckets, &entry->node, key);
	}

	list_for_each_entry(link, &entry->rulesets, list) {
		if (link->ruleset == ruleset) {
			err = 0;
			goto out_unlock;
		}
	}

	link = kzalloc(sizeof(*link), GFP_KERNEL_ACCOUNT);
	if (!link) {
		err = -ENOMEM;
		goto out_unlock;
	}
	landlock_get_ruleset(ruleset);
	link->ruleset = ruleset;
	list_add_tail(&link->list, &entry->rulesets);

	err = 0;

out_unlock:
	mutex_unlock(&table->lock);
	return err;
}

int landlock_super_table_del(struct landlock_super_table *table,
			     const struct landlock_supervisor_tag *tag,
			     struct landlock_ruleset *ruleset)
{
	struct landlock_super_table_entry *entry;
	struct landlock_super_table_link *link, *link_tmp;
	u32 key;
	int err = -ENOENT;

	if (!table || !tag || !ruleset)
		return -EINVAL;

	key = landlock_supervisor_tag_hash(tag, 0);

	mutex_lock(&table->lock);
	entry = find_entry(table, tag, key);
	if (!entry)
		goto out_unlock;

	list_for_each_entry_safe(link, link_tmp, &entry->rulesets, list) {
		if (link->ruleset != ruleset)
			continue;
		list_del(&link->list);
		landlock_put_ruleset(link->ruleset);
		kfree(link);
		err = 0;
		break;
	}

	if (list_empty(&entry->rulesets)) {
		hash_del(&entry->node);
		landlock_supervisor_tag_destroy(&entry->tag);
		kfree(entry);
	}

out_unlock:
	mutex_unlock(&table->lock);
	return err;
}

bool landlock_super_table_contains_ruleset(struct landlock_super_table *table,
					  struct landlock_ruleset *ruleset)
{
	struct landlock_super_table_entry *entry;
	struct landlock_super_table_link *link;
	int bkt;
	bool found = false;

	if (!table || !ruleset)
		return false;

	mutex_lock(&table->lock);
	hash_for_each(table->buckets, bkt, entry, node) {
		list_for_each_entry(link, &entry->rulesets, list) {
			if (link->ruleset == ruleset) {
				found = true;
				goto out_unlock;
			}
		}
	}

out_unlock:
	mutex_unlock(&table->lock);
	return found;
}

int landlock_super_table_swap_ruleset(struct landlock_super_table *table,
				      struct landlock_ruleset *old_ruleset,
				      struct landlock_ruleset *new_ruleset,
				      const struct landlock_supervisor_tag *new_tags,
				      size_t new_num_tags)
{
	struct landlock_super_table_entry *entry;
	struct landlock_super_table_link *link, *link_tmp;
	int bkt;
	size_t i;
	int err = 0;

	if (!table || !old_ruleset || !new_ruleset)
		return -EINVAL;
	if (WARN_ON_ONCE(old_ruleset->num_layers != 1 || new_ruleset->num_layers != 1))
		return -EINVAL;

	mutex_lock(&table->lock);

	/* Remove any existing links for @new_ruleset based on its provided tags. */
	for (i = 0; i < new_num_tags; i++) {
		struct landlock_super_table_entry *e;
		u32 key = landlock_supervisor_tag_hash(&new_tags[i], 0);

		e = find_entry(table, &new_tags[i], key);
		if (!e)
			continue;
		list_for_each_entry_safe(link, link_tmp, &e->rulesets, list) {
			if (link->ruleset != new_ruleset)
				continue;
			list_del(&link->list);
			landlock_put_ruleset(link->ruleset);
			kfree(link);
			break;
		}
		if (list_empty(&e->rulesets)) {
			hash_del(&e->node);
			landlock_supervisor_tag_destroy(&e->tag);
			kfree(e);
		}
	}

	/* Replace @old_ruleset by @new_ruleset everywhere. */
	hash_for_each(table->buckets, bkt, entry, node) {
		list_for_each_entry_safe(link, link_tmp, &entry->rulesets, list) {
			struct landlock_super_table_link *check;
			bool already = false;

			if (link->ruleset != old_ruleset)
				continue;

			list_for_each_entry(check, &entry->rulesets, list) {
				if (check->ruleset == new_ruleset) {
					already = true;
					break;
				}
			}

			list_del(&link->list);
			landlock_put_ruleset(link->ruleset);
			if (already) {
				kfree(link);
				continue;
			}
			landlock_get_ruleset(new_ruleset);
			link->ruleset = new_ruleset;
			list_add_tail(&link->list, &entry->rulesets);
		}
	}

	mutex_unlock(&table->lock);
	return err;
}

struct landlock_ruleset *
landlock_super_table_resolve(struct landlock_super_table *table,
			    const struct landlock_supervisor_tag *tag)
{
	struct landlock_super_table_entry *entry;
	struct landlock_super_table_link *link;
	struct landlock_ruleset **rulesets = NULL;
	struct landlock_ruleset *dom = NULL;
	u32 key;
	size_t count = 0, idx = 0;

	if (!table || !tag)
		return NULL;

	key = landlock_supervisor_tag_hash(tag, 0);

	mutex_lock(&table->lock);
	entry = find_entry(table, tag, key);
	if (!entry) {
		mutex_unlock(&table->lock);
		return NULL;
	}

	list_for_each_entry(link, &entry->rulesets, list)
		count++;

	if (!count) {
		mutex_unlock(&table->lock);
		return NULL;
	}

	rulesets = kcalloc(count, sizeof(*rulesets), GFP_KERNEL_ACCOUNT);
	if (!rulesets) {
		mutex_unlock(&table->lock);
		return ERR_PTR(-ENOMEM);
	}

	list_for_each_entry(link, &entry->rulesets, list) {
		landlock_get_ruleset(link->ruleset);
		rulesets[idx++] = link->ruleset;
	}
	mutex_unlock(&table->lock);

	for (idx = 0; idx < count; idx++) {
		struct landlock_ruleset *new_dom;

		new_dom = landlock_merge_ruleset(dom, rulesets[idx]);
		if (IS_ERR(new_dom)) {
			if (dom)
				landlock_put_ruleset(dom);
			dom = new_dom;
			goto out_put_rulesets;
		}
		if (dom)
			landlock_put_ruleset(dom);
		dom = new_dom;
	}

out_put_rulesets:
	for (idx = 0; idx < count; idx++)
		landlock_put_ruleset(rulesets[idx]);
	kfree(rulesets);
	return dom;
}

static int ruleset_ptr_cmp(const void *p1, const void *p2)
{
	const struct landlock_ruleset *a = *(const struct landlock_ruleset **)p1;
	const struct landlock_ruleset *b = *(const struct landlock_ruleset **)p2;

	if (a < b)
		return -1;
	if (a > b)
		return 1;
	return 0;
}

int landlock_super_table_gather_rulesets(
	struct landlock_super_table *table,
	const struct landlock_supervisor_tag *tags,
	u32 num_tags,
	struct landlock_ruleset ***rulesets_out,
	size_t *num_rulesets_out)
{
	size_t total = 0, idx = 0;
	struct landlock_ruleset **rulesets;
	u32 i;

	if (!rulesets_out || !num_rulesets_out)
		return -EINVAL;
	*rulesets_out = NULL;
	*num_rulesets_out = 0;

	if (!table || !tags || !num_tags)
		return 0;

	mutex_lock(&table->lock);
	for (i = 0; i < num_tags; i++) {
		struct landlock_super_table_entry *entry;
		struct landlock_super_table_link *link;
		u32 key;

		key = landlock_supervisor_tag_hash(&tags[i], 0);
		entry = find_entry(table, &tags[i], key);
		if (!entry)
			continue;
		list_for_each_entry(link, &entry->rulesets, list)
			total++;
	}

	if (!total) {
		mutex_unlock(&table->lock);
		return 0;
	}

	rulesets = kcalloc(total, sizeof(*rulesets), GFP_KERNEL_ACCOUNT);
	if (!rulesets) {
		mutex_unlock(&table->lock);
		return -ENOMEM;
	}

	for (i = 0; i < num_tags; i++) {
		struct landlock_super_table_entry *entry;
		struct landlock_super_table_link *link;
		u32 key;

		key = landlock_supervisor_tag_hash(&tags[i], 0);
		entry = find_entry(table, &tags[i], key);
		if (!entry)
			continue;
		list_for_each_entry(link, &entry->rulesets, list) {
			landlock_get_ruleset(link->ruleset);
			rulesets[idx++] = link->ruleset;
		}
	}
	mutex_unlock(&table->lock);

	/* Deduplicate by pointer value to produce stable merges. */
	sort(rulesets, idx, sizeof(*rulesets), ruleset_ptr_cmp, NULL);
	if (idx) {
		size_t out = 1;
		size_t j;

		for (j = 1; j < idx; j++) {
			if (rulesets[j] == rulesets[out - 1]) {
				landlock_put_ruleset(rulesets[j]);
				continue;
			}
			rulesets[out++] = rulesets[j];
		}
		idx = out;
	}

	*rulesets_out = rulesets;
	*num_rulesets_out = idx;
	return 0;
}
