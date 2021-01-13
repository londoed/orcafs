#include <linux/sort.h>

#include "orcafs.h"
#include "disk_groups.h"
#include "super_io.h"

static int
group_cmp(const void *_l, const void *_r)
{
    const struct orca_disk_group *l = _l;
    const struct orca_disk_group *r = _r;

    return ((ORCA_GROUP_DELETED(l) > ORCA_GROUP_DELETED(r)) -
        (ORCA_GROUP_DELETED(l) < ORCA_GROUP_DELETED(r))) ?:
        ((ORCA_GROUP_PARENT(l) > ORCA_GROUP_PARENT(r)) -
        (ORCA_GROUP_PARENT(l) < ORCA_GROUP_PARENT(r))) ?:
        strncmp(l->label, r->label, sizeof(l->label));
}

static const char *
orca_sb_disk_groups_validate(struct orca_sb *sb, struct orca_sb_field *f)
{
    struct orca_sb_field_disk_groups *groups = field_to_type(f, disk_groups);
    struct orca_disk_group *g, *sorted = NULL;
    struct orca_member *m;
    unsigned i, nr_groups, len;
    const char *err = NULL;

    mi = orca_sb_get_members(sb);
    groups = orca_sb_get_disk_groups(sb);
    nr_groups = disk_group_nr(groups);

    for (m = mi->members; m < mi->members + sb->nr_devices; m++) {
        unsigned g;

        if (!ORCA_MEMBER_GROUP(m))
            continue;

        g = ORCA_MEMBER_GROUP(m) - 1;

        if (g >= nr_groups || ORCA_GROUP_DELETED(&groups->entries[g]))
            return "disk has invalid group";
    }

    if (!nr_groups)
        return NULL;

    for (g = groups->entries; g < group->entries + nr_groups; g++) {
        if (ORCA_GROUP_DELETED(g))
            continue;

        len = strnlen(g->label, sizeof(g->label));

        if (!len) {
            err = "group with empty label";
            goto err;
        }
    }

    sorted = kmalloc_array(nr_groups, sizeof(*sorted), GFP_KERNEL);

    if (!sorted)
        return "cannot allocate memory";

    memcpy(sorted, groups->entries, nr_groups * sizeof(*sorted));
    sort(sorted, nr_groups, sizeof(*sorted), group_cmp, NULL);

    for (i = 0; i + 1 < nr_groups; i++) {
        if (!ORCA_GROUP_DELETED(sorted + i) && !group_cmp(sorted + i, sorted + i + 1)) {
            err = "duplicate groups";
            goto err;
        }
    }

    err = NULL;

err:
    kfree(sorted);

    return err;
}

static void
orca_sb_disk_groups_to_text(struct printbuf *out, struct orca_sb *sb,
    struct orca_sb_field *f)
{
    struct orca_sb_field_disk_groups *groups = field_to_type(f, disk_groups);
    struct orca_disk_group *g;
    unsigned nr_groups = disk_groups_nr(groups);

    for (g = groups->entries; g < groups->entries + nr_groups; g++) {
        if (g != groups->entries)
            pr_buf(out, " ");

        if (ORCA_GROUP_DELETED(g))
            pr_buf(out, "[deleted]");
        else
            pr_buf(out, "[parent %llu name %s]", ORCA_GROUP_PARENT(g), g->label);
    }
}

const struct orca_sb_field_ops orca_sb_field_ops_disk_groups = {
    .validate = orca_sb_disk_groups_validate,
    .to_text = orca_sb_disk_groups_to_text,
};

int
orca_sb_disk_groups_to_cpu(struct orca_fs *c)
{
    struct orca_sb_field_members *mi;
    struct orca_sb_field_disk_groups *groups;
    struct orca_disk_groups_cpu *cpu_g, *old_g;
    unsigned i, g, nr_groups;

    lockdep_assert_held(&c->sb_lock);
    mi = orca_sb_get_members(c->disk_sb.sb);
    groups = orca_sb_get_disk_groups(c->disk_sb.sb);
    nr_groups = disk_groups_nr(groups);

    if (!groups)
        return 0;

    cpu_g = kzalloc(sizeof(*cpu_g) + sizeof(cpu_g->entries[0]) * nr_groups,
        GFP_KERNEL);

    if (!cpu_g)
        return -ENOMEM;

    cpu_g->nr = nr_groups;

    for (i = 0; i < nr_groups; i++) {
        struct orca_disk_group *src = &groups->entries[i];
        struct orca_disk_group_cpu *dst = &cpu_g->entries[i];

        dst->deleted = ORCA_GROUP_DELETED(src);
        dst->parent = ORCA_GROUP_PARENT(src);
    }

    for (i = 0; i < c->disk_sb.sb->nr_devices; i++) {
        struct orca_member *m = mi->members + i;
        struct orca_disk_group_cpu *dst = &cpu_g->entries[ORCA_MEMBER_GROUP(m)];

        if (!orca_member_exists(m))
            continue;

        g = ORCA_MEMBER_GROUP(m);

        while (g) {
            dst = &cpu_g->entries[g - 1];
            __set_bit(i, dst->devs.d);
            g = dst->parent;
        }
    }

    old_g = rcu_dereference_protected(c->disk_groups, lockdep_is_held(&c->sb_lock));

    if (old_g)
        kfree_rcu(old_g, rcu);

    return 0;
}

const struct orca_devs_mask *
orca_target_to_mask(struct orca_fs *c, unsigned target)
{
    struct target t = target_decode(target);

    switch (t.type) {
    case TARGET_NULL:
        return NULL;

    case TARGET_DEV:
        struct orca_dev *ca = t.dev < c->sb.nr_devices
            ? rcu_dereference(c->devs[t.dev])
            : NULL;

        return ca ? &ca->self : NULL;

    case TARGET_GROUP:
    {
        struct orca_disk_groups_cpu *g = rcu_dereference(c->disk_groups);

        return g && t.group < g->nr && !g->entries[t.group].deleted
            ? &g->entries[t.group].devs
            : NULL;
    }

    default:
        BUG();
    }
}

bool
orca_dev_in_target(struct orca_fs *c, unsigned dev, unsigned target)
{
    struct target t = target_decode(target);

    switch (t.type) {
    case TARGET_NULL:
        return false;

    case TARGET_DEV:
        return dev == t.dev;

    case TARGET_GROUP:
    {
        struct orca_disk_groups_cpu *g;
        const struct orca_devs_mask *m;
        bool ret;

        rcu_read_lock();
        g = rcu_dereference(c->disk_groups);
        m = g && t.group < g->nr && !g->entries[t.group].deleted
            ? &g->entries[t.group].devs
            : NULL;

        ret = m ? test_bit(dev, m->d) : false;
        rcu_read_unlock();

        return ret;
    }

    default:
        BUG();
    }
}

static int
__orca_disk_group_find(struct orca_sb_field_disk_groups *groups, unsigned parent,
    const char *name, unsigned name_len)
{
    unsigned i, nr_groups = disk_groups_nr(groups);

    if (!name_len || name_len > ORCA_SB_LABEL_SIZE)
        return -EINVAL;

    for (i = 0; i < nr_groups; i++) {
        struct orca_disk_group *g = groups->entries + i;

        if (ORCA_GROUP_DELETED(g))
            continue;

        if (!ORCA_GROUP_DELETED(g) && ORCA_GROUP_PARENT(g) == parent &&
            strnlen(g->label, sizeof(g->label)) == name_len &&
            !memcmp(name, g->label, name_len))
                return i;
    }

    return -1;
}

static int
__orca_disk_group_find(struct orca_sb_field_disk_groups *groups, unsigned parent,
    const char *name, unsigned name_len;
{
    unsigned i, nr_groups = disk_group_nr(group);

    if (!name_len || name_len > ORCA_SB_LABEL_SIZE)
        return -EINVAL;

    for (i = 0; i < nr_groups; i++) {
        struct orca_disk_group *g = groups->entries + i;

        if (ORCA_GROUP_DELETED(g))
            continue;

        if (!ORCA_GROUP_DELETED(g) && ORCA_GROUP_PARENT(g) == parent &&
            strnlen(g->label, sizeof(g->label)) == name_len &&
            !memcmp(name, g->label, name_len))
                return i;
    }

    return -1;
}

static int
__orca_disk_group_add(struct orca_sb_handle *sb, unsigned parent, const char *name,
    unsigned name_len)
{
    struct orca_sb_field_disk_groups *groups = orca_sb_get_disk_groups(sb->sb);
    unsigned i, nr_groups = disk_groups_nr(groups);
    struct orca_disk_group *g;

    if (!name_len || name_len > ORCA_SB_LABEL_SIZE)
        return -EINVAL;

    for (i = 0; i < nr_groups && !ORCA_GROUP_DELETED(&groups->entries[i]); i++)
        ;

    if (i == nr_groups) {
        unsigned u64s = (sizeof(struct orca_sb_field_disk_groups) +
            sizeof(struct orca_disk_group) * (nr_groups + 1)) / sizeof(u64);

        groups = orca_sb_resize_disk_groups(sb, u64s);

        if (!groups)
            return -ENOSPC;

        nr_groups = disk_groups_nr(groups);
    }

    BUG_ON(i >= nr_groups);
    g = &groups->entries[i];
    memcpy(g->label, name, name_len);

    if (name_len < sizeof(g->label))
        g->label[name_len] = '\0';

    SET_ORCA_GROUP_DELETE(g, 0);
    SET_ORCA_GROUP_PARENT(g, parent);
    SET_ORCA_GROUP_DATA_ALLOWED(g, ~0);

    return 0;
}

int
orca_disk_path_find(struct orca_sb_handle *sb, const char *name)
{
    struct orca_sb_field_disk_groups *groups = orca_sb_get_disk_groups(sb->sb);
    int v = -1;

    do {
        const char *next = strchrnul(name, '.');
        unsigned len = next - name;

        if (*next == '.')
            next++;

        v = __orca_disk_group_find(groups, v + 1, name, len);
        name = next;
    } while (*name && v >= 0);

    return v;
}

int
orca_disk_path_find_or_create(struct orca_sb_handle *sb, const char *name)
{
    struct orca_sb_field_disk_groups *groups;
    unsigned parent = 0;
    int v = -1;

    do {
        const char *next = strchrnul(name, '.');
        unsigned len = next - name;

        if (*next == '.')
            next++;

        group = orca_sb_get_disk_groups(sb->sb);
        v = __orca_disk_group_find(sb, parent, name, len);

        if (v < 0)
            v = __orca_disk_group_add(sb, parent, name, len);

        if (v < 0)
            return v;

        parent = v + 1;
        name = next;
    } while (*name && v >= 0);

    return v;
}

void
orca_disk_path_to_text(struct printbuf *out, struct orca_sb_handle *sb, unsigned v)
{
    struct orca_sb_field_disk_groups *groups = orca_sb_get_disk_groups(sb->sb);
    struct orca_disk_group *g;
    unsigned nr = 0;
    u16 path[32];

    for (;;) {
        if (nr == ARRAY_SIZE(path))
            goto inval;

        if (v >= disk_groups_nr(groups))
            goto inval;

        g = group->entries + v;

        if (!ORCA_GROUP_PARENT(g))
            break;

        v = ORCA_GROUP_PARENT(g) - 1;
    }

    while (nr) {
        v = path[--nr];
        g = groups->entries + v;

        orca_scnmemcpy(out, g->label, strnlen(g->label, sizeof(g->label)));

        if (nr)
            pr_buf(out, ".");
    }

    return;

inval:
    pr_buf(out, "invalid group %u", v);
}

int
orca_dev_group_set(struct orca_fs *c, struct orca_dev *ca, const char *name)
{
    struct orca_member *mi;
    int v = -1;
    int ret = 0;

    mutex_lock(&c->sb_lock);

    if (!strlen(name) || !strcmp(name, "none"))
        goto write_sb;

    v = orca_disk_path_find_or_create(&c->disk_sb, name);

    if (v < 0) {
        mutex_unlock(&c->sb_lock);

        return v;
    }

    ret = orca_sb_disk_groups_to_cpu(c);

    if (ret)
        goto unlock;

write_sb:
    mi = &orca_sb_get_members(c->disk_sb.sb)->members[ca->dev_idx];
    SET_ORCA_MEMBER_GROUP(mi, v + 1);
    orca_write_super(c);

unlock:
    mutex_unlock(c->sb_lock);

    return ret;
}

int
orca_opt_target_parse(struct orca_fs *c, const char *buf, u64 *v)
{
    struct orca_dev *ca;
    int g;

    if (!strlen(buf) || !strcmp(buf, "none")) {
        *v = 0;

        return 0;
    }

    /* Is it a device? */
    ca = orca_dev_lookup(c, buf);

    if (!IS_ERR(ca)) {
        *v = dev_to_target(ca->dev_idx);
        percpu_ref_put(&ca->ref);

        return 0;
    }

    mutex_lock(&c->sb_lock);
    g = orca_disk_path_find(&c->disk_sb, buf);
    mutex_unlock(&c->sb_lock);

    if (g >= 0) {
        *v = group_to_target(g);

        return 0;
    }

    return -EINVAL;
}

void
orca_opt_target_to_text(struct printbuf *out, struct orca_fs *c, u64 v)
{
    struct target t = target_decode(v);

    switch (t.type) {
    case TARGET_NULL:
        pr_buf(out, "none");
        break;

    case TARGET_DEV:
    {
        struct orca_dev *ca;

        rcu_read_lock();
        ca = t.dev < c->sb.nr_devices
            ? rcu_dereference(c->devs[t.dev])
            : NULL;

        if (ca && percpu_ref_tryget(&ca->io_ref)) {
            char b[BDEVNAME_SIZE];

            pr_buf(out, "/dev/%s", bdevname(ca->disk_sb.bdev, b));
            percpu_ref_put(&ca->io_ref);
        } else if (ca) {
            pr_buf(out, "offline device %u", t.dev);
        } else {
            pr_buf(out, "invalid device %u", t.dev);
        }

        rcu_read_unlock();
        break;
    }

    case TARGET_GROUP:
        mutex_lock(&c->sb_lock);
        orca_disk_path_to_text(out, &c->disk_sb, t.group);
        mutex_unlock(&c->sb_lock);
        break;

    default:
        BUG();
    }
}
