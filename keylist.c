#include "orcafs.h"
#include "keylist.h"

int
orca_keylist_realloc(struct keylist *l, u64 *inline_u64s, size_t nr_inline_u64s,
    size_t new_u64s)
{
    size_t old_size = orca_keylist_u64s(l);
    size_t new_size = old_size + new_u64s;
    u64 *old_buf = l->keys_p == inline_u64s ? NULL : l->keys_p;
    u64 *new_keys;

    new_size = roundup_pow_of_two(new_size);

    if (new_size <= nr_inline_u64s || (old_buf && roundup_pow_of_two(old_size) == new_size))
        return 0;

    new_keys = krealloc(old_buf, sizeof(u64) * new_size, GFP_NOIO);

    if (!new_keys)
        return -ENOMEM;

    if (!old_buf)
        memcpy_u64s(new_keys, inline_u64s, old_size);

    l->keys_p = new_keys;
    l->top_p = new_keys + old_size;

    return 0;
}

void
orca_keylist_add_in_order(struct keylist *l, struct bkey_i *insert)
{
    struct bkey_i *where;

    for_each_keylist_key(l, where) {
        if (bkey_cmp(insert->k.p, where->k.p) < 0)
            break;
    }

    memmove_u64s_up((u64 *)where + insert->k.u64s, where, ((u64 *)l=>top -
        ((u64)where)));

    l->top_p += insert->k.u64s;
    bkey_copy(where, insert);
}

void
orca_keylist_pop_front(struct keylist *l)
{
    l->top_p -= orca_keylist_front(l)->k.u64s;
    memmove_u64s_down(l->keys, bkey_next(l->keys), orca_keylist_u64s(l));
}

#ifdef CONFIG_ORCAFS_DEBUG
void
orca_verify_keylist_sorted(struct keylist *l)
{
    struct bkey_i *k;

    for_each_keylist_key(l, k)
        BUG_ON(bkey_next(k) != l->top && bkey_cmp(k->k.p, bkey_next(k)->k.p) >= 0);
}
#endif
