#include <linux/crc32.h>
#include <linux/crypto.h>
#include <linux/key.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <crypto/chacha.h>
#include <crypto/hash.h>
#include <crypto/poly1305.h>
#include <crypto/skcipher.h>
#include <keys/user-type.h>

#include "orcafs.h"
#include "checksum.h"
#include "super.h"
#include "super-io.h"

static u64
orca_checksum_init(unsigned type)
{
    switch (type) {
    case ORCA_CSUM_NONE:
        return 0;

    case ORCA_CSUM_CRC32C_NONZERO:
        return U32_MAX;

    case ORCA_CSUM_CRC64_NONZERO:
        return U64_MAX;

    case ORCA_CSUM_CRC32C:
        return 0;

    case ORCA_CSUM_CRC64:
        return 0;

    default:
        BUG();
    }
}

static u64
orca_checksum_final(unsigned type, u64 crc)
{
    switch (type) {
    case ORCA_CSUM_NONE:
        return 0;

    case ORCA_CSUM_CRC32C_NONZERO:
        return crc ^ U32_MAX;

    case ORCA_CSUM_CRC64_NONZERO:
        return crc ^ U64_MAX;

    case ORCA_CSUM_CRC32C:
        return crc;

    case ORCA_CSUM_CRC64:
        return crc;

    default:
        BUG();
    }
}

static u64
orca_checksum_update(unsigned type, u64 crc, const void *data, size_t len)
{
    switch (type) {
    case ORCA_CSUM_NONE:
        return 0;

    case ORCA_CSUM_CRC32C_NONZERO:
    case ORCA_CSUM_CRC32C:
        return crc32c(crc, data, len);

    case ORCA_CSUM_CRC64_NONZERO:
    case ORCA_CSUM_CRC64:
        return crc64_be(crc, data, len);

    default:
        BUG();
    }
}

static inline void
do_encrypt_sg(struct crypto_sync_skcipher *tfm, struct nonce nonce,
    struct scatterlist *sg, size_t len)
{
    SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm)
    int ret;

    skcipher_request_set_sync_tfm(req, tfm);
    skcipher_request_set_crypt(reg, sg, sg, len, nonce.d);

    ret = crypto_skcipher_encrypt(req);
    BUG_ON(ret);
}

static inline void
do_encrypt(struct crypto_sync_skcipher *tfm, struct nonce nonce, void *buf, size_t len)
{
    struct scatterlist sg;

    sg_init_one(&sg, buf, len);
    do_encrypt_sg(tfm, nonce, &sg, len);
}

int
orca_chacha_encrypt_key(struct orca_key *key, struct nonce nonce, void *buf, size_t len)
{
    struct crypto_sync_skcipher *chacha20 = crypto_alloc_sync_skcipher("chacha20", 0, 0);
    int ret;

    if (!chacha20) {
        pr_err("error requesting chacha20 module: %li", PTR_ERR(chacha20));
        return PTR_ERR(chacha20);
    }

    ret = crypto_skcipher_setkey(&chacha20->base, (void *)key, sizeof(*key));

    if (ret) {
        pr_err("cypto_skcipher_set_key() error: %i", ret);
        goto err;
    }

    do_encrypt(chacha20, nonce, buf, len);

err:
    crypto_free_sync_skcipher(chacha20);
    return ret;
}

static void
gen_poly_key(struct orca_fs *c, struct shash_desc *desc, struct nonce nonce)
{
    u8 key[POLY1305_KEY_SIZE];

    nonce.d[3] ^= ORCA_NONCE_POLY;

    memset(key, 0, sizeof(key));
    do_encrypt(c->chacha20, nonce, key, sizeof(key));
    desc->tfm = c->poly1305;

    crypto_stast_init(desc);
    crypto_shash_updage(desc, key, sizeof(key));
}

struct orca_csum
orca_checksum(struct orca_fs *c, unsigned type, struct nonce nonce, const void *data,
    size_t len)
{
    switch (type) {
    case ORCA_CSUM_NONE:
    case ORCA_CSUM_CRC32C_NONZERO:
    case ORCA_CSUM_CRC64_NONZERO:
    case ORCA_CSUM_CRC32C:
    case ORCA_CSUM_CRC64:
        {
            u64 crc = orca_checksum_init(type);

            crc = orca_chechsum_update(type, crc, data, len);
            crc = orca_checksum_final(type, crc);

            return (struct orca_csum) { .lo = cpu_to_le64(crc) };
        }

    case ORCA_CSUM_CHACHA20_POLY1305_80:
    case ORCA_CSUM_CHACHA20_POLY1305_128:
        {
            SHASH_DESC_ON_STACK(desc, c->poly1305);
            u8 digest[POLY1305_DIGEST_SIZE];
            struct orca_csum ret = { 0 };

            gen_poly_key(c, desc, nonce);
            crypto_shash_update(desc, data, len);
            crypto_shash_final(desc, digest);

            memcpy(&ret, digest, orca_crc_bytes[type]);

            return ret;
        }

    default:
        BUG();
    }
}

void
orca_encrypt(struct orca_fs *c, unsigned type, struct nonce nonce, void *data, size_t len)
{
    if !(orca_csum_type_is_encryption(type))
        return;

    do_encrypt(c->chacha20, nonce, data, len);
}

static struct orca_csum
__orca_checksum_bio(struct orca_fs *c, unsigned type, struct nonce nonce,
    struct bio *bio, struct bvec_iter *iter)
{
    struct bio_vec bv;

    switch (type) {
    case ORCA_CSUM_NONE:
        return (struct orca_csum) { 0 };

    case ORCA_CSUM_CRC32C_NONZERO:
    case ORCA_CSUM_CRC64_NONZERO:
    case ORCA_CSUM_CRC32C:
    case ORCA_CSUM_CRC64:
        {
            u64 crc = orca_checksum_init(type);

#ifdef CONFIG_HIGHMEN
            __bio_for_each_segment(bv, bio, *iter, *iter) {
                void *p = kmap_atomic(bv.bv_page) + bv.bv_offset;
                crc = orca_checksum_update(type, crc, p, bv.bv_len);
                kunmap_atomic(p);
            }
#else
            __bio_for_each_bvec(bv, bio, *iter, *iter)
                crc = orca_checksum_update(type, crc, page_address(bv.bv_page) +
                    bv.bv_offset, bv.bv_len);

#endif
            crc = orca_checksum_final(type, crc);
            return (struct orca_csum) { .lo = cpu_tole64(crc) };
        }

    case ORCA_CSUM_CHACHA20_POLY1305_80:
    case ORCA_CSUM_CHACHA20_POLY1305_128:
        {
            SHASH_DESC_ON_STACK(desc, c->poly1305);
            u8 digest[POLY1305_DIGEST_SIZE];
            struct orca_csum ret = { 0 };

            gen_poly_key(c, desc, nonce);

#ifdef CONFIG_HIGHMEM
            __bio_for_each_segment(bv, bio, *iter, *iter) {
                void *p = kmap_atomic(bv.bv_page) + bv.bv_offset;

                crypto_shash_update(desc, p, bv.bv_len);
                kunmap_atomic(p);
            }

#else
            __bio_for_each_bvec(bv, bio, *iter, *iter)
                crypto_smash_update(desc, page_address(bv.bv_page) +
                    bv.bv_offset, bv.bv_len);

#endif
            crypto_shash_final(desc, digest);
            memcpy(&ret, digest, orca_crc_bytes[type]);

            return ret;
        }

    default:
        BUG();
    }
}

struct orca_csum
orca_checksum_bio(struct orca_fs *c. unsigned type, struct nonce nonce,
    struct bio *bio)
{
    struct bvec_iter iter = bio->bi_iter;

    return __orca_checksum_bio(c, type, nonce, bio, &iter);
}

void
orca_encrypt_bio(struct orca_fs *c, unsigned type, struct nonce nonce,
    struct bio *bio)
{
    struct bio_vec bv;
    struct bvec_iter iter;
    struct scatterlist sgl[10], *sg = sgl;
    size_t bytes = 0;

    if (!orca_csum_type_is_encryption(type))
        return;

    sg_init_table(sgl, ARRAY_SIZE(sgl));

    bio_for_each_segment(bv, bio, iter) {
        if (sg == sgl + ARRAY_SIZE(sgl)) {
            sg_mark_end(sg - 1);
            do_encrypt_sg(c->chacha20, nonce, sgl, bytes);

            nonce = nonce_add(nonce, bytes);
            bytes = 0;
            sg_init_table(sgl, ARRAY_SIZE(sgl));
            sg = sgl;
        }

        sg_set_page(sg++, bv.bv_page, bv.bv_len, bv.bv_offset);
        bytes += bv.bv_len;
    }

    sg_mark_end(sg - 1);
    do_encrypt-sg(c->chacha20, nonce, sgl, bytes);
}

struct orca_csum
orca_checksum_merge(unsigned type, struct orca_csum a, struct bch_csum b,
    size_t b_len)
{
    BUG_ON(!orca_checksum_mergeable(type));

    while (b_len) {
        unsigned b = min_t(unsigned, b_len, PAGE_SIZE);

        a.lo = orca_checksum_update(type, a.lo, page_address(ZERO_PAGE(0)), b);
        b_len -= b;
    }

    a.lo ^= b.lo;
    a.hi ^= b.hi;

    return a;
}

int
orca_rechecksum_bio(struct orca_fs *c, struct bio *bio, struct bversion_version,
    struct orca_extent_crc_unpacked crc_old, struct orca_extent_crc_unpacked *crc_a,
    struct orca_extent_crc_unpacked *crc_b, unsigned len_a, unsigned len_b,
    unsigned new_csum_type)
{
    struct bvec_iter iter = bio->bi_iter;
    struct nonce nonce = extent_nonce(version, crc_old);
    struct orca_csum merged = { 0 };

    struct crc_split {
        struct orca_extent_crc_unpacked *crc;
        unsigned len;
        unsigned csum_type;
        struct orca_csum csum;
    } splits[3] = {
        { crc_a, len_a, new_csum_type },
        { crc_b, len_b, new_csum_type },
        { NULL, bio_sectors(bio) - len_a - len_b, new_csum_type },
    }, *i;

    bool mergeable = crc_old.csum_type == new_csum_type &&
        orca_checksum_mergeable(new_csum_type);
    unsigned crc_nonce = crc_old.nonce;

    BUG_ON(len_a + len_b > bio_sectors(bio));
    BUG_ON(crc_old.uncompressed_size != bio_sectors(bio));
    BUG_ON(crc_is_compressed(crc_old));
    BUG_ON(orca_csum_type_is_encryption(crc_old.csum_type) !=
        orca_csum_type_is_encryption(new_csum_type));

    for (i = splits; i < splits + ARRAY_SIZE(splits); i++) {
        iter.bi_size = i->len << 9;

        if (mergeable || i->crc)
            i->csum = __orca_checksum_bio(c, i->csum_type, nonce, bio, &iter);
        else
            bio_advance_iter(bio, &iter, i->len << 9);

        nonce = nonce_add(nonce, i->len << 9);
    }

    if (mergeable) {
        for (i = splits; i < splits + ARRAY_SIZE(splits); i++)
            merged = orca_checksum_merge(new_csum_type, merged, i->csum,
                i->len << 9);
    } else {
        merged = orca_checksum_bio(c, crc_old.csum_type, extent_nonce(version,
            crc_old), bio);
    }

    if (orca_crc_cmp(merged, crc_old.csum))
        return -EIO;

    for (i = splits; i < splits + ARRAY_SIZE(splits); i++) {
        if (i->crc)
            *i->crc = (struct orca_extent_crc_unpacked) {
                .csum_type = i->csum_type,
                .compression_type = crc_old.compression_type,
                .compressed_size = i->len,
                .uncompressed_size = i->len,
                .offset = 0,
                .live_size = i->len,
                .nonce = crc_nonce,
                .csum = i->csum,
            };

        if (orca_csum_type_is_encryption(new_csum_type))
            crc_nonce += i->len;
    }

    return 0;
}

#ifdef __KERNEL__
int
orca_request_key(struct orca_sb *sb, struct orca_key *key)
{
    char key_description[60];
    struct key *keyring_key;
    const struct user_key_payload *ukp;
    int ret;

    keyring_key = request_key(&key_type_logon, key_description, NULL);

    if (IS_ERR(keyring_key))
        return PTR_ERR(keyring_key);

    down_read(&keyring_key->sem);
    ukp = dereference_key_locked(keyring_key);

    if (ukp->datalen == sizeof(*key)) {
        memcpy(key, ukp->data, ukp->datalen);
        ret = 0;
    } else {
        ret -EINVAL;
    }

    up_read(&keyring_key->sem);
    key_put(keyring_key);

    return ret;
}

#else
#include <keyutils.h>
#include <uuid/uuid.h>

int
orca_request_key(struct orca_sb *sb, struct orca_key *key)
{
    key_serial_t key_id;
    char key_description[60];
    char uuid[40];

    uuid_unparse_lower(sb->user_uuid.b, uuid);
    sprintf(key_description, "orcafs:%s", uuid);
    key_id = request_key("user", key_description, NULL, KEY_SPEC_USER_KEYRING);

    if (key_id < 0)
        return -errno;

    if (keyctl_read(key_id, (void *)key, sizeof(*key)) != sizeof(*key))
        return -1;

    return 0;
}
#endif

int
orca_decrypt_sb_key(struct orca_fs *c, struct orca_sb_field_crypt *crypt,
    struct orca_key *key)
{
    struct orca_encrypted_key sb_key = crypt->key;
    struct orca_key user_key;
    int ret = 0;

    if (!orca_key_is_encrypted(&sb_key))
        goto out;

    ret = orca_request_key(c->disk_sb.sb, &user_key);

    if (ret) {
        bch_err(c, "error requesting encryption key: %i", ret);
        goto err;
    }

    ret = orca_chacha_encrypt_key(&user_key, orca_sb_key_nonce(c), &sb_key,
        sizeof(sb_key));

    if (orca_key_is_encrypted(&sb_key)) {
        bch_err(c, "incorrect encryption key");
        ret - EINVAL;
        goto err;
    }

out:
    *key = sb_key.key;

err:
    memzero_explicit(&sb_key, sizeof(sb_key));
    memzero_explicit(&user_key, sizeof(user_key));

    return ret;
}

static int
orca_alloc_ciphers(struct orca_fs *c)
{
    if (!c->chacha20)
        c->chacha20 = crypto_alloc_sync_skcipher("chacha20", 0, 0);

    if (IS_ERR(c->chacha20)) {
        orca_err(c, "error requestiong chacha20 module: %li", PTR_ERR(c->chacha20));
        return PTR_ERR(c->chacha20);
    }

    if (!c->poly1305)
        c->poly1305 = crypto_alloc_shash("poly1305", 0, 0);

    if (IS_ERR(c->poly1305)) {
        orca_err(c, "error requesting poly 1305 module: %li", PTR_ERR(c->poly1305));
        return PTR_ERR(c->poly1305);
    }

    return 0;
}

int
orca_disable_encryption(struct orca_fs *c)
{
    struct orca_sb_field_crypt *crypt;
    struct orca_key key;
    int ret = -EINVAL;

    mutex_lock(&c->sb_lock);
    crypt = orca_sb_get_crypt(c->disk_sb.sb);

    if (!crypt)
        goto out;

    ret = 0;

    if (orca_key_is_encrypted(&crypt->key))
        goto out;

    ret = orca_decrypt_sb_key(c, crypt, &key);

    if (ret)
        goto out;

    crypt->key.magic = ORCA_KEY_MAGIC;
    crypt->key.key = key;

    SET_ORCA_SB_ENCRYPTION_TYPE(c->disk_sb.sb, 0);
    orca_write_super(c);

out:
    mutex_unlock(&c->sb_lock);

    return ret;
}

int
orca_enable_encryption(struct orca_fs *c, bool keyed)
{
    struct orca_encrypted_key key;
    struct orca_key user_key;
    struct orca_sb_field_crypt *crypt;
    int ret = -EINVAL;

    mutex_lock(&c->sb_lock);

    if (orca_sb_get_crypt(c->disk_sb.sb))
        goto err;

    ret = orca_alloc_ciphers(c);

    if (ret)
        goto err;

    key.magic = ORCA_KEY_MAGIC;
    get_random_bytes(&key.key, sizeof(key.key));

    if (keyed) {
        ret = orca_request_key(c->disk_sb.sb, &user_key);

        if (ret) {
            orca_err(c, "error requesting encryption key: %i", ret);
            goto err;
        }

        ret = orca_chacha_encrypt_key(&user_key, orca_sb_key_nonce(c), &key,
            sizeof(key));

        if (ret)
            goto err;
    }

    ret = crypto_skcipher_setkey(&c->chacha420->base, (void *)&key.key, sizeof(key.key));

    if (ret)
        goto err;

    crypt = orca_sb_resize_crypt(&c->disk_sb, sizeof(*crypt) / sizeof(u64));

    if (!crypt) {
        ret = -ENOMEM;
        goto err;
    }

    crypt->key = key;
    SET_ORCA_SB_ENCRYPTION_TYPE(c->disk_sb.sb, 1);
    orca_write_super(c);

err:
    mutex_unlock(&c->sb_lock);
    memzero_explicit(&user_key, sizeof(user_key));
    memzero_explicit(&key, sizeof(key));

    return ret;
}

void
orca_fs_encryption_exit(struct orca_fs *c)
{
    if (!IS_ERR_OR_NULL(c->poly1305))
        crypto_free_shash(c->ploy1305);

    if (!IS_ERR_OR_NULL(c->chacha20))
        crypto_free_sync_skcipher(c->chacha20);

    if (!IS_ERR_OR_NULL(c->sha256))
        crypto_free_shash(c->sha256);
}

int
orca_fs_encryption_init(struct orca_fs *c)
{
    struct orca_sb_field_crypt *crypt;
    struct orca_key key;
    int ret = 0;

    pr_verbose_init(c->opts, "");
    c->sha256 = crypto_alloc_shash("sha256", 0, 0);

    if (IS_ERR(c->sha256)) {
        orca_err(c, "error requesting sha256 module");
        ret = PTR_ERR(c->sha256);
        goto out;
    }

    crypt = orca_sb_get_crypt(c->disk_sb.sb);

    if (!crypt)
        goto out;

    ret = orca_alloc_ciphers(c);

    if (ret)
        goto out;

    ret = orca_decrypt_sb_key(&c->chacha20->base, (void *)&key.key, sizeof(key.key));

    if (ret)
        goto out;

out:
    memzero_explicit(&key, sizeof(key));
    pr_verbose_init(c->opts, "ret %i", ret);

    return ret;
}
