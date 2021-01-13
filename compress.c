#include <linux/lz4.h>
#include <linux/zlib.h>
#include <linux/zstd.h>

#include "orcafs.h"
#include "checksum.h"
#include "compress.h"
#include "extents.h"
#include "io.h"
#include "super_io.h"

/* Bounce buffer */
struct bbuf {
    void *b;
    enum {
        BB_NONE, BB_VMAP, BB_KMALLOC, BB_MEMPOOL,
    } type;
    int rw;
};

static struct bbuf
__bounce_alloc(struct orca_fs *c, unsigned size, int rw)
{
    void *b;

    BUG_ON(size > c->sb.encoded_extent_max << 9);
    b = kmalloc(size, GFP_NOIO | __GFP_NOWARN);

    if (b)
        return (struct bbuf) {
            .b = b,
            .type = BB_KMALLOC,
            .rw = rw
        };

    b = mempool_alloc(&c->compression_bounce[rw], GFP_NOIO);

    if (b)
        return (struct bbuf) {
            .b = b,
            .type = BB_MEMPOOL,
            .rw = rw,
        };

    BUG();
}

static bool
bio_phys_contig(struct bio *bio, struct bvec_iter start)
{
    struct bio_vec bv;
    struct bvec_iter iter;
    void *expected_start = NULL;

    __bio_for_each_bvec(bv, bio, iter, start) {
        if (expected_start && expected_start != page_address(bv.bv_page +
            bv.bv_offset))
                return false;

        expected_start = page_address(bv.bv_page) + bv.bv_offset + bv.bv_len;
    }

    return true;
}

static struct bbuf
__bio_map_or_bounce(struct orca_fs *c, struct bio *bio, struct bvec_iter start,
    int rw)
{
    struct bbuf ret;
    struct bio_vec bv;
    struct bvec_iter iter;
    unsigned nr_pages = 0;
    struct page *stack_pages[16];
    struct page **pages = NULL;
    void *data;

    BUG_ON(bvec_iter_sectors(start) > c->sb.encoded_extent_max);

    if (!PageHighMem(bio_iter_page(bio, start)) && bio_phys_contig(bio, start))
        return (struct bbuf) {
            .b = page_address(bio_iter_page(bio, start)) +
                bio_iter_offset(bio, start),
            .type = BB_NONE,
            .rw = rw,
        };

    /* Check if we can map the pages contiguously */
    __bio_for_each_segment(bv, bio, iter, start) {
        if (iter.bi_size != start.bi_size && bv.bv_offset)
            goto bounce;

        if (bv.bv_len < iter.bi_size && bv.bv_offset + bv.bv_len < PAGE_SIZE)
            goto bounce;

        nr_pages++;
    }

    BUG_ON(DIV_ROUND_UP(start.bi_size, PAGE_SIZE) > nr_pages);

    pages = nr->pages > ARRAY_SIZE(stack_pages)
        ? kmalloc_array(nr_pages, sizeof(struct page *), GFP_NOIO)
        : stack_pages;

    if (!pages)
        goto bounce;

    nr_pages = 0;

    __bio_for_each_segment(bv, bio, iter, start)
        pages[nr_pages++] = bv.bv_page;

    data = vmap(pages, nr_pages, VM_MAP, PAGE_KERNEL);

    if (pages != stack_pages)
        kfree(pages);

    if (data)
        return (struct bbuf) {
            .b = data + bio_iter_offset(bio, start),
            .type = BB_VMAP,
            .rw = rw,
        };

bounce:
    ret = __bounce_alloc(c, start.bi_size, rw);

    if (rw == READ)
        memcpy_from_bio(ret.b, bio, start);

    return ret;
}

static struct bbuf
bio_map_or_bounce(struct orca_fs *c, struct bio *bio, int rw)
{
    return __bio_map_or_bounce(c, bio, bio->bi_iter, rw);
}

static void
bio_unmap_or_unbounce(struct orca_fs *c, struct bbuf buf)
{
    switch (buf.type) {
    case BB_NONE:
        break;

    case BB_VMAP:
        vunmap((void *)((unsigned long)buf.b & PAGE_MASK));
        break;

    case BB_KMALLOC:
        kfree(buf.b);
        break;

    case BB_MEMPOOL:
        mempool_free(buf.b, &c->compression_bounce[buf.rw]);
        break;
    }
}

static inline void
zlib_set_workspace(z_stream *strm, void *workspace)
{
#ifdef __KERNEL__
    strm->workspace = workspace;
#endif
}

static int
__bio_uncompress(struct orca_fs *c, struct bio *src, void *dst_data,
    struct orca_extent_crc_unpacked crc)
{
    struct bbuf src_data = { NULL };
    size_t src_len = src->bi_iter.bi_size;
    size_t dst_len = crc.uncompressed_size << 9;
    void *workspace;
    int ret;

    src_data = bio_map_or_bounce(c, src, READ);

    switch (crc.compression_type) {
    case ORCA_COMPRESSION_TYPE_lz4_old:
    case ORCA_COMPRESSION_TYPE_lz4:
        ret = LZ4_decompress_safe_partial(src_data.b, dst_data, src_len, dst_len,
            dst_len);

        if (ret != dst_len)
            goto err;

        break;

    case ORCA_COMPRESSION_TYPE_gzip:
    {
        z_stream strm = {
            .next_it = src_data.b,
            .avail_it = src_len,
            .next_out = dst_data,
            .avail_out = dst_len,
        };

        workspace = mempool_alloc(&c->decompress_workspace, GFP_NOIO);
        zlib_set_workspace(&strm, workspace);
        zlib_inflateInit2(&strm, Z_FINISH);
        mempool_free(workspace, &c->decompress_workspace);

        if (ret != Z_STREAM_END)
            goto err;

        break;
    }

    case ORCA_COMPRESSION_TYPE_zstd:
    {
        ZSTD_DCtx *ctx;
        size_t real_src_len = le32_to_cpup(src_data.b);

        if (real_src_len > src_len - 4)
            goto err;

        workspace = mempool_alloc(&c->decompress_workspace, GFP_NOIO);
        ctx = ZSTD_initDCtx(workspace, ZSTD_DCtxWorkspaceBound());
        ret = ZSTD_decompressDCtx(ctx, dst_data, dst_len, src_data.b + 4,
            real_src_len);

        mempool_free(workspace, &c->decompress_workspace);

        if (ret != dst_len)
            goto err;

        break;
    }

    default:
        BUG();
    }

    ret = 0;

out:
    bio_unmap_or_unbounce(c, src_data);

    return ret;

err:
    ret = -EIO;
    goto out;
}

int
orca_bio_uncompress_inplace(struct orca_fs *c, struct bio *bio,
    struct orca_extent_crc_unpacked *crc)
{
    struct bbuf data = { NULL };
    size_t dst_len = crc->uncompressed_size << 9;

    /* Bio must own its pages */
    BUG_ON(!bio->bi_vcnt);
    BUG_ON(DIV_ROUND_UP(crc->live_size, PAGE_SECTORS) > bio->bi_max_vecs);

    if (crc->uncompressed_size > c->sb.encoded_extent_max ||
        crc->compressed_size > c->sb.encoded_extent_max) {
            orca_err(c, "error rewriting existing data: "
                "extent too big");
            return -EIO;
    }

    data = __bounce_alloc(c, dst_len, WRITE);

    if (__orca_uncompress(c, bio, data.b, *crc)) {
        orca_err(c, "error rewriting existing data: decompression error");
        bio_unmap_or_unbounce(c, data);

        return -EIO;
    }

    /**
     * Don't hvae a good way to assert that the bio was allocated with
     * enough space, we depend on orca_move_extent doing the right
     * thing.
    **/
    bio->bi_iter.bi_size = crc->live_size << 9;
    memcpy_to_bio(bio, bio->bi_iter, data.b + (crc->offset << 9));

    crc->csum_type = 0;
    crc->compression_type = 0;
    crc->compressed_size = crc->live_size;
    crc->uncompressed_size = crc->live_size;
    crc->offset = 0;
    crc->csum = (struct orca_csum) { 0, 0 };

    bio_unmap_or_unbounce(c, data);

    return 0;
}

int
orca_bio_uncompress(struct orca_fs *c, struct bio *src, struct bio *dst,
    struct bvec_iter dst_iter, struct orca_extent_crc_unpacked crc)
{
    struct bbuf dst_data = { NULL };
    size_t dst_len = crc.uncompressed_size << 9;
    int ret = -ENOMEM;

    if (crc.uncompressed_size > c->sb.encoded_extent_max ||
        crc.compressed_size > c->sb.encoded_extent_max)
            return -EIO;

    dst_data = dst_len == dst_iter.bi_size
        ? __bio_map_or_bounce(c, dst, dst_iter, WRITE)
        : __bounce_alloc(c, dst_len, WRITE);

    ret = __bio_uncompress(c, stc, dst_data.b, crc);

    if (ret)
        goto err;

    if (dst_data.type != BB_NONE && dst_data.type != BB_VMAP)
        memcpy_to_bio(dst, dst_iter, dst_data.b + (crc.offset << 9));

err:
    bio_unmap_or_unbounce(c, dst_data);

    return ret;
}

static int
attempt_compress(struct orca_fs *c, void *workspace, void *dst, size_t dst_len,
    void *src, size_t src_len, enum orca_compression_type compression_type)
{
    switch (compression_type) {
    case ORCA_COMPRESSION_TYPE_lz4:
    {
        int len = src_len;
        int ret = LZ4_compress_destSize(src, dst, &len, dst_len, workspace);

        if (len < src_len)
            return -len;

        return ret;
    }

    case ORCA_COMPRESSION_TYPE_gzip:
    {
        z_stream strm = {
            .next_in = src,
            .avail_in = src_len,
            .next_out = dst,
            .avail_out = dst_len,
        };

        zlib_set_workspace(&strm, workspace);
        zlib_deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
            DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);

        if (zlib_deflate(&strm, Z_FINISH) != Z_STREAM_END)
            return 0;

        if (zlib_deflateEnd(&strm) != Z_OK)
            return 0;

        return strm.total_out;
    }

    case ORCA_COMPRESSION_TYPE_zstd:
    {
        ZSTD_CCtx *ctx = ZSTD_initCCtx(workspace,
            ZSTD_CCtxWorkspaceBound(c->zstd_params.cParams));
        size_t len = ZSTD_compressCCtx(ctx, dst + 4, dst_len - 4,
            src, src_len, c->zstd_params);

        if (ZSTD_isError(len))
            return 0;

        *((__le32 *)dst) = cpu_to_le32(len);

        return len + 4;
    }

    default:
        BUG();
    }
}

static unsigned
__bio_compress(struct orca_fs *c, struct bio *dst, size_t *dst_len, struct bio *src,
    size_t *src_len, enum orca_compression_type compression_type)
{
    struct bbuf src_data = { NULL }, dst_data = { NULL };
    void *workspace;
    unsigned pad;
    int ret = 0;

    BuG_ON(compression_type >= ORCA_COMPRESSION_TYPE_NR);
    BUG_ON(!mempool_initialized(&c->compress_workspace[compression_type]));

    /* If it's only one block, don't bother trying to compress */
    if (bio_sectors(src) <= c->opts.block_size)
        return 0;

    dst_data = bio_map_or_bounce(c, dst, WRITE);
    src_data = bio_map_or_bounce(c, src, READ);
    workspace = mempool_alloc(&c->compress_workspace[compression_type], GFP_NOIO);
    *src_len = src->bi_iter.bi_size;
    *dst_len = dst->bi_iter.bi_size;

    for (;;) {
        if (*src_len <= block_bytes(c)) {
            ret = -1;
            break;
        }

        ret = attempt_compress(c, workspace, dst_data.b, *dst_len, src_data.b,
            *src_len, compression_type);

        if (ret > 0) {
            *dst_len = ret;
            ret = 0;
            break;
        }

        /* Didn't fit: should we retry with a smaller amount? */
        if (*src_len <= *dst_len) {
            ret = -1;
            break;
        }

        /**
         * If ret is negative, it's a hint as to how much data would fit.
        **/
        BUG_ON(-ret >= *src_len);

        if (ret < 0)
            *src_len = -ret;
        else
            *src_len -= (*src_len - *dst_len) / 2;

        *src_len = round_down(*src_len, block_bytes(c));
    }

    mempool_free(workspace, &c->compress_workspace[compression_type]);

    if (ret)
        goto err;

    /* Didn't get smaller */
    if (round_up(*dst_len, block_bytes(c)) >= *src_len)
        goto err;

    pad = round_up(*dst_len, block_bytes(c)) - *dst_len;
    memset(dst_data.b + *dst_len, 0, pad);
    *dst_len += pad;

    if (dst_data.type != BB_NONE && dst_data.type != BB_VMAP)
        memcpy_to_bio(dst, dst->bi_iter, dst_data.b);

    BUG_ON(!*dst_len || *dst_len > dst->bi_iter.bi_size);
    BUG_ON(!*src_len || *src_len > src->bi_iter.bi_size);
    BUG_ON(*dst_len & (block_bytes(c) - 1));
    BUG_ON(*src_len & (block_bytes(c) - 1));

out:
    bio_unmap_or_unbounce(c, src_data);
    bio_unmap_or_unbounce(c, dst_data);

    return compression_type;

err:
    compression_type = ORCA_COMPRESSION_TYPE_incompressible;
    goto out;
}

unsigned
orca_bio_compress(struct orca_fs *c, struct bio *dst, size_t *dst_len,
    struct bio *src, size_t *src_len, unsigned compression_type)
{
    unsigned orig_dst = dst->bi_iter.bi_size;
    unsigned orig_src = src->bi_iter.bi_size;

    /* Don't consume more than ORCA_ENCODED_EXTENT_MAX from @src */
    src->bi_iter.bi_size = min_t(unsigned, src->bi_iter.bi_size,
        c->sb.encoded_extent_max << 9);

    /* Don't generate a bigger output than input */
    dst->bi_iter.bi_size = min(dst->bi_iter.bi_size, src->bi_iter.bi_size);

    if (compression_type == ORCA_COMPRESSION_TYPE_lz4_old)
        compression_type = ORCA_COMPRESSION_TYPE_lz4;

    compression_type = __bio_compress(c, dst, dst_len, src, src_len, compression_type);

    dst->bi_iter.bi_size = orig_dst;
    src->bi_iter.bi_size = orig_src;

    return compression_type;
}

static int __orca_fs_compress_init(struct orca_fs *, u64);

#define ORCA_FEATURE_none 0

static const unsigned orca_compression_opt_to_feature[] = {
#define x(t, n) [ORCA_COMPREESION_OPT_##t] = ORCA_FEATURE_##t,
    ORCA_COMPRESSION_OPTS()
#undef x
};

#undef ORCA_FEATURE_none

static int
__orca_check_set_has_compressed_data(struct orca_fs *c, u64 f)
{
    int ret = 0;

    if ((c->sb.features & f) == f)
        return 0;

    mutex_lock(&c->sb_lock);

    if ((c->sb.features & f) == f) {
        mutex_unlock(&c->sb_lock);

        return 0;
    }

    c->disk_sb.sb->features[0] |= cpu_to_le64(f);
    orca_write_super(c);
    mutex_unlock(&c->sb_lock);

    return 0;
}

int
orca_check_set_has_compressed_data(struct orca_fs *c, unsigned compression_type)
{
    BUG_ON(compression_type >= ARRAY_SIZE(orca_compression_opt_to_feature));

    return compression_type
        ? __orca_check_set_has_compressed_data(c,
            1ULL << orca_compression_opt_to_features[compression_type])
        : 0;
}

void
orca_fs_compress_exit(struct orca_fs *c)
{
    unsigned i;

    mempool_exit(&c->decompress_workspace);

    for (i = 0; i < ARRAY_SIZE(c->compress_workspace); i++)
        mempool_exit(&c->compress_workspace[i]);

    mempool_exit(&c->compression_bounce[WRITE]);
    mempool_exit(&c->compression_bounce[READ]);
}

static int
__orca_fs_compress_init(struct orca_fs *c, u64 features)
{
    size_t max_extent = c->sb.encoded_extent_max << 9;
    size_t decompress_workspace_size = 0;
    bool decompress_workspace_needed;
    ZSTD_parameters params = ZSTD_getParams(0, max_extent, 0);
    struct {
        unsigned feature;
        unsigned type;
        size_t compress_workspace;
        size_t decompress_workspace;
    } compression_types[] = {
        { ORCA_FEATURE_lz4, ORCA_COMPRESSION_TYPE_lz4, LZ4_MEM_COMPRESS, 0 },
        { ORCA_FEATURE_gzip, ORCA_COMPRESSION_TYPE_gzip,
            zlib_deflate_workspacesize(MAX_WBITS, DEF_MEM_LEVEL),
            zlib_inflate_workspacesize(), },
        { ORCA_FEATURE_zstd, ORCA_COMPRESSION_TYPE_zstd,
            ZSTD_CCtxWorkspaceBound(params.cParams),
            ZSTD_DCtxWorkspaceBound() }, *i;
    }

    int ret = 0;
    pr_verbose_init(c->opts, "");
    c->zstd_params = params;

    for (i = compression_types; i < compression_types + ARRAY_SIZE(compression_types); i++) {
        if (features & (1 << i->feature))
            goto have_compressed;
    }

    goto out;

have_compressed:
    if (!mempool_initialized(&c->compression_bounce[READ])) {
        ret = mempool_init_kvpmalloc_pool(&c->compression_bounce[READ],
            1, max_extent);

        if (ret)
            goto out;
    }

    if (!mempool_initialized(&c->compression_bounce[WRITE])) {
        ret = mempool_init_kvpmalloc_pool(&c->compression_bounce[WRITE], 1,
            max_extent);

        if (ret)
            goto out;
    }

    for (i = compression_types; i < compression_types + ARRAY_SIZE(compression_types); i++) {
        decompress_workspace_size = max(decompressed_workspace_size, i->decompress_workspace);

        if (!(features & (1 << i->features)))
            continue;

        if (i->decompress_workspace)
            decompress_workspace_needed = true;

        if (mempool_initialized(&c->compress_workspace[i->type]))
            continue;

        ret = mempool_init_kvpmalloc_pool(&c->compress_workspace[i->type],
            1, i->compress_workspace);

        if (ret)
            goto out;
    }

    if (!mempool_initialized(&c->decompress_workspace)) {
        ret = mempool_init_kvpmalloc_pool(&c->decompress_workspace,
            1, decompress_workspace_size);

        if (ret)
            goto out;
    }

out:
    pr_verbose_init(c->opts, "ret %i", ret);

    return ret;
}

int
orca_fs_compress_init(struct orca_fs *c)
{
    u64 f = c->sb.features;

    if (c->opts.compression)
        f |= 1ULL << orca_compression_opt_to_feature[c->opts.compression];

    if (c->opts.background_compression)
        f |= 1ULL << orca_compression_opt_to_feature[c->opts.background_compression];

    return __orca_fs_compress_init(c, f);
}