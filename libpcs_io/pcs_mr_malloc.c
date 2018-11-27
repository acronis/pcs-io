/*
 * Copyright © 2003-2018 Acronis International GmbH.
 */

#include <sys/mman.h>

#include "pcs_malloc.h"
#include "pcs_mr_malloc.h"
#include "std_list.h"
#include "bug.h"
#include "log.h"

void *__pcs_malloc_mmap(struct malloc_item **p_mi, const char *file, int bugon_if_failed, int flags, size_t size)
{
	void *buf = mmap(NULL, sizeof(struct mem_header) + size, PROT_READ|PROT_WRITE,
			 MAP_ANONYMOUS|MAP_PRIVATE, 0, 0);
	if (bugon_if_failed) {
		BUG_ON(buf == MAP_FAILED);
	} else if (buf == MAP_FAILED) {
		return NULL;
	}

	struct malloc_item *mi = pcs_malloc_item_init(p_mi, file, flags);
	if (mi)
		pcs_account_alloc(mi, size);

	pcs_fill_mem_header(buf, mi, size);
	mlock(buf, size + sizeof(struct mem_header));
	return buf + sizeof(struct mem_header);
}

void __pcs_free_mmap(void *block, size_t size)
{
	struct mem_header *hdr = block - sizeof(struct mem_header);
	if (hdr->magic != PCS_MALLOC_MAGIC) {
		pcs_log(LOG_ERR, "Fatal: corrupted memory on free_mmap - no magic (%p, %p)", block, hdr);
		BUG();
	}
	BUG_ON(size != hdr->size);
	hdr->magic = PCS_DOUBLEFREE_MAGIC;
	if (hdr->caller) {
		pcs_account_alloc(hdr->caller, -size);
	}
	munmap(hdr, size + sizeof(struct mem_header));
}

#ifndef PCS_ENABLE_RDMA

struct pcs_mr_ctx *pcs_mr_get_ctx(void *block)
{
	return NULL;
}

void *pcs_mrc2buf(struct pcs_mr_ctx *ctx, size_t *length)
{
	return NULL;
}

void pcs_mr_memdump(int loglevel)
{
}

#else /* Below is MR-friendly malloc ... */

/*
 * General idea:
 *
 * 1) The global hash table consists of pointers to size_desc structures (sd),
 * where each size_desc roots the list of mr_pool structures. A size_desc
 * structure holds all allocations of given size. There can be no more than
 * one size_desc for any given size. I.e. it's unique by its "size" field.
 *
 * 2) A mr_pool structure holds a big buffer covered by one MR. The buffer
 * is logically splitted into one or (typically) many smaller buffers. Each
 * of them is of sd->size size and has correspondent (in 1:1 manner) buf_desc
 * structure.
 *
 * 3) buf_desc (standing for "buffer descriptor") is solely needed to keep
 * track which of smaller buffers are allocated. Parent mr_pool structure
 * roots the list of free buf_desc structures.
 *
 * Main trick: for each smaller buffer we allocated extra space before the
 * buffer to hold mr_label structure of 32 bytes: 8 bytes for magic and
 * 8+8 bytes for pointers referring to parent mr_pool and corresponding
 * buf_desc structure, and 8 bytes for padding. The pointer to mr_pool will
 * be used by rdma-engine to get mr by buffer from get_chunk().
 *
 * NB: mr_label can be squeezed to 16 bytes by omitting buf_desc pointer:
 *      offset   = block - mrp->bufs;
 *      int_size = internal_size(mrp->parent_sd);
 *      idx      = offset / int_size;
 *      bd       = mrp->descs + idx;
 * and padding. Not sure such an economy is a great idea...
 */

struct size_desc {
	struct size_desc *next; /* hash collision list */

	int hash_type;

	/* the size of allocation for all my pools */
	size_t size;

	/* available for allocations (i.e. non-empty) */
	struct cd_list avail_pools;

	/* completely free (i.e. ready for release) */
	struct cd_list free_pools;

	int n_free_pools;
	/* The total number of allocated pools */
	int n_pools;
	/* The total size of allocated pools */
	unsigned long long total_size;
	/* The total size of allocated buffers */
	unsigned long long used_size;
};

struct buf_desc {
	struct cd_list list; /* to be on mrp->free_bufs list */
};

struct mr_pool {
	struct size_desc *parent_sd;

	struct pcs_mr_ctx mrc; /* this part of mr_pool will be exposed to rdma-engine */

	struct cd_list   avail_list; /* to be on sd->avail_pools list */
	struct cd_list   free_list;  /* to be on sd->free_pools list */

	char            *bufs;       /* big buffer covered by mr */
	size_t		 bufs_size;  /* size of this big buffer */
	struct buf_desc *descs;      /* plain array of buf_desc-s */
	struct cd_list   free_bufs;  /* list of free buf_desc-s */

        int n_bufs_total; /* never changes since inital setup */
	int n_bufs_avail; /* varies from n_bufs_total to 0 (inclusively) */
};

struct __pre_aligned(32) mr_label {
	u64 magic;
	struct mr_pool  *mrp;
	struct buf_desc *bd;
	struct malloc_item* mi;
} __aligned(32);

#define MR_POOL_MAGIC 0x63f92a8a8d7bd80e /* random u64 */

#define MR_PREALLOC_SIZE (64*1024*1024) /* 64MB; see mr_pool_alloc below */

#define MR_FREE_POOLS_THRESHOLD 2 /* when to release mr_pool, must be > 1 */

#define MR_HASH_SIZE 2048
static struct size_desc *mr_hash_table[MR_HASH_SIZE * MR_HASH_TYPE_MAX];

/* relies on MR_HASH_SIZE to be 2048 */
static int mr_hash(size_t size)
{
	size_t kb = size >> 10;
	size_t mb = kb   >> 10;

	if (mb)
		return 1024 + (mb & 1023);
	else
		return         kb & 1023;
}

static struct size_desc *mr_hash_lookup(size_t size, int hash_type)
{
	struct size_desc *sd;
	int hash = mr_hash(size) + hash_type * MR_HASH_SIZE;

	for (sd = mr_hash_table[hash]; sd != NULL; sd = sd->next)
		if (sd->size == size)
			return sd;

	sd  = pcs_xzmalloc(sizeof(*sd));
	if (sd == NULL)
		return NULL;

	sd->size = size;
	sd->hash_type = hash_type;

	cd_list_init(&sd->avail_pools);
	cd_list_init(&sd->free_pools);

	sd->next = mr_hash_table[hash];
	mr_hash_table[hash] = sd;

	return sd;
}

static size_t internal_size(struct size_desc *sd)
{
	return sd->size + sizeof(struct mr_label);
}

static void *bd2buf(struct mr_pool *mrp, struct buf_desc *bd)
{
	size_t int_size = internal_size(mrp->parent_sd);

	return mrp->bufs + int_size * (bd - mrp->descs);
}

static void mr_pool_free(struct mr_pool *mrp)
{
	if (mrp->mrc.mr_ctx)
		mrp->mrc.mr_free_cb(mrp->mrc.mr_ctx, mrp->mrc.pd_ctx);

	if (mrp->descs)
		pcs_free(mrp->descs);

	if (mrp->bufs) {
		if (mrp->parent_sd->hash_type == MR_HASH_TYPE_MMAP)
			pcs_free_mmap(mrp->bufs, mrp->bufs_size);
		else
			pcs_free(mrp->bufs);
	}

	pcs_free(mrp);
}

static void *__pcs_malloc_with_flags(struct malloc_item **p_mi, const char *file, int bugon_if_failed, int flags, size_t size)
{
	pcs_malloc_item_init(p_mi, file, flags);
	return __pcs_malloc(p_mi, file, bugon_if_failed, size);
}

#define pcs_malloc_pool(sz)      TRACE_ALLOC(__pcs_malloc_with_flags, 0, PCS_MALLOC_F_POOL, sz)
#define pcs_malloc_pool_mmap(sz) TRACE_ALLOC(__pcs_malloc_mmap, 0, PCS_MALLOC_F_POOL, sz)

static struct mr_pool *mr_pool_alloc(struct size_desc *sd)
{
	struct buf_desc *bd;

	size_t int_size = internal_size(sd);

	int n_bufs = (MR_PREALLOC_SIZE > int_size) ?
		(MR_PREALLOC_SIZE / int_size) : 1;

	size_t descs_size = n_bufs * sizeof(struct buf_desc);
	size_t bufs_size  = n_bufs * int_size;

	struct mr_pool  *mrp   = pcs_zmalloc(sizeof(*mrp));
	struct buf_desc *descs = pcs_malloc(descs_size);
	char            *bufs  = (sd->hash_type == MR_HASH_TYPE_MMAP) ?
				pcs_malloc_pool_mmap(bufs_size) :
				pcs_malloc_pool(bufs_size);

	if (mrp == NULL || descs == NULL || bufs == NULL)
		goto failed;

	mrp->descs     = descs;
	mrp->bufs      = bufs;
	mrp->bufs_size = bufs_size;
	mrp->parent_sd = sd;
	cd_list_init(&mrp->free_bufs);

	for (bd = mrp->descs; bd - mrp->descs < n_bufs; bd++) {
		struct mr_label *mrl = bd2buf(mrp, bd);

		mrl->magic = MR_POOL_MAGIC;
		mrl->mrp   = mrp;
		mrl->bd    = bd;
		mrl->mi    = NULL;

		cd_list_add_tail(&bd->list, &mrp->free_bufs);
	}

	mrp->n_bufs_total = n_bufs;
	mrp->n_bufs_avail = n_bufs;

	cd_list_add(&mrp->avail_list, &sd->avail_pools);
	cd_list_add(&mrp->free_list,  &sd->free_pools);
	sd->n_free_pools++;
	sd->n_pools++;
	sd->total_size += bufs_size;

	return mrp;

failed:
	if (mrp)
		pcs_free(mrp);
	if (descs)
		pcs_free(descs);
	if (bufs)
		pcs_free(bufs);
	return NULL;
}

void *__pcs_mr_malloc(struct malloc_item **p_mi, const char *file, int bugon_if_failed, size_t size, int hash_type)
{
	struct size_desc *sd = mr_hash_lookup(size, hash_type);
	struct mr_pool   *mrp;
	struct buf_desc  *bd;
	struct mr_label  *mrl;

	if (sd == NULL)
		return NULL;

	if (!cd_list_empty(&sd->avail_pools)) {
		mrp = cd_list_first_entry(&sd->avail_pools, struct mr_pool, avail_list);
	} else {
		BUG_ON(!cd_list_empty(&sd->free_pools));
		mrp = mr_pool_alloc(sd);
		if (unlikely(!mrp)) {
			if (bugon_if_failed)
				pcs_malloc_failed(file);
			else
				return NULL;
		}
	}

	BUG_ON(cd_list_empty(&mrp->free_bufs));
	bd = cd_list_first_entry(&mrp->free_bufs, struct buf_desc, list);

	cd_list_del(&bd->list); /* remove bd from mrp->free_bufs list */

	if (cd_list_empty(&mrp->free_bufs)) {
		BUG_ON(mrp->n_bufs_avail != 1);
		cd_list_del(&mrp->avail_list); /* remove mrp from sd->avail_pools list */
	}

	if (mrp->n_bufs_total == mrp->n_bufs_avail) {
		cd_list_del(&mrp->free_list);  /* remove mrp from sd->free_pools list */
		sd->n_free_pools--;
		BUG_ON(sd->n_free_pools < 0);
	}

	mrp->n_bufs_avail--;
	BUG_ON(mrp->n_bufs_avail < 0);

	mrl = bd2buf(mrp, bd);
	BUG_ON(mrl->mi);

	sd->used_size += size;

	struct malloc_item *mi = pcs_malloc_item_init(p_mi, file, PCS_MALLOC_F_IN_POOL);
	if (mi) {
		pcs_account_alloc(mi, size);
		mrl->mi = mi;
	}

	return mrl + 1;
}

static void mr_pool_release(struct mr_pool *mrp)
{
	struct size_desc *sd = mrp->parent_sd;
	struct buf_desc  *bd;

	cd_list_del(&mrp->avail_list); /* remove mrp from sd->avail_pools list */
	cd_list_del(&mrp->free_list);  /* remove mrp from sd->free_pools list */

	BUG_ON(cd_list_empty(&sd->avail_pools)); /* MR_FREE_POOLS_THRESHOLD > 1 */

	sd->n_free_pools--;
	BUG_ON(sd->n_free_pools < 0);

	sd->n_pools--;
	BUG_ON(sd->n_pools < 0);

	BUG_ON(sd->total_size < mrp->bufs_size);
	sd->total_size -= mrp->bufs_size;

	/* sanity paranoia, mainly to purge magic */
	for (bd = mrp->descs; bd - mrp->descs < mrp->n_bufs_total; bd++)
		memset(bd2buf(mrp, bd), 0, sizeof(struct mr_label));

	mr_pool_free(mrp);
}

void pcs_mr_free(void *block)
{
	struct mr_label  *mrl = (struct mr_label *)(block - sizeof(*mrl));
	struct size_desc *sd;
	struct mr_pool   *mrp;
	struct buf_desc  *bd;

	BUG_ON(mrl->magic != MR_POOL_MAGIC);

	mrp = mrl->mrp;
	BUG_ON(mrl->mrp == NULL);

	sd = mrp->parent_sd;
	BUG_ON(sd == NULL);

	bd = mrl->bd;
	BUG_ON(bd == NULL);
	BUG_ON(bd2buf(mrp, bd) + sizeof(*mrl) != block);

	/* all sanity checks done, let's proceed with actual release ... */

	BUG_ON(sd->used_size < sd->size);
	sd->used_size -= sd->size;
	if (mrl->mi) {
		pcs_account_alloc(mrl->mi, -sd->size);
		mrl->mi = NULL;
	}

	cd_list_add_tail(&bd->list, &mrp->free_bufs);

	mrp->n_bufs_avail++;
	BUG_ON(mrp->n_bufs_avail > mrp->n_bufs_total);

	if (mrp->n_bufs_avail == 1)
		cd_list_add_tail(&mrp->avail_list, &sd->avail_pools);

	if (mrp->n_bufs_avail == mrp->n_bufs_total) {
		cd_list_add_tail(&mrp->free_list,  &sd->free_pools);
		sd->n_free_pools++;

		/* relink to the tail to protect mrp from allocations */
		cd_list_del(&mrp->avail_list);
		cd_list_add_tail(&mrp->avail_list, &sd->avail_pools);

		if (sd->n_free_pools >= MR_FREE_POOLS_THRESHOLD)
			mr_pool_release(mrp);
	}
}

struct pcs_mr_ctx *pcs_mr_get_ctx(void *block)
{
	struct mr_label  *mrl = (struct mr_label *)(block - sizeof(*mrl));
	struct mr_pool   *mrp = mrl->mrp;

	BUG_ON(mrl->magic != MR_POOL_MAGIC);
	BUG_ON(mrp == NULL);
	BUG_ON(mrp->parent_sd == NULL);
	BUG_ON(mrl->bd == NULL);
	BUG_ON(bd2buf(mrp, mrl->bd) + sizeof(*mrl) != block);

	return &mrp->mrc;
}

void *pcs_mrc2buf(struct pcs_mr_ctx *ctx, size_t *length)
{
	struct mr_pool *mrp = container_of(ctx, struct mr_pool, mrc);

	*length = mrp->n_bufs_total * internal_size(mrp->parent_sd);
	return mrp->bufs;
}

void pcs_mr_memdump(int loglevel)
{
	int h;
	struct size_desc * sd;
	unsigned long long total_size = 0, total_used = 0;

	pcs_log(loglevel, "---====== MR memory dump ======---");
	pcs_log(loglevel, " size:type total_pools free_pools total_size used_size");

	for (h = 0; h < MR_HASH_SIZE * MR_HASH_TYPE_MAX; h++) {
		for (sd = mr_hash_table[h]; sd; sd = sd->next) {
			pcs_log(loglevel, "%lu:%d\t%d\t%d\t%llu\t%llu", sd->size, sd->hash_type,
				sd->n_pools, sd->n_free_pools, sd->total_size, sd->used_size);
			total_size += sd->total_size;
			total_used += sd->used_size;
		}
	}
	pcs_log(loglevel, "--------------------------------------");
	pcs_log(loglevel, "%llu bytes used out of %llu allocated in all pools",
			total_used, total_size
		);
	pcs_log(loglevel, "---====== MR memory dump end ======---");
}

#endif /* PCS_ENABLE_RDMA */
