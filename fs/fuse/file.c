/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/module.h>
#include <linux/compat.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <linux/uio.h>
#include <linux/dax.h>
#include <linux/iomap.h>
#include <linux/interval_tree_generic.h>

INTERVAL_TREE_DEFINE(struct fuse_dax_mapping,
                     rb, __u64, __subtree_last,
                     START, LAST, static inline, fuse_dax_interval_tree);

static long __fuse_file_fallocate(struct file *file, int mode,
					loff_t offset, loff_t length);
static struct fuse_dax_mapping *alloc_dax_mapping_reclaim(struct fuse_conn *fc,
					struct inode *inode);

static int fuse_send_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
			  int opcode, struct fuse_open_out *outargp)
{
	struct fuse_open_in inarg;
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
	if (!fc->atomic_o_trunc)
		inarg.flags &= ~O_TRUNC;
	args.in.h.opcode = opcode;
	args.in.h.nodeid = nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(*outargp);
	args.out.args[0].value = outargp;

	return fuse_simple_request(fc, &args);
}

struct fuse_file *fuse_file_alloc(struct fuse_conn *fc)
{
	struct fuse_file *ff;

	ff = kzalloc(sizeof(struct fuse_file), GFP_KERNEL);
	if (unlikely(!ff))
		return NULL;

	ff->fc = fc;
	ff->reserved_req = fuse_request_alloc(0);
	if (unlikely(!ff->reserved_req)) {
		kfree(ff);
		return NULL;
	}

	INIT_LIST_HEAD(&ff->write_entry);
	refcount_set(&ff->count, 1);
	RB_CLEAR_NODE(&ff->polled_node);
	init_waitqueue_head(&ff->poll_wait);

	spin_lock(&fc->lock);
	ff->kh = ++fc->khctr;
	spin_unlock(&fc->lock);

	return ff;
}

void fuse_file_free(struct fuse_file *ff)
{
	fuse_request_free(ff->reserved_req);
	kfree(ff);
}

static struct fuse_file *fuse_file_get(struct fuse_file *ff)
{
	refcount_inc(&ff->count);
	return ff;
}

static void fuse_release_end(struct fuse_conn *fc, struct fuse_req *req)
{
	iput(req->misc.release.inode);
}

static void fuse_file_put(struct fuse_file *ff, bool sync)
{
	if (refcount_dec_and_test(&ff->count)) {
		struct fuse_req *req = ff->reserved_req;

		if (ff->fc->no_open) {
			/*
			 * Drop the release request when client does not
			 * implement 'open'
			 */
			__clear_bit(FR_BACKGROUND, &req->flags);
			iput(req->misc.release.inode);
			fuse_put_request(ff->fc, req);
		} else if (sync) {
			__set_bit(FR_FORCE, &req->flags);
			__clear_bit(FR_BACKGROUND, &req->flags);
			fuse_request_send(ff->fc, req);
			iput(req->misc.release.inode);
			fuse_put_request(ff->fc, req);
		} else {
			req->end = fuse_release_end;
			__set_bit(FR_BACKGROUND, &req->flags);
			fuse_request_send_background(ff->fc, req);
		}
		kfree(ff);
	}
}

int fuse_do_open(struct fuse_conn *fc, u64 nodeid, struct file *file,
		 bool isdir)
{
	struct fuse_file *ff;
	int opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;

	ff = fuse_file_alloc(fc);
	if (!ff)
		return -ENOMEM;

	ff->fh = 0;
	ff->open_flags = FOPEN_KEEP_CACHE; /* Default for no-open */
	if (!fc->no_open || isdir) {
		struct fuse_open_out outarg;
		int err;

		err = fuse_send_open(fc, nodeid, file, opcode, &outarg);
		if (!err) {
			ff->fh = outarg.fh;
			ff->open_flags = outarg.open_flags;

		} else if (err != -ENOSYS || isdir) {
			fuse_file_free(ff);
			return err;
		} else {
			fc->no_open = 1;
		}
	}

	if (isdir)
		ff->open_flags &= ~FOPEN_DIRECT_IO;

	ff->nodeid = nodeid;
	file->private_data = ff;

	return 0;
}
EXPORT_SYMBOL_GPL(fuse_do_open);

static void fuse_link_write_file(struct file *file)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = file->private_data;
	/*
	 * file may be written through mmap, so chain it onto the
	 * inodes's write_file list
	 */
	spin_lock(&fc->lock);
	if (list_empty(&ff->write_entry))
		list_add(&ff->write_entry, &fi->write_files);
	spin_unlock(&fc->lock);
}

static struct fuse_dax_mapping *alloc_dax_mapping(struct fuse_conn *fc)
{
	unsigned long free_threshold;
	struct fuse_dax_mapping *dmap = NULL;

	spin_lock(&fc->lock);

	/* TODO: Add logic to try to free up memory if wait is allowed */
	if (fc->nr_free_ranges <= 0) {
		spin_unlock(&fc->lock);
		goto out_kick;
	}

	WARN_ON(list_empty(&fc->free_ranges));

	/* Take a free range */
	dmap = list_first_entry(&fc->free_ranges, struct fuse_dax_mapping,
					list);
	list_del_init(&dmap->list);
	fc->nr_free_ranges--;
	spin_unlock(&fc->lock);

out_kick:
	/* If number of free ranges are below threshold, start reclaim */
	free_threshold = max((fc->nr_ranges * FUSE_DAX_RECLAIM_THRESHOLD)/100,
				(unsigned long)1);
	if (fc->nr_free_ranges < free_threshold) {
		pr_debug("fuse: Kicking dax memory reclaim worker. nr_free_ranges=0x%ld nr_total_ranges=%ld\n", fc->nr_free_ranges, fc->nr_ranges);
		queue_delayed_work(system_long_wq, &fc->dax_free_work, 0);
	}
	return dmap;
}

/* This assumes fc->lock is held */
static void __dmap_remove_busy_list(struct fuse_conn *fc,
				struct fuse_dax_mapping *dmap)
{
	list_del_init(&dmap->busy_list);
	WARN_ON(fc->nr_busy_ranges == 0);
	fc->nr_busy_ranges--;
}

static void dmap_remove_busy_list(struct fuse_conn *fc,
				struct fuse_dax_mapping *dmap)
{
	spin_lock(&fc->lock);
	__dmap_remove_busy_list(fc, dmap);
	spin_unlock(&fc->lock);
}

/* This assumes fc->lock is held */
static void __free_dax_mapping(struct fuse_conn *fc,
				struct fuse_dax_mapping *dmap)
{
	list_add_tail(&dmap->list, &fc->free_ranges);
	fc->nr_free_ranges++;
	/* TODO: Wake up only when needed */
	wake_up(&fc->dax_range_waitq);
}

static void free_dax_mapping(struct fuse_conn *fc,
				struct fuse_dax_mapping *dmap)
{
	/* Return fuse_dax_mapping to free list */
	spin_lock(&fc->lock);
	__free_dax_mapping(fc, dmap);
	spin_unlock(&fc->lock);
}

/* offset passed in should be aligned to FUSE_DAX_MEM_RANGE_SZ */
static int fuse_setup_one_mapping(struct inode *inode,
				struct file *file, loff_t offset,
				struct fuse_dax_mapping *dmap)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff = NULL;
	struct fuse_setupmapping_in inarg;
	FUSE_ARGS(args);
	ssize_t err;

	if (file)
		ff = file->private_data;

	WARN_ON(offset % FUSE_DAX_MEM_RANGE_SZ);
	WARN_ON(fc->nr_free_ranges < 0);

	/* Ask fuse daemon to setup mapping */
	memset(&inarg, 0, sizeof(inarg));
	inarg.foffset = offset;
	if (ff)
		inarg.fh = ff->fh;
	else
		inarg.fh = -1;
	inarg.moffset = dmap->window_offset;
	inarg.len = FUSE_DAX_MEM_RANGE_SZ;
	if (file) {
		inarg.flags |= (file->f_mode & FMODE_WRITE) ?
				FUSE_SETUPMAPPING_FLAG_WRITE : 0;
		inarg.flags |= (file->f_mode & FMODE_READ) ?
				FUSE_SETUPMAPPING_FLAG_READ : 0;
	} else {
		inarg.flags |= FUSE_SETUPMAPPING_FLAG_READ;
		inarg.flags |= FUSE_SETUPMAPPING_FLAG_WRITE;
	}
	args.in.h.opcode = FUSE_SETUPMAPPING;
	args.in.h.nodeid = fi->nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = fuse_simple_request(fc, &args);
	if (err < 0) {
		printk(KERN_ERR "%s request failed at mem_offset=0x%llx %zd\n",
				 __func__, dmap->window_offset, err);
		return err;
	}

	pr_debug("fuse_setup_one_mapping() succeeded. offset=0x%llx err=%zd\n", offset, err);

	/*
	 * We don't take a refernce on inode. inode is valid right now and
	 * when inode is going away, cleanup logic should first cleanup
	 * dmap entries.
	 *
	 * TODO: Do we need to ensure that we are holding inode lock
	 * as well.
	 */
	dmap->inode = inode;
	dmap->start = offset;
	dmap->end = offset + FUSE_DAX_MEM_RANGE_SZ - 1;
	/* Protected by fi->i_dmap_sem */
	fuse_dax_interval_tree_insert(dmap, &fi->dmap_tree);
	fi->nr_dmaps++;
	spin_lock(&fc->lock);
	list_add_tail(&dmap->busy_list, &fc->busy_ranges);
	fc->nr_busy_ranges++;
	spin_unlock(&fc->lock);
	return 0;
}

static int fuse_removemapping_one(struct inode *inode,
					struct fuse_dax_mapping *dmap)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_removemapping_in inarg;
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.moffset = dmap->window_offset;
	inarg.len = dmap->length;
	args.in.h.opcode = FUSE_REMOVEMAPPING;
	args.in.h.nodeid = fi->nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	return fuse_simple_request(fc, &args);
}

/*
 * It is called from evict_inode() and by that time inode is going away. So
 * this function does not take any locks like fi->i_dmap_sem for traversing
 * that fuse inode interval tree. If that lock is taken then lock validator
 * complains of deadlock situation w.r.t fs_reclaim lock.
 */
void fuse_removemapping(struct inode *inode)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	ssize_t err;
	struct fuse_dax_mapping *dmap;

	/* Clear the mappings list */
	while (true) {
		WARN_ON(fi->nr_dmaps < 0);

		dmap = fuse_dax_interval_tree_iter_first(&fi->dmap_tree, 0,
								-1);
		if (dmap) {
			fuse_dax_interval_tree_remove(dmap, &fi->dmap_tree);
			fi->nr_dmaps--;
			dmap_remove_busy_list(fc, dmap);
		}

		if (!dmap)
			break;

		/*
		 * During umount/shutdown, fuse connection is dropped first
		 * and later evict_inode() is called later. That means any
		 * removemapping messages are going to fail. Send messages
		 * only if connection is up. Otherwise fuse daemon is
		 * responsible for cleaning up any leftover references and
		 * mappings.
		 */
		if (fc->connected) {
			err = fuse_removemapping_one(inode, dmap);
			if (err) {
				pr_warn("Failed to removemapping. offset=0x%llx"
					" len=0x%llx\n", dmap->window_offset,
					dmap->length);
			}
		}

		dmap->inode = NULL;

		/* Add it back to free ranges list */
		free_dax_mapping(fc, dmap);
	}
}

void fuse_finish_open(struct inode *inode, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!(ff->open_flags & FOPEN_KEEP_CACHE))
		invalidate_inode_pages2(inode->i_mapping);
	if (ff->open_flags & FOPEN_NONSEEKABLE)
		nonseekable_open(inode, file);
	if (fc->atomic_o_trunc && (file->f_flags & O_TRUNC)) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		spin_lock(&fc->lock);
		fi->attr_version = ++fc->attr_version;
		i_size_write(inode, 0);
		spin_unlock(&fc->lock);
		fuse_invalidate_attr(inode);
		if (fc->writeback_cache)
			file_update_time(file);
	}
	if ((file->f_mode & FMODE_WRITE) && fc->writeback_cache)
		fuse_link_write_file(file);
}

int fuse_open_common(struct inode *inode, struct file *file, bool isdir)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;
	bool lock_inode = (file->f_flags & O_TRUNC) &&
			  fc->atomic_o_trunc &&
			  (fc->writeback_cache || IS_DAX(inode));

	err = generic_file_open(inode, file);
	if (err)
		return err;

	if (lock_inode)
		inode_lock(inode);

	err = fuse_do_open(fc, get_node_id(inode), file, isdir);

	if (!err)
		fuse_finish_open(inode, file);

	if (lock_inode)
		inode_unlock(inode);

	return err;
}

static void fuse_prepare_release(struct fuse_file *ff, int flags, int opcode)
{
	struct fuse_conn *fc = ff->fc;
	struct fuse_req *req = ff->reserved_req;
	struct fuse_release_in *inarg = &req->misc.release.in;

	spin_lock(&fc->lock);
	list_del(&ff->write_entry);
	if (!RB_EMPTY_NODE(&ff->polled_node))
		rb_erase(&ff->polled_node, &fc->polled_files);
	spin_unlock(&fc->lock);

	wake_up_interruptible_all(&ff->poll_wait);

	inarg->fh = ff->fh;
	inarg->flags = flags;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_release_in);
	req->in.args[0].value = inarg;
}

void fuse_release_common(struct file *file, int opcode)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req = ff->reserved_req;
	bool sync = false;

	fuse_prepare_release(ff, file->f_flags, opcode);

	if (ff->flock) {
		struct fuse_release_in *inarg = &req->misc.release.in;
		inarg->release_flags |= FUSE_RELEASE_FLOCK_UNLOCK;
		inarg->lock_owner = fuse_lock_owner_id(ff->fc,
						       (fl_owner_t) file);
	}
	/* Hold inode until release is finished */
	req->misc.release.inode = igrab(file_inode(file));

	/*
	 * Normally this will send the RELEASE request, however if
	 * some asynchronous READ or WRITE requests are outstanding,
	 * the sending will be delayed.
	 *
	 * Make the release synchronous if this is a fuseblk mount,
	 * synchronous RELEASE is allowed (and desirable) in this case
	 * because the server can be trusted not to screw up.
	 *
	 * For DAX, fuse server is trusted. So it should be fine to
	 * do a sync file put. Doing async file put is creating
	 * problems right now because when request finish, iput()
	 * can lead to freeing of inode. That means it tears down
	 * mappings backing DAX memory and sends REMOVEMAPPING message
	 * to server and blocks for completion. Currently, waiting
	 * in req->end context deadlocks the system as same worker thread
	 * can't process REMOVEMAPPING reply it is waiting for.
	 */
	if (IS_DAX(req->misc.release.inode) || ff->fc->destroy_req != NULL)
		sync = true;

	fuse_file_put(ff, sync);
}

static int fuse_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, false);
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = get_fuse_conn(inode);

	/* see fuse_vma_close() for !writeback_cache case */
	if (fc->writeback_cache)
		write_inode_now(inode, 1);

	fuse_release_common(file, FUSE_RELEASE);

	/* return value is ignored by VFS */
	return 0;
}

void fuse_sync_release(struct fuse_file *ff, int flags)
{
	WARN_ON(refcount_read(&ff->count) > 1);
	fuse_prepare_release(ff, flags, FUSE_RELEASE);
	/*
	 * iput(NULL) is a no-op and since the refcount is 1 and everything's
	 * synchronous, we are fine with not doing igrab() here"
	 */
	fuse_file_put(ff, true);
}
EXPORT_SYMBOL_GPL(fuse_sync_release);

/*
 * Scramble the ID space with XTEA, so that the value of the files_struct
 * pointer is not exposed to userspace.
 */
u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id)
{
	u32 *k = fc->scramble_key;
	u64 v = (unsigned long) id;
	u32 v0 = v;
	u32 v1 = v >> 32;
	u32 sum = 0;
	int i;

	for (i = 0; i < 32; i++) {
		v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
		sum += 0x9E3779B9;
		v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
	}

	return (u64) v0 + ((u64) v1 << 32);
}

/*
 * Check if any page in a range is under writeback
 *
 * This is currently done by walking the list of writepage requests
 * for the inode, which can be pretty inefficient.
 */
static bool fuse_range_is_writeback(struct inode *inode, pgoff_t idx_from,
				   pgoff_t idx_to)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	bool found = false;

	spin_lock(&fc->lock);
	list_for_each_entry(req, &fi->writepages, writepages_entry) {
		pgoff_t curr_index;

		BUG_ON(req->inode != inode);
		curr_index = req->misc.write.in.offset >> PAGE_SHIFT;
		if (idx_from < curr_index + req->num_pages &&
		    curr_index <= idx_to) {
			found = true;
			break;
		}
	}
	spin_unlock(&fc->lock);

	return found;
}

static inline bool fuse_page_is_writeback(struct inode *inode, pgoff_t index)
{
	return fuse_range_is_writeback(inode, index, index);
}

/*
 * Wait for page writeback to be completed.
 *
 * Since fuse doesn't rely on the VM writeback tracking, this has to
 * use some other means.
 */
static int fuse_wait_on_page_writeback(struct inode *inode, pgoff_t index)
{
	struct fuse_inode *fi = get_fuse_inode(inode);

	wait_event(fi->page_waitq, !fuse_page_is_writeback(inode, index));
	return 0;
}

/*
 * Wait for all pending writepages on the inode to finish.
 *
 * This is currently done by blocking further writes with FUSE_NOWRITE
 * and waiting for all sent writes to complete.
 *
 * This must be called under i_mutex, otherwise the FUSE_NOWRITE usage
 * could conflict with truncation.
 */
static void fuse_sync_writes(struct inode *inode)
{
	fuse_set_nowrite(inode);
	fuse_release_nowrite(inode);
}

static int fuse_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	struct fuse_req *req;
	struct fuse_flush_in inarg;
	int err;

	if (is_bad_inode(inode))
		return -EIO;

	if (fc->no_flush)
		return 0;

	err = write_inode_now(inode, 1);
	if (err)
		return err;

	inode_lock(inode);
	fuse_sync_writes(inode);
	inode_unlock(inode);

	err = filemap_check_errors(file->f_mapping);
	if (err)
		return err;

	req = fuse_get_req_nofail_nopages(fc, file);
	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.lock_owner = fuse_lock_owner_id(fc, id);
	req->in.h.opcode = FUSE_FLUSH;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	__set_bit(FR_FORCE, &req->flags);
	fuse_request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_flush = 1;
		err = 0;
	}
	return err;
}

int fuse_fsync_common(struct file *file, loff_t start, loff_t end,
		      int datasync, int isdir)
{
	struct inode *inode = file->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	FUSE_ARGS(args);
	struct fuse_fsync_in inarg;
	int err;

	if (is_bad_inode(inode))
		return -EIO;

	inode_lock(inode);

	/*
	 * Start writeback against all dirty pages of the inode, then
	 * wait for all outstanding writes, before sending the FSYNC
	 * request.
	 */
	err = file_write_and_wait_range(file, start, end);
	if (err)
		goto out;

	fuse_sync_writes(inode);

	/*
	 * Due to implementation of fuse writeback
	 * file_write_and_wait_range() does not catch errors.
	 * We have to do this directly after fuse_sync_writes()
	 */
	err = file_check_and_advance_wb_err(file);
	if (err)
		goto out;

	err = sync_inode_metadata(inode, 1);
	if (err)
		goto out;

	if ((!isdir && fc->no_fsync) || (isdir && fc->no_fsyncdir))
		goto out;

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = ff->fh;
	inarg.fsync_flags = datasync ? 1 : 0;
	args.in.h.opcode = isdir ? FUSE_FSYNCDIR : FUSE_FSYNC;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		if (isdir)
			fc->no_fsyncdir = 1;
		else
			fc->no_fsync = 1;
		err = 0;
	}
out:
	inode_unlock(inode);
	return err;
}

static int fuse_fsync(struct file *file, loff_t start, loff_t end,
		      int datasync)
{
	return fuse_fsync_common(file, start, end, datasync, 0);
}

void fuse_read_fill(struct fuse_req *req, struct file *file, loff_t pos,
		    size_t count, int opcode)
{
	struct fuse_read_in *inarg = &req->misc.read.in;
	struct fuse_file *ff = file->private_data;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	inarg->flags = file->f_flags;
	req->in.h.opcode = opcode;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(struct fuse_read_in);
	req->in.args[0].value = inarg;
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = count;
}

static void fuse_release_user_pages(struct fuse_req *req, bool should_dirty)
{
	unsigned i;

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (should_dirty)
			set_page_dirty_lock(page);
		put_page(page);
	}
}

static void fuse_io_release(struct kref *kref)
{
	kfree(container_of(kref, struct fuse_io_priv, refcnt));
}

static ssize_t fuse_get_res_by_io(struct fuse_io_priv *io)
{
	if (io->err)
		return io->err;

	if (io->bytes >= 0 && io->write)
		return -EIO;

	return io->bytes < 0 ? io->size : io->bytes;
}

/**
 * In case of short read, the caller sets 'pos' to the position of
 * actual end of fuse request in IO request. Otherwise, if bytes_requested
 * == bytes_transferred or rw == WRITE, the caller sets 'pos' to -1.
 *
 * An example:
 * User requested DIO read of 64K. It was splitted into two 32K fuse requests,
 * both submitted asynchronously. The first of them was ACKed by userspace as
 * fully completed (req->out.args[0].size == 32K) resulting in pos == -1. The
 * second request was ACKed as short, e.g. only 1K was read, resulting in
 * pos == 33K.
 *
 * Thus, when all fuse requests are completed, the minimal non-negative 'pos'
 * will be equal to the length of the longest contiguous fragment of
 * transferred data starting from the beginning of IO request.
 */
static void fuse_aio_complete(struct fuse_io_priv *io, int err, ssize_t pos)
{
	int left;

	spin_lock(&io->lock);
	if (err)
		io->err = io->err ? : err;
	else if (pos >= 0 && (io->bytes < 0 || pos < io->bytes))
		io->bytes = pos;

	left = --io->reqs;
	if (!left && io->blocking)
		complete(io->done);
	spin_unlock(&io->lock);

	if (!left && !io->blocking) {
		ssize_t res = fuse_get_res_by_io(io);

		if (res >= 0) {
			struct inode *inode = file_inode(io->iocb->ki_filp);
			struct fuse_conn *fc = get_fuse_conn(inode);
			struct fuse_inode *fi = get_fuse_inode(inode);

			spin_lock(&fc->lock);
			fi->attr_version = ++fc->attr_version;
			spin_unlock(&fc->lock);
		}

		io->iocb->ki_complete(io->iocb, res, 0);
	}

	kref_put(&io->refcnt, fuse_io_release);
}

static void fuse_aio_complete_req(struct fuse_conn *fc, struct fuse_req *req)
{
	struct fuse_io_priv *io = req->io;
	ssize_t pos = -1;

	fuse_release_user_pages(req, io->should_dirty);

	if (io->write) {
		if (req->misc.write.in.size != req->misc.write.out.size)
			pos = req->misc.write.in.offset - io->offset +
				req->misc.write.out.size;
	} else {
		if (req->misc.read.in.size != req->out.args[0].size)
			pos = req->misc.read.in.offset - io->offset +
				req->out.args[0].size;
	}

	fuse_aio_complete(io, req->out.h.error, pos);
}

static size_t fuse_async_req_send(struct fuse_conn *fc, struct fuse_req *req,
		size_t num_bytes, struct fuse_io_priv *io)
{
	spin_lock(&io->lock);
	kref_get(&io->refcnt);
	io->size += num_bytes;
	io->reqs++;
	spin_unlock(&io->lock);

	req->io = io;
	req->end = fuse_aio_complete_req;

	__fuse_get_request(req);
	fuse_request_send_background(fc, req);

	return num_bytes;
}

static size_t fuse_send_read(struct fuse_req *req, struct fuse_io_priv *io,
			     loff_t pos, size_t count, fl_owner_t owner)
{
	struct file *file = io->iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;

	fuse_read_fill(req, file, pos, count, FUSE_READ);
	if (owner != NULL) {
		struct fuse_read_in *inarg = &req->misc.read.in;

		inarg->read_flags |= FUSE_READ_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fc, owner);
	}

	if (io->async)
		return fuse_async_req_send(fc, req, count, io);

	fuse_request_send(fc, req);
	return req->out.args[0].size;
}

static void fuse_read_update_size(struct inode *inode, loff_t size,
				  u64 attr_ver)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);

	spin_lock(&fc->lock);
	if (attr_ver == fi->attr_version && size < inode->i_size &&
	    !test_bit(FUSE_I_SIZE_UNSTABLE, &fi->state)) {
		fi->attr_version = ++fc->attr_version;
		i_size_write(inode, size);
	}
	spin_unlock(&fc->lock);
}

static void fuse_short_read(struct fuse_req *req, struct inode *inode,
			    u64 attr_ver)
{
	size_t num_read = req->out.args[0].size;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (fc->writeback_cache) {
		/*
		 * A hole in a file. Some data after the hole are in page cache,
		 * but have not reached the client fs yet. So, the hole is not
		 * present there.
		 */
		int i;
		int start_idx = num_read >> PAGE_SHIFT;
		size_t off = num_read & (PAGE_SIZE - 1);

		for (i = start_idx; i < req->num_pages; i++) {
			zero_user_segment(req->pages[i], off, PAGE_SIZE);
			off = 0;
		}
	} else {
		loff_t pos = page_offset(req->pages[0]) + num_read;
		fuse_read_update_size(inode, pos, attr_ver);
	}
}

static int fuse_do_readpage(struct file *file, struct page *page)
{
	struct kiocb iocb;
	struct fuse_io_priv io;
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	size_t num_read;
	loff_t pos = page_offset(page);
	size_t count = PAGE_SIZE;
	u64 attr_ver;
	int err;

	/*
	 * Page writeback can extend beyond the lifetime of the
	 * page-cache page, so make sure we read a properly synced
	 * page.
	 */
	fuse_wait_on_page_writeback(inode, page->index);

	req = fuse_get_req(fc, 1);
	if (IS_ERR(req))
		return PTR_ERR(req);

	attr_ver = fuse_get_attr_version(fc);

	req->out.page_zeroing = 1;
	req->out.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = page;
	req->page_descs[0].length = count;
	init_sync_kiocb(&iocb, file);
	io = (struct fuse_io_priv) FUSE_IO_PRIV_SYNC(&iocb);
	num_read = fuse_send_read(req, &io, pos, count, NULL);
	err = req->out.h.error;

	if (!err) {
		/*
		 * Short read means EOF.  If file size is larger, truncate it
		 */
		if (num_read < count)
			fuse_short_read(req, inode, attr_ver);

		SetPageUptodate(page);
	}

	fuse_put_request(fc, req);

	return err;
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int err;

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	err = fuse_do_readpage(file, page);
	fuse_invalidate_atime(inode);
 out:
	unlock_page(page);
	return err;
}

static void fuse_readpages_end(struct fuse_conn *fc, struct fuse_req *req)
{
	int i;
	size_t count = req->misc.read.in.size;
	size_t num_read = req->out.args[0].size;
	struct address_space *mapping = NULL;

	for (i = 0; mapping == NULL && i < req->num_pages; i++)
		mapping = req->pages[i]->mapping;

	if (mapping) {
		struct inode *inode = mapping->host;

		/*
		 * Short read means EOF. If file size is larger, truncate it
		 */
		if (!req->out.h.error && num_read < count)
			fuse_short_read(req, inode, req->misc.read.attr_ver);

		fuse_invalidate_atime(inode);
	}

	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];
		if (!req->out.h.error)
			SetPageUptodate(page);
		else
			SetPageError(page);
		unlock_page(page);
		put_page(page);
	}
	if (req->ff)
		fuse_file_put(req->ff, false);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	loff_t pos = page_offset(req->pages[0]);
	size_t count = req->num_pages << PAGE_SHIFT;

	req->out.argpages = 1;
	req->out.page_zeroing = 1;
	req->out.page_replace = 1;
	fuse_read_fill(req, file, pos, count, FUSE_READ);
	req->misc.read.attr_ver = fuse_get_attr_version(fc);
	if (fc->async_read) {
		req->ff = fuse_file_get(ff);
		req->end = fuse_readpages_end;
		fuse_request_send_background(fc, req);
	} else {
		fuse_request_send(fc, req);
		fuse_readpages_end(fc, req);
		fuse_put_request(fc, req);
	}
}

struct fuse_fill_data {
	struct fuse_req *req;
	struct file *file;
	struct inode *inode;
	unsigned nr_pages;
};

static int fuse_readpages_fill(void *_data, struct page *page)
{
	struct fuse_fill_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	fuse_wait_on_page_writeback(inode, page->index);

	if (req->num_pages &&
	    (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_SIZE > fc->max_read ||
	     req->pages[req->num_pages - 1]->index + 1 != page->index)) {
		int nr_alloc = min_t(unsigned, data->nr_pages,
				     FUSE_MAX_PAGES_PER_REQ);
		fuse_send_readpages(req, data->file);
		if (fc->async_read)
			req = fuse_get_req_for_background(fc, nr_alloc);
		else
			req = fuse_get_req(fc, nr_alloc);

		data->req = req;
		if (IS_ERR(req)) {
			unlock_page(page);
			return PTR_ERR(req);
		}
	}

	if (WARN_ON(req->num_pages >= req->max_pages)) {
		unlock_page(page);
		fuse_put_request(fc, req);
		return -EIO;
	}

	get_page(page);
	req->pages[req->num_pages] = page;
	req->page_descs[req->num_pages].length = PAGE_SIZE;
	req->num_pages++;
	data->nr_pages--;
	return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_fill_data data;
	int err;
	int nr_alloc = min_t(unsigned, nr_pages, FUSE_MAX_PAGES_PER_REQ);

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	data.file = file;
	data.inode = inode;
	if (fc->async_read)
		data.req = fuse_get_req_for_background(fc, nr_alloc);
	else
		data.req = fuse_get_req(fc, nr_alloc);
	data.nr_pages = nr_pages;
	err = PTR_ERR(data.req);
	if (IS_ERR(data.req))
		goto out;

	err = read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
	if (!err) {
		if (data.req->num_pages)
			fuse_send_readpages(data.req, file);
		else
			fuse_put_request(fc, data.req);
	}
out:
	return err;
}


static ssize_t fuse_direct_read_iter(struct kiocb *iocb, struct iov_iter *to);
static ssize_t fuse_dax_read_iter(struct kiocb *iocb, struct iov_iter *to);

static ssize_t fuse_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (ff->open_flags & FOPEN_DIRECT_IO)
		return fuse_direct_read_iter(iocb, to);

	if (IS_DAX(inode))
		return fuse_dax_read_iter(iocb, to);

	/*
	 * In auto invalidate mode, always update attributes on read.
	 * Otherwise, only update if we attempt to read past EOF (to ensure
	 * i_size is up to date).
	 */
	if (fc->auto_inval_data ||
	    (iocb->ki_pos + iov_iter_count(to) > i_size_read(inode))) {
		int err;
		err = fuse_update_attributes(inode, iocb->ki_filp);
		if (err)
			return err;
	}

	return generic_file_read_iter(iocb, to);
}

static void fuse_write_fill(struct fuse_req *req, struct fuse_file *ff,
			    loff_t pos, size_t count)
{
	struct fuse_write_in *inarg = &req->misc.write.in;
	struct fuse_write_out *outarg = &req->misc.write.out;

	inarg->fh = ff->fh;
	inarg->offset = pos;
	inarg->size = count;
	req->in.h.opcode = FUSE_WRITE;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 2;
	if (ff->fc->minor < 9)
		req->in.args[0].size = FUSE_COMPAT_WRITE_IN_SIZE;
	else
		req->in.args[0].size = sizeof(struct fuse_write_in);
	req->in.args[0].value = inarg;
	req->in.args[1].size = count;
	req->out.numargs = 1;
	req->out.args[0].size = sizeof(struct fuse_write_out);
	req->out.args[0].value = outarg;
}

static size_t fuse_send_write(struct fuse_req *req, struct fuse_io_priv *io,
			      loff_t pos, size_t count, fl_owner_t owner)
{
	struct kiocb *iocb = io->iocb;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_write_in *inarg = &req->misc.write.in;

	fuse_write_fill(req, ff, pos, count);
	inarg->flags = file->f_flags;
	if (iocb->ki_flags & IOCB_DSYNC)
		inarg->flags |= O_DSYNC;
	if (iocb->ki_flags & IOCB_SYNC)
		inarg->flags |= O_SYNC;
	if (owner != NULL) {
		inarg->write_flags |= FUSE_WRITE_LOCKOWNER;
		inarg->lock_owner = fuse_lock_owner_id(fc, owner);
	}

	if (io->async)
		return fuse_async_req_send(fc, req, count, io);

	fuse_request_send(fc, req);
	return req->misc.write.out.size;
}

bool fuse_write_update_size(struct inode *inode, loff_t pos)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	bool ret = false;

	spin_lock(&fc->lock);
	fi->attr_version = ++fc->attr_version;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		ret = true;
	}
	spin_unlock(&fc->lock);

	return ret;
}

static size_t fuse_send_write_pages(struct fuse_req *req, struct kiocb *iocb,
				    struct inode *inode, loff_t pos,
				    size_t count)
{
	size_t res;
	unsigned offset;
	unsigned i;
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(iocb);

	for (i = 0; i < req->num_pages; i++)
		fuse_wait_on_page_writeback(inode, req->pages[i]->index);

	res = fuse_send_write(req, &io, pos, count, NULL);

	offset = req->page_descs[0].offset;
	count = res;
	for (i = 0; i < req->num_pages; i++) {
		struct page *page = req->pages[i];

		if (!req->out.h.error && !offset && count >= PAGE_SIZE)
			SetPageUptodate(page);

		if (count > PAGE_SIZE - offset)
			count -= PAGE_SIZE - offset;
		else
			count = 0;
		offset = 0;

		unlock_page(page);
		put_page(page);
	}

	return res;
}

static ssize_t fuse_fill_write_pages(struct fuse_req *req,
			       struct address_space *mapping,
			       struct iov_iter *ii, loff_t pos)
{
	struct fuse_conn *fc = get_fuse_conn(mapping->host);
	unsigned offset = pos & (PAGE_SIZE - 1);
	size_t count = 0;
	int err;

	req->in.argpages = 1;
	req->page_descs[0].offset = offset;

	do {
		size_t tmp;
		struct page *page;
		pgoff_t index = pos >> PAGE_SHIFT;
		size_t bytes = min_t(size_t, PAGE_SIZE - offset,
				     iov_iter_count(ii));

		bytes = min_t(size_t, bytes, fc->max_write - count);

 again:
		err = -EFAULT;
		if (iov_iter_fault_in_readable(ii, bytes))
			break;

		err = -ENOMEM;
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			break;

		if (mapping_writably_mapped(mapping))
			flush_dcache_page(page);

		tmp = iov_iter_copy_from_user_atomic(page, ii, offset, bytes);
		flush_dcache_page(page);

		iov_iter_advance(ii, tmp);
		if (!tmp) {
			unlock_page(page);
			put_page(page);
			bytes = min(bytes, iov_iter_single_seg_count(ii));
			goto again;
		}

		err = 0;
		req->pages[req->num_pages] = page;
		req->page_descs[req->num_pages].length = tmp;
		req->num_pages++;

		count += tmp;
		pos += tmp;
		offset += tmp;
		if (offset == PAGE_SIZE)
			offset = 0;

		if (!fc->big_writes)
			break;
	} while (iov_iter_count(ii) && count < fc->max_write &&
		 req->num_pages < req->max_pages && offset == 0);

	return count > 0 ? count : err;
}

static inline unsigned fuse_wr_pages(loff_t pos, size_t len)
{
	return min_t(unsigned,
		     ((pos + len - 1) >> PAGE_SHIFT) -
		     (pos >> PAGE_SHIFT) + 1,
		     FUSE_MAX_PAGES_PER_REQ);
}

static ssize_t fuse_perform_write(struct kiocb *iocb,
				  struct address_space *mapping,
				  struct iov_iter *ii, loff_t pos)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err = 0;
	ssize_t res = 0;

	if (is_bad_inode(inode))
		return -EIO;

	if (inode->i_size < pos + iov_iter_count(ii))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	do {
		struct fuse_req *req;
		ssize_t count;
		unsigned nr_pages = fuse_wr_pages(pos, iov_iter_count(ii));

		req = fuse_get_req(fc, nr_pages);
		if (IS_ERR(req)) {
			err = PTR_ERR(req);
			break;
		}

		count = fuse_fill_write_pages(req, mapping, ii, pos);
		if (count <= 0) {
			err = count;
		} else {
			size_t num_written;

			num_written = fuse_send_write_pages(req, iocb, inode,
							    pos, count);
			err = req->out.h.error;
			if (!err) {
				res += num_written;
				pos += num_written;

				/* break out of the loop on short write */
				if (num_written != count)
					err = -EIO;
			}
		}
		fuse_put_request(fc, req);
	} while (!err && iov_iter_count(ii));

	if (res > 0)
		fuse_write_update_size(inode, pos);

	clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);
	fuse_invalidate_attr(inode);

	return res > 0 ? res : err;
}

static ssize_t fuse_direct_write_iter(struct kiocb *iocb,
				      struct iov_iter *from);
static ssize_t fuse_dax_write_iter(struct kiocb *iocb, struct iov_iter *from);

static ssize_t fuse_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct address_space *mapping = file->f_mapping;
	ssize_t written = 0;
	ssize_t written_buffered = 0;
	struct inode *inode = mapping->host;
	ssize_t err;
	loff_t endbyte = 0;

	if (ff->open_flags & FOPEN_DIRECT_IO)
		return fuse_direct_write_iter(iocb, from);
	if (IS_DAX(inode))
		return fuse_dax_write_iter(iocb, from);

	if (get_fuse_conn(inode)->writeback_cache) {
		/* Update size (EOF optimization) and mode (SUID clearing) */
		err = fuse_update_attributes(mapping->host, file);
		if (err)
			return err;

		return generic_file_write_iter(iocb, from);
	}

	inode_lock(inode);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);

	err = generic_write_checks(iocb, from);
	if (err <= 0)
		goto out;

	err = file_remove_privs(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

	if (iocb->ki_flags & IOCB_DIRECT) {
		loff_t pos = iocb->ki_pos;
		written = generic_file_direct_write(iocb, from);
		if (written < 0 || !iov_iter_count(from))
			goto out;

		pos += written;

		written_buffered = fuse_perform_write(iocb, mapping, from, pos);
		if (written_buffered < 0) {
			err = written_buffered;
			goto out;
		}
		endbyte = pos + written_buffered - 1;

		err = filemap_write_and_wait_range(file->f_mapping, pos,
						   endbyte);
		if (err)
			goto out;

		invalidate_mapping_pages(file->f_mapping,
					 pos >> PAGE_SHIFT,
					 endbyte >> PAGE_SHIFT);

		written += written_buffered;
		iocb->ki_pos = pos + written_buffered;
	} else {
		written = fuse_perform_write(iocb, mapping, from, iocb->ki_pos);
		if (written >= 0)
			iocb->ki_pos += written;
	}
out:
	current->backing_dev_info = NULL;
	inode_unlock(inode);
	if (written > 0)
		written = generic_write_sync(iocb, written);

	return written ? written : err;
}

static inline void fuse_page_descs_length_init(struct fuse_req *req,
		unsigned index, unsigned nr_pages)
{
	int i;

	for (i = index; i < index + nr_pages; i++)
		req->page_descs[i].length = PAGE_SIZE -
			req->page_descs[i].offset;
}

static inline unsigned long fuse_get_user_addr(const struct iov_iter *ii)
{
	return (unsigned long)ii->iov->iov_base + ii->iov_offset;
}

static inline size_t fuse_get_frag_size(const struct iov_iter *ii,
					size_t max_size)
{
	return min(iov_iter_single_seg_count(ii), max_size);
}

static int fuse_get_user_pages(struct fuse_req *req, struct iov_iter *ii,
			       size_t *nbytesp, int write)
{
	size_t nbytes = 0;  /* # bytes already packed in req */
	ssize_t ret = 0;

	/* Special case for kernel I/O: can copy directly into the buffer */
	if (ii->type & ITER_KVEC) {
		unsigned long user_addr = fuse_get_user_addr(ii);
		size_t frag_size = fuse_get_frag_size(ii, *nbytesp);

		if (write)
			req->in.args[1].value = (void *) user_addr;
		else
			req->out.args[0].value = (void *) user_addr;

		iov_iter_advance(ii, frag_size);
		*nbytesp = frag_size;
		return 0;
	}

	while (nbytes < *nbytesp && req->num_pages < req->max_pages) {
		unsigned npages;
		size_t start;
		ret = iov_iter_get_pages(ii, &req->pages[req->num_pages],
					*nbytesp - nbytes,
					req->max_pages - req->num_pages,
					&start);
		if (ret < 0)
			break;

		iov_iter_advance(ii, ret);
		nbytes += ret;

		ret += start;
		npages = (ret + PAGE_SIZE - 1) / PAGE_SIZE;

		req->page_descs[req->num_pages].offset = start;
		fuse_page_descs_length_init(req, req->num_pages, npages);

		req->num_pages += npages;
		req->page_descs[req->num_pages - 1].length -=
			(PAGE_SIZE - ret) & (PAGE_SIZE - 1);
	}

	if (write)
		req->in.argpages = 1;
	else
		req->out.argpages = 1;

	*nbytesp = nbytes;

	return ret < 0 ? ret : 0;
}

static inline int fuse_iter_npages(const struct iov_iter *ii_p)
{
	return iov_iter_npages(ii_p, FUSE_MAX_PAGES_PER_REQ);
}

ssize_t fuse_direct_io(struct fuse_io_priv *io, struct iov_iter *iter,
		       loff_t *ppos, int flags)
{
	int write = flags & FUSE_DIO_WRITE;
	int cuse = flags & FUSE_DIO_CUSE;
	struct file *file = io->iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	size_t nmax = write ? fc->max_write : fc->max_read;
	loff_t pos = *ppos;
	size_t count = iov_iter_count(iter);
	pgoff_t idx_from = pos >> PAGE_SHIFT;
	pgoff_t idx_to = (pos + count - 1) >> PAGE_SHIFT;
	ssize_t res = 0;
	struct fuse_req *req;
	int err = 0;

	if (io->async)
		req = fuse_get_req_for_background(fc, fuse_iter_npages(iter));
	else
		req = fuse_get_req(fc, fuse_iter_npages(iter));
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (!cuse && fuse_range_is_writeback(inode, idx_from, idx_to)) {
		if (!write)
			inode_lock(inode);
		fuse_sync_writes(inode);
		if (!write)
			inode_unlock(inode);
	}

	io->should_dirty = !write && iter_is_iovec(iter);
	while (count) {
		size_t nres;
		fl_owner_t owner = current->files;
		size_t nbytes = min(count, nmax);
		err = fuse_get_user_pages(req, iter, &nbytes, write);
		if (err && !nbytes)
			break;

		if (write)
			nres = fuse_send_write(req, io, pos, nbytes, owner);
		else
			nres = fuse_send_read(req, io, pos, nbytes, owner);

		if (!io->async)
			fuse_release_user_pages(req, io->should_dirty);
		if (req->out.h.error) {
			err = req->out.h.error;
			break;
		} else if (nres > nbytes) {
			res = 0;
			err = -EIO;
			break;
		}
		count -= nres;
		res += nres;
		pos += nres;
		if (nres != nbytes)
			break;
		if (count) {
			fuse_put_request(fc, req);
			if (io->async)
				req = fuse_get_req_for_background(fc,
					fuse_iter_npages(iter));
			else
				req = fuse_get_req(fc, fuse_iter_npages(iter));
			if (IS_ERR(req))
				break;
		}
	}
	if (!IS_ERR(req))
		fuse_put_request(fc, req);
	if (res > 0)
		*ppos = pos;

	return res > 0 ? res : err;
}
EXPORT_SYMBOL_GPL(fuse_direct_io);

static ssize_t __fuse_direct_read(struct fuse_io_priv *io,
				  struct iov_iter *iter,
				  loff_t *ppos)
{
	ssize_t res;
	struct inode *inode = file_inode(io->iocb->ki_filp);

	if (is_bad_inode(inode))
		return -EIO;

	res = fuse_direct_io(io, iter, ppos, 0);

	fuse_invalidate_attr(inode);

	return res;
}

static ssize_t fuse_direct_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(iocb);
	return __fuse_direct_read(&io, to, &iocb->ki_pos);
}

static ssize_t fuse_direct_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(iocb);
	ssize_t res;

	if (is_bad_inode(inode))
		return -EIO;

	/* Don't allow parallel writes to the same file */
	inode_lock(inode);
	res = generic_write_checks(iocb, from);
	if (res < 0)
		goto out_invalidate;

	res = file_remove_privs(iocb->ki_filp);
	if (res)
		goto out_invalidate;

	res = fuse_direct_io(&io, from, &iocb->ki_pos, FUSE_DIO_WRITE);
	if (res < 0)
		goto out_invalidate;

	fuse_invalidate_attr(inode);
	fuse_write_update_size(inode, iocb->ki_pos);
	inode_unlock(inode);
	return res;

out_invalidate:
	fuse_invalidate_attr(inode);
	inode_unlock(inode);
	return res;
}

static void fuse_fill_iomap_hole(struct iomap *iomap, loff_t length)
{
	iomap->addr = IOMAP_NULL_ADDR;
	iomap->length = length;
	iomap->type = IOMAP_HOLE;
}

static void fuse_fill_iomap(struct inode *inode, loff_t pos, loff_t length,
			struct iomap *iomap, struct fuse_dax_mapping *dmap,
			unsigned flags)
{
	loff_t offset, len;
	loff_t i_size = i_size_read(inode);

	offset = pos - dmap->start;
	len = min(length, dmap->length - offset);

	/* If length is beyond end of file, truncate further */
	if (pos + len > i_size)
		len = i_size - pos;

	if (len > 0) {
		iomap->addr = dmap->window_offset + offset;
		iomap->length = len;
		if (flags & IOMAP_FAULT)
			iomap->length = ALIGN(len, PAGE_SIZE);
		iomap->type = IOMAP_MAPPED;
		pr_debug("%s: returns iomap: addr 0x%llx offset 0x%llx"
				" length 0x%llx\n", __func__, iomap->addr,
				iomap->offset, iomap->length);
	} else {
		/* Mapping beyond end of file is hole */
		fuse_fill_iomap_hole(iomap, length);
		pr_debug("%s: returns iomap: addr 0x%llx offset 0x%llx"
				"length 0x%llx\n", __func__, iomap->addr,
				iomap->offset, iomap->length);
	}
}

/* This is just for DAX and the mapping is ephemeral, do not use it for other
 * purposes since there is no block device with a permanent mapping.
 */
static int fuse_iomap_begin(struct inode *inode, loff_t pos, loff_t length,
			    unsigned flags, struct iomap *iomap)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_dax_mapping *dmap, *alloc_dmap = NULL;
	int ret;

	/* We don't support FIEMAP */
	BUG_ON(flags & IOMAP_REPORT);

	pr_debug("fuse_iomap_begin() called. pos=0x%llx length=0x%llx\n",
			pos, length);

	iomap->offset = pos;
	iomap->flags = 0;
	iomap->bdev = NULL;
	iomap->dax_dev = fc->dax_dev;

	/*
	 * Both read/write and mmap path can race here. So we need something
	 * to make sure if we are setting up mapping, then other path waits
	 *
	 * For now, use a semaphore for this. It probably needs to be
	 * optimized later.
	 */
	down_read(&fi->i_dmap_sem);
	dmap = fuse_dax_interval_tree_iter_first(&fi->dmap_tree, pos, pos);

	if (dmap) {
		fuse_fill_iomap(inode, pos, length, iomap, dmap, flags);
		up_read(&fi->i_dmap_sem);
		return 0;
	} else {
		up_read(&fi->i_dmap_sem);
		pr_debug("%s: no mapping at offset 0x%llx length 0x%llx\n",
				__func__, pos, length);
		if (pos >= i_size_read(inode))
			goto iomap_hole;

		/* Can't do reclaim in fault path yet due to lock ordering */
		if (flags & IOMAP_FAULT) {
			alloc_dmap = alloc_dax_mapping(fc);
			if (!alloc_dmap)
				return -ENOSPC;
		} else {
			alloc_dmap = alloc_dax_mapping_reclaim(fc, inode);
			if (IS_ERR(alloc_dmap))
				return PTR_ERR(alloc_dmap);
		}

		/* If we are here, we should have memory allocated */
		if (WARN_ON(!alloc_dmap))
			return -EBUSY;

		/*
		 * Drop read lock and take write lock so that only one
		 * caller can try to setup mapping and other waits
		 */
		down_write(&fi->i_dmap_sem);
		/*
		 * We dropped lock. Check again if somebody else setup
		 * mapping already.
		 */
		dmap = fuse_dax_interval_tree_iter_first(&fi->dmap_tree, pos,
							pos);
		if (dmap) {
			fuse_fill_iomap(inode, pos, length, iomap, dmap, flags);
			free_dax_mapping(fc, alloc_dmap);
			up_write(&fi->i_dmap_sem);
			return 0;
		}

		/* Setup one mapping */
		ret = fuse_setup_one_mapping(inode, NULL,
				ALIGN_DOWN(pos, FUSE_DAX_MEM_RANGE_SZ),
				alloc_dmap);
		if (ret < 0) {
			printk("fuse_setup_one_mapping() failed. err=%d"
				" pos=0x%llx\n", ret, pos);
			free_dax_mapping(fc, alloc_dmap);
			up_write(&fi->i_dmap_sem);
			return ret;
		}
		fuse_fill_iomap(inode, pos, length, iomap, alloc_dmap, flags);
		up_write(&fi->i_dmap_sem);
		return 0;
	}

	/*
	 * If read beyond end of file happnes, fs code seems to return
	 * it as hole
	 */
iomap_hole:
	fuse_fill_iomap_hole(iomap, length);
	pr_debug("fuse_iomap_begin() returning hole mapping. pos=0x%llx length_asked=0x%llx length_returned=0x%llx\n", pos, length, iomap->length);
	return 0;
}

static int fuse_iomap_end(struct inode *inode, loff_t pos, loff_t length,
			  ssize_t written, unsigned flags,
			  struct iomap *iomap)
{
	/* DAX writes beyond end-of-file aren't handled using iomap, so the
	 * file size is unchanged and there is nothing to do here.
	 */
	return 0;
}

static const struct iomap_ops fuse_iomap_ops = {
	.iomap_begin = fuse_iomap_begin,
	.iomap_end = fuse_iomap_end,
};

static ssize_t fuse_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}

	ret = dax_iomap_rw(iocb, to, &fuse_iomap_ops);
	inode_unlock_shared(inode);

	/* TODO file_accessed(iocb->f_filp) */

	return ret;
}

static ssize_t fuse_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode))
			return -EAGAIN;
	} else {
		inode_lock(inode);
	}

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;
	/* TODO file_update_time() but we don't want metadata I/O */

	/* TODO handle growing the file */
	/* Grow file here if need be. iomap_begin() does not have access
	 * to file pointer
	 */
	if (iov_iter_rw(from) == WRITE &&
	    ((iocb->ki_pos + iov_iter_count(from)) > i_size_read(inode))) {
		ret = __fuse_file_fallocate(iocb->ki_filp, 0, iocb->ki_pos,
						iov_iter_count(from));
		if (ret < 0) {
			printk("fallocate(offset=0x%llx length=0x%zx)"
			" failed. err=%zd\n", iocb->ki_pos,
			iov_iter_count(from), ret);
			goto out;
		}
		pr_debug("fallocate(offset=0x%llx length=0x%zx)"
		" succeed. ret=%zd\n", iocb->ki_pos, iov_iter_count(from), ret);
	}

	ret = dax_iomap_rw(iocb, from, &fuse_iomap_ops);

out:
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}

static void fuse_writepage_free(struct fuse_conn *fc, struct fuse_req *req)
{
	int i;

	for (i = 0; i < req->num_pages; i++)
		__free_page(req->pages[i]);

	if (req->ff)
		fuse_file_put(req->ff, false);
}

static void fuse_writepage_finish(struct fuse_conn *fc, struct fuse_req *req)
{
	struct inode *inode = req->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct backing_dev_info *bdi = inode_to_bdi(inode);
	int i;

	list_del(&req->writepages_entry);
	for (i = 0; i < req->num_pages; i++) {
		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(req->pages[i], NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
	}
	wake_up(&fi->page_waitq);
}

/* Called under fc->lock, may release and reacquire it */
static void fuse_send_writepage(struct fuse_conn *fc, struct fuse_req *req,
				loff_t size)
__releases(fc->lock)
__acquires(fc->lock)
{
	struct fuse_inode *fi = get_fuse_inode(req->inode);
	struct fuse_write_in *inarg = &req->misc.write.in;
	__u64 data_size = req->num_pages * PAGE_SIZE;

	if (!fc->connected)
		goto out_free;

	if (inarg->offset + data_size <= size) {
		inarg->size = data_size;
	} else if (inarg->offset < size) {
		inarg->size = size - inarg->offset;
	} else {
		/* Got truncated off completely */
		goto out_free;
	}

	req->in.args[1].size = inarg->size;
	fi->writectr++;
	fuse_request_send_background_locked(fc, req);
	return;

 out_free:
	fuse_writepage_finish(fc, req);
	spin_unlock(&fc->lock);
	fuse_writepage_free(fc, req);
	fuse_put_request(fc, req);
	spin_lock(&fc->lock);
}

/*
 * If fi->writectr is positive (no truncate or fsync going on) send
 * all queued writepage requests.
 *
 * Called with fc->lock
 */
void fuse_flush_writepages(struct inode *inode)
__releases(fc->lock)
__acquires(fc->lock)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	size_t crop = i_size_read(inode);
	struct fuse_req *req;

	while (fi->writectr >= 0 && !list_empty(&fi->queued_writes)) {
		req = list_entry(fi->queued_writes.next, struct fuse_req, list);
		list_del_init(&req->list);
		fuse_send_writepage(fc, req, crop);
	}
}

static void fuse_writepage_end(struct fuse_conn *fc, struct fuse_req *req)
{
	struct inode *inode = req->inode;
	struct fuse_inode *fi = get_fuse_inode(inode);

	mapping_set_error(inode->i_mapping, req->out.h.error);
	spin_lock(&fc->lock);
	while (req->misc.write.next) {
		struct fuse_conn *fc = get_fuse_conn(inode);
		struct fuse_write_in *inarg = &req->misc.write.in;
		struct fuse_req *next = req->misc.write.next;
		req->misc.write.next = next->misc.write.next;
		next->misc.write.next = NULL;
		next->ff = fuse_file_get(req->ff);
		list_add(&next->writepages_entry, &fi->writepages);

		/*
		 * Skip fuse_flush_writepages() to make it easy to crop requests
		 * based on primary request size.
		 *
		 * 1st case (trivial): there are no concurrent activities using
		 * fuse_set/release_nowrite.  Then we're on safe side because
		 * fuse_flush_writepages() would call fuse_send_writepage()
		 * anyway.
		 *
		 * 2nd case: someone called fuse_set_nowrite and it is waiting
		 * now for completion of all in-flight requests.  This happens
		 * rarely and no more than once per page, so this should be
		 * okay.
		 *
		 * 3rd case: someone (e.g. fuse_do_setattr()) is in the middle
		 * of fuse_set_nowrite..fuse_release_nowrite section.  The fact
		 * that fuse_set_nowrite returned implies that all in-flight
		 * requests were completed along with all of their secondary
		 * requests.  Further primary requests are blocked by negative
		 * writectr.  Hence there cannot be any in-flight requests and
		 * no invocations of fuse_writepage_end() while we're in
		 * fuse_set_nowrite..fuse_release_nowrite section.
		 */
		fuse_send_writepage(fc, next, inarg->offset + inarg->size);
	}
	fi->writectr--;
	fuse_writepage_finish(fc, req);
	spin_unlock(&fc->lock);
	fuse_writepage_free(fc, req);
}

static struct fuse_file *__fuse_write_file_get(struct fuse_conn *fc,
					       struct fuse_inode *fi)
{
	struct fuse_file *ff = NULL;

	spin_lock(&fc->lock);
	if (!list_empty(&fi->write_files)) {
		ff = list_entry(fi->write_files.next, struct fuse_file,
				write_entry);
		fuse_file_get(ff);
	}
	spin_unlock(&fc->lock);

	return ff;
}

static struct fuse_file *fuse_write_file_get(struct fuse_conn *fc,
					     struct fuse_inode *fi)
{
	struct fuse_file *ff = __fuse_write_file_get(fc, fi);
	WARN_ON(!ff);
	return ff;
}

int fuse_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_file *ff;
	int err;

	ff = __fuse_write_file_get(fc, fi);
	err = fuse_flush_times(inode, ff);
	if (ff)
		fuse_file_put(ff, 0);

	return err;
}

static int fuse_writepage_locked(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_req *req;
	struct page *tmp_page;
	int error = -ENOMEM;

	set_page_writeback(page);

	req = fuse_request_alloc_nofs(1);
	if (!req)
		goto err;

	/* writeback always goes to bg_queue */
	__set_bit(FR_BACKGROUND, &req->flags);
	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto err_free;

	error = -EIO;
	req->ff = fuse_write_file_get(fc, fi);
	if (!req->ff)
		goto err_nofile;

	fuse_write_fill(req, req->ff, page_offset(page), 0);

	copy_highpage(tmp_page, page);
	req->misc.write.in.write_flags |= FUSE_WRITE_CACHE;
	req->misc.write.next = NULL;
	req->in.argpages = 1;
	req->num_pages = 1;
	req->pages[0] = tmp_page;
	req->page_descs[0].offset = 0;
	req->page_descs[0].length = PAGE_SIZE;
	req->end = fuse_writepage_end;
	req->inode = inode;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	spin_lock(&fc->lock);
	list_add(&req->writepages_entry, &fi->writepages);
	list_add_tail(&req->list, &fi->queued_writes);
	fuse_flush_writepages(inode);
	spin_unlock(&fc->lock);

	end_page_writeback(page);

	return 0;

err_nofile:
	__free_page(tmp_page);
err_free:
	fuse_request_free(req);
err:
	mapping_set_error(page->mapping, error);
	end_page_writeback(page);
	return error;
}

static int fuse_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;

	if (fuse_page_is_writeback(page->mapping->host, page->index)) {
		/*
		 * ->writepages() should be called for sync() and friends.  We
		 * should only get here on direct reclaim and then we are
		 * allowed to skip a page which is already in flight
		 */
		WARN_ON(wbc->sync_mode == WB_SYNC_ALL);

		redirty_page_for_writepage(wbc, page);
		return 0;
	}

	err = fuse_writepage_locked(page);
	unlock_page(page);

	return err;
}

struct fuse_fill_wb_data {
	struct fuse_req *req;
	struct fuse_file *ff;
	struct inode *inode;
	struct page **orig_pages;
};

static void fuse_writepages_send(struct fuse_fill_wb_data *data)
{
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_inode *fi = get_fuse_inode(inode);
	int num_pages = req->num_pages;
	int i;

	req->ff = fuse_file_get(data->ff);
	spin_lock(&fc->lock);
	list_add_tail(&req->list, &fi->queued_writes);
	fuse_flush_writepages(inode);
	spin_unlock(&fc->lock);

	for (i = 0; i < num_pages; i++)
		end_page_writeback(data->orig_pages[i]);
}

static bool fuse_writepage_in_flight(struct fuse_req *new_req,
				     struct page *page)
{
	struct fuse_conn *fc = get_fuse_conn(new_req->inode);
	struct fuse_inode *fi = get_fuse_inode(new_req->inode);
	struct fuse_req *tmp;
	struct fuse_req *old_req;
	bool found = false;
	pgoff_t curr_index;

	BUG_ON(new_req->num_pages != 0);

	spin_lock(&fc->lock);
	list_del(&new_req->writepages_entry);
	list_for_each_entry(old_req, &fi->writepages, writepages_entry) {
		BUG_ON(old_req->inode != new_req->inode);
		curr_index = old_req->misc.write.in.offset >> PAGE_SHIFT;
		if (curr_index <= page->index &&
		    page->index < curr_index + old_req->num_pages) {
			found = true;
			break;
		}
	}
	if (!found) {
		list_add(&new_req->writepages_entry, &fi->writepages);
		goto out_unlock;
	}

	new_req->num_pages = 1;
	for (tmp = old_req; tmp != NULL; tmp = tmp->misc.write.next) {
		BUG_ON(tmp->inode != new_req->inode);
		curr_index = tmp->misc.write.in.offset >> PAGE_SHIFT;
		if (tmp->num_pages == 1 &&
		    curr_index == page->index) {
			old_req = tmp;
		}
	}

	if (old_req->num_pages == 1 && test_bit(FR_PENDING, &old_req->flags)) {
		struct backing_dev_info *bdi = inode_to_bdi(page->mapping->host);

		copy_highpage(old_req->pages[0], page);
		spin_unlock(&fc->lock);

		dec_wb_stat(&bdi->wb, WB_WRITEBACK);
		dec_node_page_state(page, NR_WRITEBACK_TEMP);
		wb_writeout_inc(&bdi->wb);
		fuse_writepage_free(fc, new_req);
		fuse_request_free(new_req);
		goto out;
	} else {
		new_req->misc.write.next = old_req->misc.write.next;
		old_req->misc.write.next = new_req;
	}
out_unlock:
	spin_unlock(&fc->lock);
out:
	return found;
}

static int fuse_writepages_fill(struct page *page,
		struct writeback_control *wbc, void *_data)
{
	struct fuse_fill_wb_data *data = _data;
	struct fuse_req *req = data->req;
	struct inode *inode = data->inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct page *tmp_page;
	bool is_writeback;
	int err;

	if (!data->ff) {
		err = -EIO;
		data->ff = fuse_write_file_get(fc, get_fuse_inode(inode));
		if (!data->ff)
			goto out_unlock;
	}

	/*
	 * Being under writeback is unlikely but possible.  For example direct
	 * read to an mmaped fuse file will set the page dirty twice; once when
	 * the pages are faulted with get_user_pages(), and then after the read
	 * completed.
	 */
	is_writeback = fuse_page_is_writeback(inode, page->index);

	if (req && req->num_pages &&
	    (is_writeback || req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	     (req->num_pages + 1) * PAGE_SIZE > fc->max_write ||
	     data->orig_pages[req->num_pages - 1]->index + 1 != page->index)) {
		fuse_writepages_send(data);
		data->req = NULL;
	}
	err = -ENOMEM;
	tmp_page = alloc_page(GFP_NOFS | __GFP_HIGHMEM);
	if (!tmp_page)
		goto out_unlock;

	/*
	 * The page must not be redirtied until the writeout is completed
	 * (i.e. userspace has sent a reply to the write request).  Otherwise
	 * there could be more than one temporary page instance for each real
	 * page.
	 *
	 * This is ensured by holding the page lock in page_mkwrite() while
	 * checking fuse_page_is_writeback().  We already hold the page lock
	 * since clear_page_dirty_for_io() and keep it held until we add the
	 * request to the fi->writepages list and increment req->num_pages.
	 * After this fuse_page_is_writeback() will indicate that the page is
	 * under writeback, so we can release the page lock.
	 */
	if (data->req == NULL) {
		struct fuse_inode *fi = get_fuse_inode(inode);

		err = -ENOMEM;
		req = fuse_request_alloc_nofs(FUSE_MAX_PAGES_PER_REQ);
		if (!req) {
			__free_page(tmp_page);
			goto out_unlock;
		}

		fuse_write_fill(req, data->ff, page_offset(page), 0);
		req->misc.write.in.write_flags |= FUSE_WRITE_CACHE;
		req->misc.write.next = NULL;
		req->in.argpages = 1;
		__set_bit(FR_BACKGROUND, &req->flags);
		req->num_pages = 0;
		req->end = fuse_writepage_end;
		req->inode = inode;

		spin_lock(&fc->lock);
		list_add(&req->writepages_entry, &fi->writepages);
		spin_unlock(&fc->lock);

		data->req = req;
	}
	set_page_writeback(page);

	copy_highpage(tmp_page, page);
	req->pages[req->num_pages] = tmp_page;
	req->page_descs[req->num_pages].offset = 0;
	req->page_descs[req->num_pages].length = PAGE_SIZE;

	inc_wb_stat(&inode_to_bdi(inode)->wb, WB_WRITEBACK);
	inc_node_page_state(tmp_page, NR_WRITEBACK_TEMP);

	err = 0;
	if (is_writeback && fuse_writepage_in_flight(req, page)) {
		end_page_writeback(page);
		data->req = NULL;
		goto out_unlock;
	}
	data->orig_pages[req->num_pages] = page;

	/*
	 * Protected by fc->lock against concurrent access by
	 * fuse_page_is_writeback().
	 */
	spin_lock(&fc->lock);
	req->num_pages++;
	spin_unlock(&fc->lock);

out_unlock:
	unlock_page(page);

	return err;
}

static int fuse_dax_writepages(struct address_space *mapping,
				struct writeback_control *wbc)
{

	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);

	return dax_writeback_mapping_range(mapping,
		NULL, fc->dax_dev, wbc);
}

static int fuse_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct fuse_fill_wb_data data;
	int err;

	err = -EIO;
	if (is_bad_inode(inode))
		goto out;

	data.inode = inode;
	data.req = NULL;
	data.ff = NULL;

	err = -ENOMEM;
	data.orig_pages = kcalloc(FUSE_MAX_PAGES_PER_REQ,
				  sizeof(struct page *),
				  GFP_NOFS);
	if (!data.orig_pages)
		goto out;

	err = write_cache_pages(mapping, wbc, fuse_writepages_fill, &data);
	if (data.req) {
		/* Ignore errors if we can write at least one page */
		BUG_ON(!data.req->num_pages);
		fuse_writepages_send(&data);
		err = 0;
	}
	if (data.ff)
		fuse_file_put(data.ff, false);

	kfree(data.orig_pages);
out:
	return err;
}

/*
 * It's worthy to make sure that space is reserved on disk for the write,
 * but how to implement it without killing performance need more thinking.
 */
static int fuse_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	pgoff_t index = pos >> PAGE_SHIFT;
	struct fuse_conn *fc = get_fuse_conn(file_inode(file));
	struct page *page;
	loff_t fsize;
	int err = -ENOMEM;

	WARN_ON(!fc->writeback_cache);

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		goto error;

	fuse_wait_on_page_writeback(mapping->host, page->index);

	if (PageUptodate(page) || len == PAGE_SIZE)
		goto success;
	/*
	 * Check if the start this page comes after the end of file, in which
	 * case the readpage can be optimized away.
	 */
	fsize = i_size_read(mapping->host);
	if (fsize <= (pos & PAGE_MASK)) {
		size_t off = pos & ~PAGE_MASK;
		if (off)
			zero_user_segment(page, 0, off);
		goto success;
	}
	err = fuse_do_readpage(file, page);
	if (err)
		goto cleanup;
success:
	*pagep = page;
	return 0;

cleanup:
	unlock_page(page);
	put_page(page);
error:
	return err;
}

static int fuse_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied,
		struct page *page, void *fsdata)
{
	struct inode *inode = page->mapping->host;

	/* Haven't copied anything?  Skip zeroing, size extending, dirtying. */
	if (!copied)
		goto unlock;

	if (!PageUptodate(page)) {
		/* Zero any unwritten bytes at the end of the page */
		size_t endoff = (pos + copied) & ~PAGE_MASK;
		if (endoff)
			zero_user_segment(page, endoff, PAGE_SIZE);
		SetPageUptodate(page);
	}

	fuse_write_update_size(inode, pos + copied);
	set_page_dirty(page);

unlock:
	unlock_page(page);
	put_page(page);

	return copied;
}

static int fuse_launder_page(struct page *page)
{
	int err = 0;
	if (clear_page_dirty_for_io(page)) {
		struct inode *inode = page->mapping->host;
		err = fuse_writepage_locked(page);
		if (!err)
			fuse_wait_on_page_writeback(inode, page->index);
	}
	return err;
}

/*
 * Write back dirty pages now, because there may not be any suitable
 * open files later
 */
static void fuse_vma_close(struct vm_area_struct *vma)
{
	filemap_write_and_wait(vma->vm_file->f_mapping);
}

/*
 * Wait for writeback against this page to complete before allowing it
 * to be marked dirty again, and hence written back again, possibly
 * before the previous writepage completed.
 *
 * Block here, instead of in ->writepage(), so that the userspace fs
 * can only block processes actually operating on the filesystem.
 *
 * Otherwise unprivileged userspace fs would be able to block
 * unrelated:
 *
 * - page migration
 * - sync(2)
 * - try_to_free_pages() with order > PAGE_ALLOC_COSTLY_ORDER
 */
static vm_fault_t fuse_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);

	file_update_time(vmf->vma->vm_file);
	lock_page(page);
	if (page->mapping != inode->i_mapping) {
		unlock_page(page);
		return VM_FAULT_NOPAGE;
	}

	fuse_wait_on_page_writeback(inode, page->index);
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct fuse_file_vm_ops = {
	.close		= fuse_vma_close,
	.fault		= filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= fuse_page_mkwrite,
};

static int fuse_direct_mmap(struct file *file, struct vm_area_struct *vma);
static int fuse_dax_mmap(struct file *file, struct vm_area_struct *vma);

static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;

	/* DAX mmap is superior to direct_io mmap */
	if (IS_DAX(file_inode(file)))
		return fuse_dax_mmap(file, vma);

	if (ff->open_flags & FOPEN_DIRECT_IO)
		return fuse_direct_mmap(file, vma);

	if ((vma->vm_flags & VM_SHARED) && (vma->vm_flags & VM_MAYWRITE))
		fuse_link_write_file(file);

	file_accessed(file);
	vma->vm_ops = &fuse_file_vm_ops;
	return 0;
}

static int fuse_direct_mmap(struct file *file, struct vm_area_struct *vma)
{
	/* Can't provide the coherency needed for MAP_SHARED */
	if (vma->vm_flags & VM_MAYSHARE)
		return -ENODEV;

	invalidate_inode_pages2(file->f_mapping);

	return generic_file_mmap(file, vma);
}

static ssize_t fuse_file_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe, size_t len,
				     unsigned int flags)
{
	struct fuse_file *ff = in->private_data;

	if (ff->open_flags & FOPEN_DIRECT_IO)
		return default_file_splice_read(in, ppos, pipe, len, flags);
	else
		return generic_file_splice_read(in, ppos, pipe, len, flags);

}
static int __fuse_dax_fault(struct vm_fault *vmf, enum page_entry_size pe_size,
			    bool write)
{
	int ret, error = 0;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;
	pfn_t pfn;
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool retry = false;

	if (write)
		sb_start_pagefault(sb);

retry:
	if (retry && !(fc->nr_free_ranges > 0)) {
		ret = -EINTR;
		if (wait_event_killable_exclusive(fc->dax_range_waitq,
					(fc->nr_free_ranges > 0)))
			goto out;
	}

	/*
	 * We need to serialize against not only truncate but also against
	 * fuse dax memory range reclaim. While a range is being reclaimed,
	 * we do not want any read/write/mmap to make progress and try
	 * to populate page cache or access memory we are trying to free.
	 */
	down_read(&get_fuse_inode(inode)->i_mmap_sem);
	ret = dax_iomap_fault(vmf, pe_size, &pfn, &error, &fuse_iomap_ops);
	if ((ret & VM_FAULT_ERROR) && error == -ENOSPC) {
		error = 0;
		retry = true;
		up_read(&get_fuse_inode(inode)->i_mmap_sem);
		goto retry;
	}

	if (ret & VM_FAULT_NEEDDSYNC)
		ret = dax_finish_sync_fault(vmf, pe_size, pfn);

	up_read(&get_fuse_inode(inode)->i_mmap_sem);

out:
	if (write)
		sb_end_pagefault(sb);

	return ret;
}

static int fuse_dax_fault(struct vm_fault *vmf)
{
	return __fuse_dax_fault(vmf, PE_SIZE_PTE,
				vmf->flags & FAULT_FLAG_WRITE);
}

static int fuse_dax_huge_fault(struct vm_fault *vmf,
			       enum page_entry_size pe_size)
{
	return __fuse_dax_fault(vmf, pe_size, vmf->flags & FAULT_FLAG_WRITE);
}

static int fuse_dax_page_mkwrite(struct vm_fault *vmf)
{
	return __fuse_dax_fault(vmf, PE_SIZE_PTE, true);
}

static int fuse_dax_pfn_mkwrite(struct vm_fault *vmf)
{
	return __fuse_dax_fault(vmf, PE_SIZE_PTE, true);
}

static const struct vm_operations_struct fuse_dax_vm_ops = {
	.fault		= fuse_dax_fault,
	.huge_fault	= fuse_dax_huge_fault,
	.page_mkwrite	= fuse_dax_page_mkwrite,
	.pfn_mkwrite	= fuse_dax_pfn_mkwrite,
};

static int fuse_dax_mmap(struct file *file, struct vm_area_struct *vma)
{
	file_accessed(file);
	vma->vm_ops = &fuse_dax_vm_ops;
	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;
	return 0;
}

static int convert_fuse_file_lock(struct fuse_conn *fc,
				  const struct fuse_file_lock *ffl,
				  struct file_lock *fl)
{
	switch (ffl->type) {
	case F_UNLCK:
		break;

	case F_RDLCK:
	case F_WRLCK:
		if (ffl->start > OFFSET_MAX || ffl->end > OFFSET_MAX ||
		    ffl->end < ffl->start)
			return -EIO;

		fl->fl_start = ffl->start;
		fl->fl_end = ffl->end;

		/*
		 * Convert pid into init's pid namespace.  The locks API will
		 * translate it into the caller's pid namespace.
		 */
		rcu_read_lock();
		fl->fl_pid = pid_nr_ns(find_pid_ns(ffl->pid, fc->pid_ns), &init_pid_ns);
		rcu_read_unlock();
		break;

	default:
		return -EIO;
	}
	fl->fl_type = ffl->type;
	return 0;
}

static void fuse_lk_fill(struct fuse_args *args, struct file *file,
			 const struct file_lock *fl, int opcode, pid_t pid,
			 int flock, struct fuse_lk_in *inarg)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;

	memset(inarg, 0, sizeof(*inarg));
	inarg->fh = ff->fh;
	inarg->owner = fuse_lock_owner_id(fc, fl->fl_owner);
	inarg->lk.start = fl->fl_start;
	inarg->lk.end = fl->fl_end;
	inarg->lk.type = fl->fl_type;
	inarg->lk.pid = pid;
	if (flock)
		inarg->lk_flags |= FUSE_LK_FLOCK;
	args->in.h.opcode = opcode;
	args->in.h.nodeid = get_node_id(inode);
	args->in.numargs = 1;
	args->in.args[0].size = sizeof(*inarg);
	args->in.args[0].value = inarg;
}

static int fuse_getlk(struct file *file, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_lk_in inarg;
	struct fuse_lk_out outarg;
	int err;

	fuse_lk_fill(&args, file, fl, FUSE_GETLK, 0, 0, &inarg);
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);
	if (!err)
		err = convert_fuse_file_lock(fc, &outarg.lk, fl);

	return err;
}

static int fuse_setlk(struct file *file, struct file_lock *fl, int flock)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_lk_in inarg;
	int opcode = (fl->fl_flags & FL_SLEEP) ? FUSE_SETLKW : FUSE_SETLK;
	struct pid *pid = fl->fl_type != F_UNLCK ? task_tgid(current) : NULL;
	pid_t pid_nr = pid_nr_ns(pid, fc->pid_ns);
	int err;

	if (fl->fl_lmops && fl->fl_lmops->lm_grant) {
		/* NLM needs asynchronous locks, which we don't support yet */
		return -ENOLCK;
	}

	/* Unlock on close is handled by the flush method */
	if ((fl->fl_flags & FL_CLOSE_POSIX) == FL_CLOSE_POSIX)
		return 0;

	fuse_lk_fill(&args, file, fl, opcode, pid_nr, flock, &inarg);
	err = fuse_simple_request(fc, &args);

	/* locking is restartable */
	if (err == -EINTR)
		err = -ERESTARTSYS;

	return err;
}

static int fuse_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (cmd == F_CANCELLK) {
		err = 0;
	} else if (cmd == F_GETLK) {
		if (fc->no_lock) {
			posix_test_lock(file, fl);
			err = 0;
		} else
			err = fuse_getlk(file, fl);
	} else {
		if (fc->no_lock)
			err = posix_lock_file(file, fl, NULL);
		else
			err = fuse_setlk(file, fl, 0);
	}
	return err;
}

static int fuse_file_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);
	int err;

	if (fc->no_flock) {
		err = locks_lock_file_wait(file, fl);
	} else {
		struct fuse_file *ff = file->private_data;

		/* emulate flock with POSIX locks */
		ff->flock = true;
		err = fuse_setlk(file, fl, 1);
	}

	return err;
}

static sector_t fuse_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	FUSE_ARGS(args);
	struct fuse_bmap_in inarg;
	struct fuse_bmap_out outarg;
	int err;

	if (!inode->i_sb->s_bdev || fc->no_bmap)
		return 0;

	memset(&inarg, 0, sizeof(inarg));
	inarg.block = block;
	inarg.blocksize = inode->i_sb->s_blocksize;
	args.in.h.opcode = FUSE_BMAP;
	args.in.h.nodeid = get_node_id(inode);
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS)
		fc->no_bmap = 1;

	return err ? 0 : outarg.block;
}

static loff_t fuse_lseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_file *ff = file->private_data;
	FUSE_ARGS(args);
	struct fuse_lseek_in inarg = {
		.fh = ff->fh,
		.offset = offset,
		.whence = whence
	};
	struct fuse_lseek_out outarg;
	int err;

	if (fc->no_lseek)
		goto fallback;

	args.in.h.opcode = FUSE_LSEEK;
	args.in.h.nodeid = ff->nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);
	if (err) {
		if (err == -ENOSYS) {
			fc->no_lseek = 1;
			goto fallback;
		}
		return err;
	}

	return vfs_setpos(file, outarg.offset, inode->i_sb->s_maxbytes);

fallback:
	err = fuse_update_attributes(inode, file);
	if (!err)
		return generic_file_llseek(file, offset, whence);
	else
		return err;
}

static loff_t fuse_file_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t retval;
	struct inode *inode = file_inode(file);

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
		 /* No i_mutex protection necessary for SEEK_CUR and SEEK_SET */
		retval = generic_file_llseek(file, offset, whence);
		break;
	case SEEK_END:
		inode_lock(inode);
		retval = fuse_update_attributes(inode, file);
		if (!retval)
			retval = generic_file_llseek(file, offset, whence);
		inode_unlock(inode);
		break;
	case SEEK_HOLE:
	case SEEK_DATA:
		inode_lock(inode);
		retval = fuse_lseek(file, offset, whence);
		inode_unlock(inode);
		break;
	default:
		retval = -EINVAL;
	}

	return retval;
}

/*
 * CUSE servers compiled on 32bit broke on 64bit kernels because the
 * ABI was defined to be 'struct iovec' which is different on 32bit
 * and 64bit.  Fortunately we can determine which structure the server
 * used from the size of the reply.
 */
static int fuse_copy_ioctl_iovec_old(struct iovec *dst, void *src,
				     size_t transferred, unsigned count,
				     bool is_compat)
{
#ifdef CONFIG_COMPAT
	if (count * sizeof(struct compat_iovec) == transferred) {
		struct compat_iovec *ciov = src;
		unsigned i;

		/*
		 * With this interface a 32bit server cannot support
		 * non-compat (i.e. ones coming from 64bit apps) ioctl
		 * requests
		 */
		if (!is_compat)
			return -EINVAL;

		for (i = 0; i < count; i++) {
			dst[i].iov_base = compat_ptr(ciov[i].iov_base);
			dst[i].iov_len = ciov[i].iov_len;
		}
		return 0;
	}
#endif

	if (count * sizeof(struct iovec) != transferred)
		return -EIO;

	memcpy(dst, src, transferred);
	return 0;
}

/* Make sure iov_length() won't overflow */
static int fuse_verify_ioctl_iov(struct iovec *iov, size_t count)
{
	size_t n;
	u32 max = FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT;

	for (n = 0; n < count; n++, iov++) {
		if (iov->iov_len > (size_t) max)
			return -ENOMEM;
		max -= iov->iov_len;
	}
	return 0;
}

static int fuse_copy_ioctl_iovec(struct fuse_conn *fc, struct iovec *dst,
				 void *src, size_t transferred, unsigned count,
				 bool is_compat)
{
	unsigned i;
	struct fuse_ioctl_iovec *fiov = src;

	if (fc->minor < 16) {
		return fuse_copy_ioctl_iovec_old(dst, src, transferred,
						 count, is_compat);
	}

	if (count * sizeof(struct fuse_ioctl_iovec) != transferred)
		return -EIO;

	for (i = 0; i < count; i++) {
		/* Did the server supply an inappropriate value? */
		if (fiov[i].base != (unsigned long) fiov[i].base ||
		    fiov[i].len != (unsigned long) fiov[i].len)
			return -EIO;

		dst[i].iov_base = (void __user *) (unsigned long) fiov[i].base;
		dst[i].iov_len = (size_t) fiov[i].len;

#ifdef CONFIG_COMPAT
		if (is_compat &&
		    (ptr_to_compat(dst[i].iov_base) != fiov[i].base ||
		     (compat_size_t) dst[i].iov_len != fiov[i].len))
			return -EIO;
#endif
	}

	return 0;
}


/*
 * For ioctls, there is no generic way to determine how much memory
 * needs to be read and/or written.  Furthermore, ioctls are allowed
 * to dereference the passed pointer, so the parameter requires deep
 * copying but FUSE has no idea whatsoever about what to copy in or
 * out.
 *
 * This is solved by allowing FUSE server to retry ioctl with
 * necessary in/out iovecs.  Let's assume the ioctl implementation
 * needs to read in the following structure.
 *
 * struct a {
 *	char	*buf;
 *	size_t	buflen;
 * }
 *
 * On the first callout to FUSE server, inarg->in_size and
 * inarg->out_size will be NULL; then, the server completes the ioctl
 * with FUSE_IOCTL_RETRY set in out->flags, out->in_iovs set to 1 and
 * the actual iov array to
 *
 * { { .iov_base = inarg.arg,	.iov_len = sizeof(struct a) } }
 *
 * which tells FUSE to copy in the requested area and retry the ioctl.
 * On the second round, the server has access to the structure and
 * from that it can tell what to look for next, so on the invocation,
 * it sets FUSE_IOCTL_RETRY, out->in_iovs to 2 and iov array to
 *
 * { { .iov_base = inarg.arg,	.iov_len = sizeof(struct a)	},
 *   { .iov_base = a.buf,	.iov_len = a.buflen		} }
 *
 * FUSE will copy both struct a and the pointed buffer from the
 * process doing the ioctl and retry ioctl with both struct a and the
 * buffer.
 *
 * This time, FUSE server has everything it needs and completes ioctl
 * without FUSE_IOCTL_RETRY which finishes the ioctl call.
 *
 * Copying data out works the same way.
 *
 * Note that if FUSE_IOCTL_UNRESTRICTED is clear, the kernel
 * automatically initializes in and out iovs by decoding @cmd with
 * _IOC_* macros and the server is not allowed to request RETRY.  This
 * limits ioctl data transfers to well-formed ioctls and is the forced
 * behavior for all FUSE servers.
 */
long fuse_do_ioctl(struct file *file, unsigned int cmd, unsigned long arg,
		   unsigned int flags)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_ioctl_in inarg = {
		.fh = ff->fh,
		.cmd = cmd,
		.arg = arg,
		.flags = flags
	};
	struct fuse_ioctl_out outarg;
	struct fuse_req *req = NULL;
	struct page **pages = NULL;
	struct iovec *iov_page = NULL;
	struct iovec *in_iov = NULL, *out_iov = NULL;
	unsigned int in_iovs = 0, out_iovs = 0, num_pages = 0, max_pages;
	size_t in_size, out_size, transferred, c;
	int err, i;
	struct iov_iter ii;

#if BITS_PER_LONG == 32
	inarg.flags |= FUSE_IOCTL_32BIT;
#else
	if (flags & FUSE_IOCTL_COMPAT)
		inarg.flags |= FUSE_IOCTL_32BIT;
#endif

	/* assume all the iovs returned by client always fits in a page */
	BUILD_BUG_ON(sizeof(struct fuse_ioctl_iovec) * FUSE_IOCTL_MAX_IOV > PAGE_SIZE);

	err = -ENOMEM;
	pages = kcalloc(FUSE_MAX_PAGES_PER_REQ, sizeof(pages[0]), GFP_KERNEL);
	iov_page = (struct iovec *) __get_free_page(GFP_KERNEL);
	if (!pages || !iov_page)
		goto out;

	/*
	 * If restricted, initialize IO parameters as encoded in @cmd.
	 * RETRY from server is not allowed.
	 */
	if (!(flags & FUSE_IOCTL_UNRESTRICTED)) {
		struct iovec *iov = iov_page;

		iov->iov_base = (void __user *)arg;
		iov->iov_len = _IOC_SIZE(cmd);

		if (_IOC_DIR(cmd) & _IOC_WRITE) {
			in_iov = iov;
			in_iovs = 1;
		}

		if (_IOC_DIR(cmd) & _IOC_READ) {
			out_iov = iov;
			out_iovs = 1;
		}
	}

 retry:
	inarg.in_size = in_size = iov_length(in_iov, in_iovs);
	inarg.out_size = out_size = iov_length(out_iov, out_iovs);

	/*
	 * Out data can be used either for actual out data or iovs,
	 * make sure there always is at least one page.
	 */
	out_size = max_t(size_t, out_size, PAGE_SIZE);
	max_pages = DIV_ROUND_UP(max(in_size, out_size), PAGE_SIZE);

	/* make sure there are enough buffer pages and init request with them */
	err = -ENOMEM;
	if (max_pages > FUSE_MAX_PAGES_PER_REQ)
		goto out;
	while (num_pages < max_pages) {
		pages[num_pages] = alloc_page(GFP_KERNEL | __GFP_HIGHMEM);
		if (!pages[num_pages])
			goto out;
		num_pages++;
	}

	req = fuse_get_req(fc, num_pages);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		req = NULL;
		goto out;
	}
	memcpy(req->pages, pages, sizeof(req->pages[0]) * num_pages);
	req->num_pages = num_pages;
	fuse_page_descs_length_init(req, 0, req->num_pages);

	/* okay, let's send it to the client */
	req->in.h.opcode = FUSE_IOCTL;
	req->in.h.nodeid = ff->nodeid;
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	if (in_size) {
		req->in.numargs++;
		req->in.args[1].size = in_size;
		req->in.argpages = 1;

		err = -EFAULT;
		iov_iter_init(&ii, WRITE, in_iov, in_iovs, in_size);
		for (i = 0; iov_iter_count(&ii) && !WARN_ON(i >= num_pages); i++) {
			c = copy_page_from_iter(pages[i], 0, PAGE_SIZE, &ii);
			if (c != PAGE_SIZE && iov_iter_count(&ii))
				goto out;
		}
	}

	req->out.numargs = 2;
	req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	req->out.args[1].size = out_size;
	req->out.argpages = 1;
	req->out.argvar = 1;

	fuse_request_send(fc, req);
	err = req->out.h.error;
	transferred = req->out.args[1].size;
	fuse_put_request(fc, req);
	req = NULL;
	if (err)
		goto out;

	/* did it ask for retry? */
	if (outarg.flags & FUSE_IOCTL_RETRY) {
		void *vaddr;

		/* no retry if in restricted mode */
		err = -EIO;
		if (!(flags & FUSE_IOCTL_UNRESTRICTED))
			goto out;

		in_iovs = outarg.in_iovs;
		out_iovs = outarg.out_iovs;

		/*
		 * Make sure things are in boundary, separate checks
		 * are to protect against overflow.
		 */
		err = -ENOMEM;
		if (in_iovs > FUSE_IOCTL_MAX_IOV ||
		    out_iovs > FUSE_IOCTL_MAX_IOV ||
		    in_iovs + out_iovs > FUSE_IOCTL_MAX_IOV)
			goto out;

		vaddr = kmap_atomic(pages[0]);
		err = fuse_copy_ioctl_iovec(fc, iov_page, vaddr,
					    transferred, in_iovs + out_iovs,
					    (flags & FUSE_IOCTL_COMPAT) != 0);
		kunmap_atomic(vaddr);
		if (err)
			goto out;

		in_iov = iov_page;
		out_iov = in_iov + in_iovs;

		err = fuse_verify_ioctl_iov(in_iov, in_iovs);
		if (err)
			goto out;

		err = fuse_verify_ioctl_iov(out_iov, out_iovs);
		if (err)
			goto out;

		goto retry;
	}

	err = -EIO;
	if (transferred > inarg.out_size)
		goto out;

	err = -EFAULT;
	iov_iter_init(&ii, READ, out_iov, out_iovs, transferred);
	for (i = 0; iov_iter_count(&ii) && !WARN_ON(i >= num_pages); i++) {
		c = copy_page_to_iter(pages[i], 0, PAGE_SIZE, &ii);
		if (c != PAGE_SIZE && iov_iter_count(&ii))
			goto out;
	}
	err = 0;
 out:
	if (req)
		fuse_put_request(fc, req);
	free_page((unsigned long) iov_page);
	while (num_pages)
		__free_page(pages[--num_pages]);
	kfree(pages);

	return err ? err : outarg.result;
}
EXPORT_SYMBOL_GPL(fuse_do_ioctl);

long fuse_ioctl_common(struct file *file, unsigned int cmd,
		       unsigned long arg, unsigned int flags)
{
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_current_process(fc))
		return -EACCES;

	if (is_bad_inode(inode))
		return -EIO;

	return fuse_do_ioctl(file, cmd, arg, flags);
}

static long fuse_file_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	return fuse_ioctl_common(file, cmd, arg, 0);
}

static long fuse_file_compat_ioctl(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	return fuse_ioctl_common(file, cmd, arg, FUSE_IOCTL_COMPAT);
}

/*
 * All files which have been polled are linked to RB tree
 * fuse_conn->polled_files which is indexed by kh.  Walk the tree and
 * find the matching one.
 */
static struct rb_node **fuse_find_polled_node(struct fuse_conn *fc, u64 kh,
					      struct rb_node **parent_out)
{
	struct rb_node **link = &fc->polled_files.rb_node;
	struct rb_node *last = NULL;

	while (*link) {
		struct fuse_file *ff;

		last = *link;
		ff = rb_entry(last, struct fuse_file, polled_node);

		if (kh < ff->kh)
			link = &last->rb_left;
		else if (kh > ff->kh)
			link = &last->rb_right;
		else
			return link;
	}

	if (parent_out)
		*parent_out = last;
	return link;
}

/*
 * The file is about to be polled.  Make sure it's on the polled_files
 * RB tree.  Note that files once added to the polled_files tree are
 * not removed before the file is released.  This is because a file
 * polled once is likely to be polled again.
 */
static void fuse_register_polled_file(struct fuse_conn *fc,
				      struct fuse_file *ff)
{
	spin_lock(&fc->lock);
	if (RB_EMPTY_NODE(&ff->polled_node)) {
		struct rb_node **link, *uninitialized_var(parent);

		link = fuse_find_polled_node(fc, ff->kh, &parent);
		BUG_ON(*link);
		rb_link_node(&ff->polled_node, parent, link);
		rb_insert_color(&ff->polled_node, &fc->polled_files);
	}
	spin_unlock(&fc->lock);
}

__poll_t fuse_file_poll(struct file *file, poll_table *wait)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fc;
	struct fuse_poll_in inarg = { .fh = ff->fh, .kh = ff->kh };
	struct fuse_poll_out outarg;
	FUSE_ARGS(args);
	int err;

	if (fc->no_poll)
		return DEFAULT_POLLMASK;

	poll_wait(file, &ff->poll_wait, wait);
	inarg.events = mangle_poll(poll_requested_events(wait));

	/*
	 * Ask for notification iff there's someone waiting for it.
	 * The client may ignore the flag and always notify.
	 */
	if (waitqueue_active(&ff->poll_wait)) {
		inarg.flags |= FUSE_POLL_SCHEDULE_NOTIFY;
		fuse_register_polled_file(fc, ff);
	}

	args.in.h.opcode = FUSE_POLL;
	args.in.h.nodeid = ff->nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	args.out.numargs = 1;
	args.out.args[0].size = sizeof(outarg);
	args.out.args[0].value = &outarg;
	err = fuse_simple_request(fc, &args);

	if (!err)
		return demangle_poll(outarg.revents);
	if (err == -ENOSYS) {
		fc->no_poll = 1;
		return DEFAULT_POLLMASK;
	}
	return EPOLLERR;
}
EXPORT_SYMBOL_GPL(fuse_file_poll);

/*
 * This is called from fuse_handle_notify() on FUSE_NOTIFY_POLL and
 * wakes up the poll waiters.
 */
int fuse_notify_poll_wakeup(struct fuse_conn *fc,
			    struct fuse_notify_poll_wakeup_out *outarg)
{
	u64 kh = outarg->kh;
	struct rb_node **link;

	spin_lock(&fc->lock);

	link = fuse_find_polled_node(fc, kh, NULL);
	if (*link) {
		struct fuse_file *ff;

		ff = rb_entry(*link, struct fuse_file, polled_node);
		wake_up_interruptible_sync(&ff->poll_wait);
	}

	spin_unlock(&fc->lock);
	return 0;
}

static void fuse_do_truncate(struct file *file)
{
	struct inode *inode = file->f_mapping->host;
	struct iattr attr;

	attr.ia_valid = ATTR_SIZE;
	attr.ia_size = i_size_read(inode);

	attr.ia_file = file;
	attr.ia_valid |= ATTR_FILE;

	fuse_do_setattr(file_dentry(file), &attr, file);
}

static inline loff_t fuse_round_up(loff_t off)
{
	return round_up(off, FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT);
}

static ssize_t
fuse_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	DECLARE_COMPLETION_ONSTACK(wait);
	ssize_t ret = 0;
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	bool async_dio = ff->fc->async_dio;
	loff_t pos = 0;
	struct inode *inode;
	loff_t i_size;
	size_t count = iov_iter_count(iter);
	loff_t offset = iocb->ki_pos;
	struct fuse_io_priv *io;

	pos = offset;
	inode = file->f_mapping->host;
	i_size = i_size_read(inode);

	if ((iov_iter_rw(iter) == READ) && (offset > i_size))
		return 0;

	/* optimization for short read */
	if (async_dio && iov_iter_rw(iter) != WRITE && offset + count > i_size) {
		if (offset >= i_size)
			return 0;
		iov_iter_truncate(iter, fuse_round_up(i_size - offset));
		count = iov_iter_count(iter);
	}

	io = kmalloc(sizeof(struct fuse_io_priv), GFP_KERNEL);
	if (!io)
		return -ENOMEM;
	spin_lock_init(&io->lock);
	kref_init(&io->refcnt);
	io->reqs = 1;
	io->bytes = -1;
	io->size = 0;
	io->offset = offset;
	io->write = (iov_iter_rw(iter) == WRITE);
	io->err = 0;
	/*
	 * By default, we want to optimize all I/Os with async request
	 * submission to the client filesystem if supported.
	 */
	io->async = async_dio;
	io->iocb = iocb;
	io->blocking = is_sync_kiocb(iocb);

	/*
	 * We cannot asynchronously extend the size of a file.
	 * In such case the aio will behave exactly like sync io.
	 */
	if ((offset + count > i_size) && iov_iter_rw(iter) == WRITE)
		io->blocking = true;

	if (io->async && io->blocking) {
		/*
		 * Additional reference to keep io around after
		 * calling fuse_aio_complete()
		 */
		kref_get(&io->refcnt);
		io->done = &wait;
	}

	if (iov_iter_rw(iter) == WRITE) {
		ret = fuse_direct_io(io, iter, &pos, FUSE_DIO_WRITE);
		fuse_invalidate_attr(inode);
	} else {
		ret = __fuse_direct_read(io, iter, &pos);
	}

	if (io->async) {
		fuse_aio_complete(io, ret < 0 ? ret : 0, -1);

		/* we have a non-extending, async request, so return */
		if (!io->blocking)
			return -EIOCBQUEUED;

		wait_for_completion(&wait);
		ret = fuse_get_res_by_io(io);
	}

	kref_put(&io->refcnt, fuse_io_release);

	if (iov_iter_rw(iter) == WRITE) {
		if (ret > 0)
			fuse_write_update_size(inode, pos);
		else if (ret < 0 && offset + count > i_size)
			fuse_do_truncate(file);
	}

	return ret;
}

/*
 * This variant does not take any inode lock and if locking is required,
 * caller is supposed to hold lock
 */
static long __fuse_file_fallocate(struct file *file, int mode,
					loff_t offset, loff_t length)
{
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = ff->fc;
	FUSE_ARGS(args);
	struct fuse_fallocate_in inarg = {
		.fh = ff->fh,
		.offset = offset,
		.length = length,
		.mode = mode
	};
	int err;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (fc->no_fallocate)
		return -EOPNOTSUPP;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		loff_t endbyte = offset + length - 1;
		err = filemap_write_and_wait_range(inode->i_mapping, offset,
							endbyte);
		if (err)
			goto out;
		fuse_sync_writes(inode);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE))
		set_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	args.in.h.opcode = FUSE_FALLOCATE;
	args.in.h.nodeid = ff->nodeid;
	args.in.numargs = 1;
	args.in.args[0].size = sizeof(inarg);
	args.in.args[0].value = &inarg;
	err = fuse_simple_request(fc, &args);
	if (err == -ENOSYS) {
		fc->no_fallocate = 1;
		err = -EOPNOTSUPP;
	}
	if (err)
		goto out;

	/* we could have extended the file */
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		bool changed = fuse_write_update_size(inode, offset + length);

		if (changed && fc->writeback_cache)
			file_update_time(file);
	}

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		down_write(&fi->i_mmap_sem);
		truncate_pagecache_range(inode, offset, offset + length - 1);
		down_write(&fi->i_mmap_sem);
	}
	fuse_invalidate_attr(inode);

out:
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		clear_bit(FUSE_I_SIZE_UNSTABLE, &fi->state);

	return err;
}

static long fuse_file_fallocate(struct file *file, int mode, loff_t offset,
				loff_t length)
{
	struct fuse_file *ff = file->private_data;
	struct inode *inode = file_inode(file);
	struct fuse_conn *fc = ff->fc;
	int err;
	bool lock_inode = !(mode & FALLOC_FL_KEEP_SIZE) ||
			   (mode & FALLOC_FL_PUNCH_HOLE);

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (fc->no_fallocate)
		return -EOPNOTSUPP;

	if (lock_inode)
		inode_lock(inode);

	err = __fuse_file_fallocate(file, mode, offset, length);
	if (lock_inode)
		inode_unlock(inode);
	return err;
}

static const struct file_operations fuse_file_operations = {
	.llseek		= fuse_file_llseek,
	.read_iter	= fuse_file_read_iter,
	.write_iter	= fuse_file_write_iter,
 	.mmap		= fuse_file_mmap,
	.splice_read    = fuse_file_splice_read,
	.open		= fuse_open,
	.flush		= fuse_flush,
	.release	= fuse_release,
	.fsync		= fuse_fsync,
	.lock		= fuse_file_lock,
	.get_unmapped_area = thp_get_unmapped_area,
	.flock		= fuse_file_flock,
	.unlocked_ioctl	= fuse_file_ioctl,
	.compat_ioctl	= fuse_file_compat_ioctl,
	.poll		= fuse_file_poll,
	.fallocate	= fuse_file_fallocate,
};

static const struct address_space_operations fuse_file_aops  = {
	.readpage	= fuse_readpage,
	.writepage	= fuse_writepage,
	.writepages	= fuse_writepages,
	.launder_page	= fuse_launder_page,
	.readpages	= fuse_readpages,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.bmap		= fuse_bmap,
	.direct_IO	= fuse_direct_IO,
	.write_begin	= fuse_write_begin,
	.write_end	= fuse_write_end,
};

static const struct address_space_operations fuse_dax_file_aops  = {
	.writepages	= fuse_dax_writepages,
	.direct_IO	= noop_direct_IO,
	.set_page_dirty	= noop_set_page_dirty,
	.invalidatepage	= noop_invalidatepage,
};

void fuse_init_file_inode(struct inode *inode)
{
 	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_conn *fc = get_fuse_conn(inode);

	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
	fi->dmap_tree = RB_ROOT_CACHED;

	if (fc->dax_dev) {
		inode->i_flags |= S_DAX;
		inode->i_data.a_ops = &fuse_dax_file_aops;
	}
}

int fuse_dax_reclaim_dmap_locked(struct fuse_conn *fc, struct inode *inode,
				struct fuse_dax_mapping *dmap)
{
	int ret;
	struct fuse_inode *fi = get_fuse_inode(inode);

	ret = filemap_fdatawrite_range(inode->i_mapping, dmap->start,
					dmap->end);
	if (ret) {
		printk("filemap_fdatawrite_range() failed. err=%d start=0x%llx,"
			" end=0x%llx\n", ret, dmap->start, dmap->end);
		return ret;
	}

	ret = invalidate_inode_pages2_range(inode->i_mapping,
					dmap->start >> PAGE_SHIFT,
					dmap->end >> PAGE_SHIFT);
	/* TODO: What to do if above fails? For now,
	 * leave the range in place.
	 */
	if (ret) {
		printk("invalidate_inode_pages2_range() failed err=%d\n", ret);
		return ret;
	}

	/* Remove dax mapping from inode interval tree now */
	fuse_dax_interval_tree_remove(dmap, &fi->dmap_tree);
	fi->nr_dmaps--;
	return 0;
}

/* First first mapping in the tree and free it. */
struct fuse_dax_mapping *fuse_dax_reclaim_first_mapping_locked(
				struct fuse_conn *fc, struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_dax_mapping *dmap;
	int ret;

	/* Find fuse dax mapping at file offset inode. */
	dmap = fuse_dax_interval_tree_iter_first(&fi->dmap_tree, 0, -1);
	if (!dmap)
		return NULL;

	ret = fuse_dax_reclaim_dmap_locked(fc, inode, dmap);
	if (ret < 0)
		return ERR_PTR(ret);

	/* Clean up dmap. Do not add back to free list */
	dmap_remove_busy_list(fc, dmap);
	dmap->inode = NULL;
	dmap->start = dmap->end = 0;

	pr_debug("fuse: reclaimed memory range window_offset=0x%llx,"
				" length=0x%llx\n", dmap->window_offset,
				dmap->length);
	return dmap;
}

/*
 * First first mapping in the tree and free it and return it. Do not add
 * it back to free pool.
 *
 * This is called with inode lock held.
 */
struct fuse_dax_mapping *fuse_dax_reclaim_first_mapping(struct fuse_conn *fc,
					struct inode *inode)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_dax_mapping *dmap;

	down_write(&fi->i_mmap_sem);
	down_write(&fi->i_dmap_sem);
	dmap = fuse_dax_reclaim_first_mapping_locked(fc, inode);
	up_write(&fi->i_dmap_sem);
	up_write(&fi->i_mmap_sem);
	return dmap;
}

static struct fuse_dax_mapping *alloc_dax_mapping_reclaim(struct fuse_conn *fc,
					struct inode *inode)
{
	struct fuse_dax_mapping *dmap;
	struct fuse_inode *fi = get_fuse_inode(inode);

	while(1) {
		dmap = alloc_dax_mapping(fc);
		if (dmap)
			return dmap;

		if (fi->nr_dmaps)
			return fuse_dax_reclaim_first_mapping(fc, inode);
		/*
		 * There are no mappings which can be reclaimed.
		 * Wait for one.
		 */
		if (!(fc->nr_free_ranges > 0)) {
			if (wait_event_killable_exclusive(fc->dax_range_waitq,
					(fc->nr_free_ranges > 0)))
				return ERR_PTR(-EINTR);
		}
	}
}

int fuse_dax_free_one_mapping_locked(struct fuse_conn *fc, struct inode *inode,
				u64 dmap_start)
{
	int ret;
	struct fuse_inode *fi = get_fuse_inode(inode);
	struct fuse_dax_mapping *dmap;

	WARN_ON(!inode_is_locked(inode));

	/* Find fuse dax mapping at file offset inode. */
	dmap = fuse_dax_interval_tree_iter_first(&fi->dmap_tree, dmap_start,
							dmap_start);

	/* Range already got cleaned up by somebody else */
	if (!dmap)
		return 0;

	ret = fuse_dax_reclaim_dmap_locked(fc, inode, dmap);
	if (ret < 0)
		return ret;

	/* Cleanup dmap entry and add back to free list */
	spin_lock(&fc->lock);
	__dmap_remove_busy_list(fc, dmap);
	dmap->inode = NULL;
	dmap->start = dmap->end = 0;
	__free_dax_mapping(fc, dmap);
	spin_unlock(&fc->lock);

	pr_debug("fuse: freed memory range window_offset=0x%llx,"
				" length=0x%llx\n", dmap->window_offset,
				dmap->length);
	return ret;
}

/*
 * Free a range of memory.
 * Locking.
 * 1. Take inode->i_rwsem to prever further read/write.
 * 2. Take fuse_inode->i_mmap_sem to block dax faults.
 * 3. Take fuse_inode->i_dmap_sem to protect interval tree. It might not
 *    be strictly necessary as lock 1 and 2 seem sufficient.
 */
int fuse_dax_free_one_mapping(struct fuse_conn *fc, struct inode *inode,
				u64 dmap_start)
{
	int ret;
	struct fuse_inode *fi = get_fuse_inode(inode);

	/*
	 * If process is blocked waiting for memory while holding inode
	 * lock, we will deadlock. So continue to free next range.
	 */
	if (!inode_trylock(inode))
		return -EAGAIN;
	down_write(&fi->i_mmap_sem);
	down_write(&fi->i_dmap_sem);
	ret = fuse_dax_free_one_mapping_locked(fc, inode, dmap_start);
	up_write(&fi->i_dmap_sem);
	up_write(&fi->i_mmap_sem);
	inode_unlock(inode);
	return ret;
}

int fuse_dax_free_memory(struct fuse_conn *fc, unsigned long nr_to_free)
{
	struct fuse_dax_mapping *dmap, *pos, *temp;
	int ret, nr_freed = 0, nr_eagain = 0;
	u64 dmap_start = 0, window_offset = 0;
	struct inode *inode = NULL;

	/* Pick first busy range and free it for now*/
	while(1) {
		if (nr_freed >= nr_to_free)
			break;

		if (nr_eagain > 20) {
			queue_delayed_work(system_long_wq, &fc->dax_free_work,
						msecs_to_jiffies(10));
			return 0;
		}

		dmap = NULL;
		spin_lock(&fc->lock);

		list_for_each_entry_safe(pos, temp, &fc->busy_ranges,
						busy_list) {
			inode = igrab(pos->inode);
			/*
			 * This inode is going away. That will free
			 * up all the ranges anyway, continue to
			 * next range.
			 */
			if (!inode)
				continue;
			/*
			 * Take this element off list and add it tail. If
			 * inode lock can't be obtained, this will help with
			 * selecting new element
			 */
			dmap = pos;
			list_move_tail(&dmap->busy_list, &fc->busy_ranges);
			dmap_start = dmap->start;
			window_offset = dmap->window_offset;
			break;
		}
		spin_unlock(&fc->lock);
		if (!dmap)
			return 0;

		ret = fuse_dax_free_one_mapping(fc, inode, dmap_start);
		iput(inode);
		if (ret && ret != -EAGAIN) {
			printk("%s(window_offset=0x%llx) failed. err=%d\n",
				__func__, window_offset, ret);
			return ret;
		}

		/* Could not get inode lock. Try next element */
		if (ret == -EAGAIN) {
			nr_eagain++;
			continue;
		}
		nr_freed++;
	}
	return 0;
}

/* TODO: This probably should go in inode.c */
void fuse_dax_free_mem_worker(struct work_struct *work)
{
	int ret;
	struct fuse_conn *fc = container_of(work, struct fuse_conn,
						dax_free_work.work);
	pr_debug("fuse: Worker to free memory called.\n");
	pr_debug("fuse: Worker to free memory called. nr_free_ranges=%lu"
		 " nr_busy_ranges=%lu\n", fc->nr_free_ranges,
		 fc->nr_busy_ranges);
	ret = fuse_dax_free_memory(fc, FUSE_DAX_RECLAIM_CHUNK);
	if (ret)
		pr_debug("fuse: fuse_dax_free_memory() failed with err=%d\n", ret);
}
