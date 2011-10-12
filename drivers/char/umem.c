/*
 * UMEM: user process backed memory.
 *
 * Copyright (c) 2011,
 * National Institute of Advanced Industrial Science and Technology
 *
 * https://sites.google.com/site/grivonhome/quick-kvm-migration
 * Author: Isaku Yamahata <yamahata at valinux co jp>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/memcontrol.h>
#include <linux/poll.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/miscdevice.h>
#include <linux/umem.h>

struct umem_page_req_list {
	struct list_head list;
	pgoff_t pgoff;
};


/* those constants are taken from kvm internal values. */
#define KVM_MAX_VCPUS           256
#define ASYNC_PF_PER_VCPU       64

#define ASYNC_REQ_MAX           (ASYNC_PF_PER_VCPU * KVM_MAX_VCPUS)
#define SYNC_REQ_MAX            (ASYNC_PF_PER_VCPU * KVM_MAX_VCPUS)

struct umem {
	loff_t size;
	pgoff_t pgoff_end;
	spinlock_t lock;

	wait_queue_head_t req_wait;

	int async_req_max;
	int async_req_nr;
	pgoff_t *async_req;

	/*
	 * Heuristic
	 * Asynchronous page fault with same pgoffset can occur repeatedly
	 * if guest kernel decides to schedule same process.
	 * In order to avoid to wake up with same request,
	 * record the async request and don't wake up.
	 */
#define ASYNC_LOG_MAX		(1 << 3)	/* must be power of 2 */
#define ASYNC_LOG_INVALID	((pgoff_t)-1)
	pgoff_t async_log[ASYNC_LOG_MAX];
	int async_log_index;

	int sync_req_max;
	unsigned long *sync_req_bitmap;
	unsigned long *sync_wait_bitmap;
	pgoff_t *sync_req;
	wait_queue_head_t *page_wait;

	int req_list_nr;
	struct list_head req_list;
	wait_queue_head_t req_list_wait;

	unsigned long *cached;
	unsigned long *faulted;

	bool mmapped;
	unsigned long vm_start;
	unsigned int vma_nr;
	struct task_struct *task;

	struct file *shmem_filp;
	struct vm_area_struct *vma;
};

static bool umem_initialized(struct umem *umem)
{
	BUG_ON(!spin_is_locked(&umem->lock));
	return umem->shmem_filp != NULL;
}

static void umem_release_fake_vmf(int ret, struct vm_fault *fake_vmf)
{
	if (ret & VM_FAULT_LOCKED) {
		unlock_page(fake_vmf->page);
	}
	page_cache_release(fake_vmf->page);
}

static int umem_minor_fault(struct umem *umem,
			    struct vm_area_struct *vma,
			    struct vm_fault *vmf)
{
	struct vm_fault fake_vmf;
	int ret;
	struct page *page;

	BUG_ON(!test_bit(vmf->pgoff, umem->cached));
	fake_vmf = *vmf;
	fake_vmf.page = NULL;
	ret = umem->vma->vm_ops->fault(umem->vma, &fake_vmf);
	if (ret & (VM_FAULT_ERROR | VM_FAULT_NOPAGE | VM_FAULT_RETRY))
		return ret;

	/*
	 * TODO: pull out fake_vmf->page from shmem file and donate it
	 * to this vma resolving the page fault.
	 * vmf->page = fake_vmf->page;
	 */

	page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, vmf->virtual_address);
	if (!page)
		return VM_FAULT_OOM;
	if (mem_cgroup_cache_charge(page, vma->vm_mm, GFP_KERNEL)) {
		umem_release_fake_vmf(ret, &fake_vmf);
		page_cache_release(page);
		return VM_FAULT_OOM;
	}

	copy_highpage(page, fake_vmf.page);
	umem_release_fake_vmf(ret, &fake_vmf);

	set_bit(vmf->pgoff, umem->faulted); /* SetPageUptodate() means wmb */
	ret |= VM_FAULT_LOCKED;
	SetPageUptodate(page);
	vmf->page = page;

	return ret;
}

static bool umem_fatal_signal_pending(struct task_struct *p)
{
	unsigned long flags;

	if (unlikely(fatal_signal_pending(p))) {
		return true;
	}

	/*
	 * Make the fault handler killable by not only tgkill, but also kill
	 * in order to make coredumping process killable.
	 *
	 * the umem fault handler can be called during coredump where
	 * the process is already group-exiting.
	 * In such situation, SIGKILL isn't delivered to other threads
	 * which isn't directly received the signal.
	 * So to catch SIGKILL sent to our process, shared signal must be
	 * checked.
	 *
	 * Another option is to tell users to use tgkill instead of kill
	 * in order to kill coredumping process.
	 */
	if (!spin_trylock_irqsave(&p->sighand->siglock, flags)) {
		return false;
	}
	if (unlikely(sigismember(&p->signal->shared_pending.signal, SIGKILL))) {
		sigaddset(&p->pending.signal, SIGKILL);
		spin_unlock_irqrestore(&p->sighand->siglock, flags);
		return true;
	}
	spin_unlock_irqrestore(&p->sighand->siglock, flags);

	return false;
}

static int umem_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *filp = vma->vm_file;
	struct umem *umem = filp->private_data;
	int fault_retry;
	unsigned long bit;
	DEFINE_WAIT(wait);

	if (vmf->pgoff >= umem->pgoff_end) {
		return VM_FAULT_SIGBUS;
	}

	if (test_bit(vmf->pgoff, umem->cached))
		return umem_minor_fault(umem, vma, vmf);

	/* major fault */
	fault_retry = vmf->flags & FAULT_FLAG_ALLOW_RETRY? VM_FAULT_RETRY: 0;
	spin_lock(&umem->lock);
	if (fault_retry) {
		if (vmf->flags & FAULT_FLAG_RETRY_NOWAIT) {
			/* async page fault */
			int i;
			for (i = 0; i < ASYNC_LOG_MAX; i++) {
				if (umem->async_log[i] == vmf->pgoff) {
					spin_unlock(&umem->lock);
					return VM_FAULT_RETRY;
				}
			}
			if (umem->async_req_nr < umem->async_req_max) {
				umem->async_req[umem->async_req_nr] =
					vmf->pgoff;
				umem->async_req_nr++;
				umem->async_log[umem->async_log_index] =
					vmf->pgoff;
				umem->async_log_index++;
				umem->async_log_index &= ASYNC_LOG_MAX;
			}
			spin_unlock(&umem->lock);
			wake_up_poll(&umem->req_wait, POLLIN);
			return VM_FAULT_RETRY;
		}

		up_read(&vma->vm_mm->mmap_sem);
	}

	/*
	 * sync fault sometimes follows async fault with same pgoff.
	 * Don't request same pgoff twice by easy check.
	 * NOTE: user process must be aware that same pgoff can be
	 * requested multiple times due to race condition anyway.
	 */
	if (umem->async_req_nr > 0 &&
	    umem->async_req[umem->async_req_nr - 1] == vmf->pgoff)
		umem->async_req_nr--;

again:
	bit = find_first_zero_bit(umem->sync_wait_bitmap,
				  umem->sync_req_max);
	if (likely(bit < umem->sync_req_max)) {
		umem->sync_req[bit] = vmf->pgoff;
		prepare_to_wait(&umem->page_wait[bit], &wait, TASK_KILLABLE);
		set_bit(bit, umem->sync_req_bitmap);
		set_bit(bit, umem->sync_wait_bitmap);
		spin_unlock(&umem->lock);
		wake_up_poll(&umem->req_wait, POLLIN);

		if (!test_bit(vmf->pgoff, umem->cached) &&
		    test_bit(bit, umem->sync_req_bitmap) &&
		    !umem_fatal_signal_pending(current))
			schedule();

		finish_wait(&umem->page_wait[bit], &wait);
		clear_bit(bit, umem->sync_wait_bitmap);
	} else {
		struct umem_page_req_list page_req_list = {
			.pgoff = vmf->pgoff,
		};
		umem->req_list_nr++;
		list_add_tail(&page_req_list.list, &umem->req_list);
		wake_up_poll(&umem->req_wait, POLLIN);
		for (;;) {
			prepare_to_wait(&umem->req_list_wait, &wait,
					TASK_KILLABLE);
			if (test_bit(vmf->pgoff, umem->cached) ||
			    umem_fatal_signal_pending(current)) {
				umem->req_list_nr--;
				break;
			}
			spin_unlock(&umem->lock);
			schedule();
			spin_lock(&umem->lock);
		}
		spin_unlock(&umem->lock);
		finish_wait(&umem->req_list_wait, &wait);
	}

	if (!test_bit(vmf->pgoff, umem->cached)) {
		if (fatal_signal_pending(current))
			return VM_FAULT_SIGBUS | fault_retry;

		spin_lock(&umem->lock);
		goto again;
	}

	if (fault_retry)
		return VM_FAULT_MAJOR | VM_FAULT_RETRY;
	return umem_minor_fault(umem, vma, vmf) | VM_FAULT_MAJOR;
}

/* for partial munmap */
static void umem_vma_open(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct umem *umem = filp->private_data;

	spin_lock(&umem->lock);
	umem->vma_nr++;
	spin_unlock(&umem->lock);
}

static void umem_vma_close(struct vm_area_struct *vma)
{
	struct file *filp = vma->vm_file;
	struct umem *umem = filp->private_data;
	struct task_struct *task = NULL;

	spin_lock(&umem->lock);
	umem->vma_nr--;
	if (umem->vma_nr == 0) {
		task = umem->task;
		umem->task = NULL;
	}
	spin_unlock(&umem->lock);

	if (task)
		put_task_struct(task);
}

static const struct vm_operations_struct umem_vm_ops = {
	.open = umem_vma_open,
	.close = umem_vma_close,
	.fault = umem_fault,
};

static int umem_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct umem *umem = filp->private_data;
	int error;

	/* allow mmap() only once */
	spin_lock(&umem->lock);
	if (unlikely(!umem_initialized(umem))) {
		error = -ENXIO;
		goto out;
	}
	if (umem->mmapped) {
		error = -EBUSY;
		goto out;
	}
	if (((vma->vm_end - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff >
	    umem->pgoff_end) {
		error = -EINVAL;
		goto out;
	}

	umem->mmapped = true;
	umem->vma_nr = 1;
	umem->vm_start = vma->vm_start;
	get_task_struct(current);
	umem->task = current;
	spin_unlock(&umem->lock);

	vma->vm_ops = &umem_vm_ops;
	vma->vm_flags |= VM_DONTCOPY | VM_DONTEXPAND;
	vma->vm_flags &= ~VM_SHARED;
	return 0;

out:
	spin_unlock(&umem->lock);
	return error;
}

static bool umem_req_pending(struct umem* umem)
{
	return !list_empty(&umem->req_list) ||
		!bitmap_empty(umem->sync_req_bitmap, umem->sync_req_max) ||
		(umem->async_req_nr > 0);
}

static unsigned int umem_poll(struct file* filp, poll_table *wait)
{
	struct umem *umem = filp->private_data;
	unsigned int events = 0;

	poll_wait(filp, &umem->req_wait, wait);

	spin_lock(&umem->lock);
	if (umem_initialized(umem) && umem_req_pending(umem))
		events |= POLLIN;
	spin_unlock(&umem->lock);

	return events;
}

/*
 * return value
 * true: finished
 * false: more request
 */
static bool umem_copy_page_request(struct umem *umem,
				   pgoff_t *pgoffs, int req_max,
				   int *req_nr)
{
	struct umem_page_req_list *req_list;
	struct umem_page_req_list *tmp;

	unsigned long bit;

	*req_nr = 0;
	list_for_each_entry_safe(req_list, tmp, &umem->req_list, list) {
		list_del(&req_list->list);
		pgoffs[*req_nr] = req_list->pgoff;
		(*req_nr)++;
		if (*req_nr >= req_max)
			return false;
	}

	bit = 0;
	for (;;) {
		bit = find_next_bit(umem->sync_req_bitmap, umem->sync_req_max,
				    bit);
		if (bit >= umem->sync_req_max)
			break;
		pgoffs[*req_nr] = umem->sync_req[bit];
		(*req_nr)++;
		clear_bit(bit, umem->sync_req_bitmap);
		if (*req_nr >= req_max)
			return false;
		bit++;
	}

	if (umem->async_req_nr > 0) {
		int nr = min(req_max - *req_nr, umem->async_req_nr);
		memcpy(pgoffs + *req_nr, umem->async_req,
		       sizeof(*umem->async_req) * nr);
		umem->async_req_nr -= nr;
		*req_nr += nr;
		memmove(umem->async_req, umem->sync_req + nr,
			umem->async_req_nr * sizeof(*umem->async_req));

	}
	return umem->async_req_nr == 0;
}

/* get page request from fault handler */
static ssize_t umem_read(struct file *filp, char __user *buf, size_t count,
			 loff_t *ppos)
{
	struct umem *umem = filp->private_data;
	pgoff_t __user *u_pgoffs = (pgoff_t*)buf;
	size_t nr_pgoffs = count / sizeof(u_pgoffs[0]);

	ssize_t ret = 0;
	DEFINE_WAIT(wait);

#define REQ_MAX	((size_t)32)
	pgoff_t pgoffs[REQ_MAX];
	size_t req_copied = 0;

	if (unlikely(nr_pgoffs == 0))
		return -EINVAL;

	spin_lock(&umem->lock);
	if (unlikely(!umem_initialized(umem))) {
		ret = -ENXIO;
		goto out_unlock;
	}

	for (;;) {
		prepare_to_wait(&umem->req_wait, &wait, TASK_INTERRUPTIBLE);
		if (umem_req_pending(umem)) {
			break;
		}
		if (filp->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		spin_unlock(&umem->lock);
		schedule();
		spin_lock(&umem->lock);
	}
	finish_wait(&umem->req_wait, &wait);
	if (ret)
		goto out_unlock;

	while (req_copied < nr_pgoffs) {
		int req_max;
		int req_nr;
		bool finished;
		req_max = min(nr_pgoffs - req_copied, REQ_MAX);
		finished = umem_copy_page_request(umem, pgoffs, req_max,
						  &req_nr);

		spin_unlock(&umem->lock);

		if (req_nr > 0) {
			ret = 0;
			if (copy_to_user(u_pgoffs + req_copied,
					 pgoffs, sizeof(*pgoffs) * req_nr)) {
				ret = -EFAULT;
				goto out;
			}
		}
		req_copied += req_nr;
		if (finished)
			goto out;

		spin_lock(&umem->lock);
	}

out_unlock:
	spin_unlock(&umem->lock);
out:
	if (ret < 0)
		return ret;
	return req_copied * sizeof(u_pgoffs[0]);
}

/* mark page cached and tell the fault handler that page is available */
static ssize_t umem_write(struct file *filp,
			  const char __user *buf, size_t count, loff_t *ppos)
{
	ssize_t ret = 0;
	struct umem *umem = filp->private_data;
	const pgoff_t __user *u_pgoffs = (const pgoff_t*)buf;
	size_t nr_pgoffs = count / sizeof(u_pgoffs[0]);

#define PG_MAX	((size_t)32)
	__u64 pgoffs[PG_MAX];
	size_t nr;
	unsigned long bit;
	bool wake_up_list;

	if (unlikely(nr_pgoffs == 0))
		return -EINVAL;

	spin_lock(&umem->lock);
	if (unlikely(!umem_initialized(umem))) {
		spin_unlock(&umem->lock);
		return -ENXIO;
	}
	spin_unlock(&umem->lock);

	nr = 0;
	while (nr < nr_pgoffs) {
		int todo = min(PG_MAX, (nr_pgoffs - nr));
		int i;

		if (copy_from_user(pgoffs, u_pgoffs + nr,
				   sizeof(*pgoffs) * todo)) {
			ret = -EFAULT;
			goto out;
		}
		for (i = 0; i < todo; ++i) {
			if (pgoffs[i] >= umem->pgoff_end) {
				ret = -EINVAL;
				goto out;
			}
			set_bit(pgoffs[i], umem->cached);
		}
		nr += todo;
	}

	smp_wmb();
	spin_lock(&umem->lock);
	bit = 0;
	for (;;) {
		bit = find_next_bit(umem->sync_wait_bitmap, umem->sync_req_max,
				    bit);
		if (bit >= umem->sync_req_max)
			break;
		if (test_bit(umem->sync_req[bit], umem->cached))
			wake_up(&umem->page_wait[bit]);
		bit++;
	}

	wake_up_list = (umem->req_list_nr > 0);
	spin_unlock(&umem->lock);

	if (wake_up_list)
		wake_up_all(&umem->req_list_wait);

out:
	if (ret < 0)
		return ret;
	return nr * sizeof(pgoffs[0]);
}

static int umem_make_vma_anonymous(struct umem *umem)
{
#if 1
	return -ENOSYS;
#else
	unsigned long saddr;
	unsigned long eaddr;
	unsigned long addr;
	unsigned long bit;
	struct task_struct *task;
	struct mm_struct *mm;

	spin_lock(&umem->lock);
	if (!umem_initialized(umem)) {
		spin_unlock(&umem->lock);
		return -ENXIO;
	}
	task = umem->task;
	saddr = umem->vm_start;
	eaddr = saddr + umem->size;
	bit = find_first_zero_bit(umem->faulted, umem->pgoff_end);
	if (bit < umem->pgoff_end) {
		spin_unlock(&umem->lock);
		return -EBUSY;
	}
	spin_unlock(&umem->lock);
	if (task == NULL)
		return 0;
	mm = get_task_mm(task);
	if (mm == NULL)
		return 0;

	addr = saddr;
	down_write(&mm->mmap_sem);
	while (addr < eaddr) {
		struct vm_area_struct *vma;
		vma = find_vma(mm, addr);
		if (umem_is_umem_vma(umem, vma)) {
			/* XXX incorrect. race/locking and more fix up */
			struct file *filp = vma->vm_file;
			vma->vm_ops->close(vma);
			vma->vm_ops = NULL;
			vma->vm_file = NULL;
			/* vma->vm_flags */
			fput(filp);
		}
		addr = vma->vm_end;
	}
	up_write(&mm->mmap_sem);

	mmput(mm);
	return 0;
#endif
}

static unsigned long umem_bitmap_bytes(unsigned long pgoff_end)
{
	return round_up(pgoff_end, BITS_PER_LONG) / 8;
}

static int umem_init(struct file *filp, struct umem_init *uinit)
{
	int error = 0;
	struct umem *umem = filp->private_data;
	struct vm_area_struct *vma = NULL;
	int shmem_fd;

	int async_req_max = ASYNC_REQ_MAX;
	pgoff_t *async_req = NULL;

	int sync_req_max = SYNC_REQ_MAX;
	unsigned long sync_bitmap_bytes;
	unsigned long *sync_req_bitmap = NULL;
	unsigned long *sync_wait_bitmap = NULL;
	pgoff_t *sync_req = NULL;
	wait_queue_head_t *page_wait = NULL;
	int i;

	unsigned long bitmap_bytes = 0;
	unsigned long *cached = NULL;
	unsigned long *faulted = NULL;


	if (uinit->size == 0)
		return -EINVAL;

	spin_lock(&umem->lock);
	if (umem_initialized(umem)) {
		spin_unlock(&umem->lock);
		return -EBUSY;
	}
	spin_unlock(&umem->lock);

	uinit->size = roundup(uinit->size, PAGE_SIZE);
	vma = kzalloc(sizeof(*vma), GFP_KERNEL);
	vma->vm_start = 0;
	vma->vm_end = uinit->size;
	/* this shmem file is used for temporal buffer for pages
	   so it's unlikely that so many pages exists in this shmem file */
	vma->vm_flags = VM_READ | VM_SHARED | VM_NOHUGEPAGE | VM_DONTCOPY |
		VM_DONTEXPAND;
	vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	vma->vm_pgoff = 0;
	INIT_LIST_HEAD(&vma->anon_vma_chain);

	shmem_fd = get_unused_fd();
	if (shmem_fd < 0) {
		error = shmem_fd;
		goto out;
	}
	error = shmem_zero_setup(vma);
	if (error < 0) {
		put_unused_fd(shmem_fd);
		goto out;
	}
	vma->vm_file->f_flags |= O_LARGEFILE;
	fd_install(shmem_fd, vma->vm_file);
	uinit->shmem_fd = shmem_fd;

	async_req = kzalloc(sizeof(*umem->async_req) * async_req_max,
			    GFP_KERNEL);

	sync_req_max = round_up(sync_req_max, BITS_PER_LONG);
	sync_bitmap_bytes = sizeof(unsigned long) *
		(sync_req_max / BITS_PER_LONG);
	sync_req_bitmap = kzalloc(sync_bitmap_bytes, GFP_KERNEL);
	sync_wait_bitmap = kzalloc(sync_bitmap_bytes, GFP_KERNEL);
	sync_req = kzalloc(sizeof(*umem->sync_req) * sync_req_max, GFP_KERNEL);
	page_wait = kzalloc(sizeof(*umem->page_wait) * sync_req_max,
			    GFP_KERNEL);
	for (i = 0; i < sync_req_max; ++i)
		init_waitqueue_head(&page_wait[i]);

	bitmap_bytes = umem_bitmap_bytes(uinit->size >> PAGE_SHIFT);
	if (bitmap_bytes > PAGE_SIZE) {
		cached = vzalloc(bitmap_bytes);
		faulted = vzalloc(bitmap_bytes);
	} else {
		cached = kzalloc(bitmap_bytes, GFP_KERNEL);
		faulted = kzalloc(bitmap_bytes, GFP_KERNEL);
	}

	spin_lock(&umem->lock);
	if (unlikely(umem_initialized(umem))) {
		spin_unlock(&umem->lock);
		error = -EBUSY;
		goto out;
	}
	umem->shmem_filp = vma->vm_file;
	get_file(umem->shmem_filp);
	umem->vma = vma;

	umem->size = uinit->size;
	umem->pgoff_end = umem->size >> PAGE_SHIFT;

	umem->async_req_max = async_req_max;
	umem->async_req_nr = 0;
	umem->async_req = async_req;

	umem->sync_req_max = sync_req_max;
	umem->sync_req_bitmap = sync_req_bitmap;
	umem->sync_wait_bitmap = sync_wait_bitmap;
	umem->sync_req = sync_req;
	umem->page_wait = page_wait;
	umem->req_list_nr = 0;

	umem->cached = cached;
	umem->faulted = faulted;

	spin_unlock(&umem->lock);

	return 0;

 out:
	kfree(vma);
	kfree(async_req);
	kfree(sync_req_bitmap);
	kfree(sync_wait_bitmap);
	kfree(sync_req);
	kfree(page_wait);
	if (bitmap_bytes > PAGE_SIZE) {
		vfree(cached);
		vfree(faulted);
	} else {
		kfree(cached);
		kfree(faulted);
	}
	return error;
}

static long umem_ioctl(struct file *filp, unsigned int ioctl,
		       unsigned long arg)
{
	struct umem *umem = filp->private_data;
	void __user *argp = (void __user *) arg;
	long ret = 0;

	switch (ioctl) {
	case UMEM_INIT: {
		struct umem_init uinit;
		if (copy_from_user(&uinit, argp, sizeof(uinit))) {
			ret = -EFAULT;
			break;
		}
		ret = umem_init(filp, &uinit);
		if (ret)
			break;
		if (copy_to_user(argp, &uinit, sizeof(uinit)))
			ret = -EFAULT;
		break;
	}
	case UMEM_MAKE_VMA_ANONYMOUS:
		ret = umem_make_vma_anonymous(umem);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

static void umem_free(struct umem *umem)
{
	if (umem == NULL)
		return;

	if (umem->task) {
		put_task_struct(umem->task);
		umem->task = NULL;
	}

	kfree(umem->vma);
	if (umem->shmem_filp)
		fput(umem->shmem_filp);

	kfree(umem->async_req);
	kfree(umem->sync_req_bitmap);
	kfree(umem->sync_wait_bitmap);
	kfree(umem->sync_req);
	kfree(umem->page_wait);

	if (umem_bitmap_bytes(umem->pgoff_end) > PAGE_SIZE) {
		vfree(umem->cached);
		vfree(umem->faulted);
	} else {
		kfree(umem->cached);
		kfree(umem->faulted);
	}

	kfree(umem);
}

static int umem_release(struct inode *inode, struct file *filp)
{
	struct umem *umem = filp->private_data;
	umem_free(umem);
	return 0;
}

static int umem_open(struct inode *inode, struct file *filp)
{
	struct umem *umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	int i;

	spin_lock_init(&umem->lock);
	init_waitqueue_head(&umem->req_wait);
	INIT_LIST_HEAD(&umem->req_list);
	init_waitqueue_head(&umem->req_list_wait);
	umem->mmapped = false;
	for (i = 0; i < ASYNC_LOG_MAX; ++i) {
		umem->async_log[i] = ASYNC_LOG_INVALID;
	}

	filp->private_data = umem;
	return 0;
}

static struct file_operations umem_fops = {
	.open		= umem_open,
	.release	= umem_release,
	.unlocked_ioctl = umem_ioctl,
	.mmap		= umem_mmap,
	.poll		= umem_poll,
	.read		= umem_read,
	.write		= umem_write,
	.llseek		= noop_llseek,
};

static struct miscdevice umem_dev = {
	MISC_DYNAMIC_MINOR,
	"umem",
	&umem_fops,
};

static int __init umem_dev_init(void)
{
	int r;
	r = misc_register(&umem_dev);
	if (r) {
		printk(KERN_ERR "umem: misc device register failed\n");
		return r;
	}
	return 0;
}
module_init(umem_dev_init);

static void __exit umem_dev_exit(void)
{
	misc_deregister(&umem_dev);
}
module_exit(umem_dev_exit);

MODULE_DESCRIPTION("UMEM user process backed memory driver "
		   "for distributed shared memory");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Isaku Yamahata");
