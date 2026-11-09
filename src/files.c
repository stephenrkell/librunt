#define _GNU_SOURCE

struct file_metadata;
/* Used to ensure --wrappability of the relevant symbols i.e.
 * preventing direct self-calls to them.
 * See note on __runt_files_notify_load below. In short, call
 * the __wrap_ entry point and not the call itself. */
struct file_metadata *(__attribute__((warning("do not call __runt_files_notify_load from files.c; use __wrap_*")))
	__runt_files_notify_load)(void *handle, const void *load_site);
struct file_metadata *(__attribute__((warning("do not call __runt_files_metadata_by_addr from files.c; use __wrap_*")))
 __runt_files_metadata_by_addr)(void *addr);

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <link.h>
#include <sys/mman.h>
#include "relf.h"
#include "dso-meta.h"
#include "vas.h"
#include "librunt.h"
#include "librunt_private.h"
int fstat(int fd, struct stat *buf);


/* This file's logic really belongs in the dynamic linker.
 * It is responding to load and unload events.
 * Also, it'd be great if we could keep a file descriptor on
 * all the files we loaded -- rather than having to look them up again
 * by name.
 * We also want phdr, ehdr and shdr access. */

static _Bool trying_to_initialize;
static _Bool initialized;

struct lm_pair
{
	struct link_map *lm;
	struct file_metadata *fm;
};
/* NOTE: in liballocs, this lm_pairs structure should never be used,
 * as it is . */
static struct lm_pair (__attribute__((aligned(COMMON_PAGE_SIZE))) lm_pairs)[COMMON_PAGE_SIZE / sizeof (struct lm_pair)];
static unsigned npairs;
static 
#ifndef NO_PTHREADS
#include <pthread.h>
#define BIG_LOCK \
        int lock_ret = pthread_mutex_lock(&mutex); \
        assert(lock_ret == 0);
#define BIG_UNLOCK \
        lock_ret = pthread_mutex_unlock(&mutex); \
        assert(lock_ret == 0);
static pthread_mutex_t mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
#else
#define BIG_LOCK
#define BIG_UNLOCK
#endif
static int compare_lm_pair_by_load_addr(const void *v1, const void *v2)
{
	/* Trick: null pointers always compare *higher*. This is so that if we
	 * null out an entry and re-sort, we compact to the beginning.
	 * (But that doesn't mean that a load address of zero compares higher...
	 * it doesn't.) */
	const struct lm_pair *p1 = v1;
	const struct lm_pair *p2 = v2;
	if (p1 == p2) return 0;
	if (!p1->lm) /* p2 compares higher */ return -1;
	if (!p2->lm) /* p1 compares higher */ return 1;
	uintptr_t addr1 = (uintptr_t) p1->lm->l_addr;
	uintptr_t addr2 = (uintptr_t) p2->lm->l_addr;
	/* avoid integer truncation issues by just returning -1 or 1 */
	return (addr1 == addr2) ? 0 : (addr1 < addr2) ? -1 : 1;
}
void __insert_file_metadata(struct link_map *lm, struct file_metadata *fm) __attribute__((weak,visibility("protected")));
void __insert_file_metadata(struct link_map *lm, struct file_metadata *fm)
{
	BIG_LOCK
	lm_pairs[npairs++] = (struct lm_pair) { .lm = lm, .fm = fm };
	qsort(lm_pairs, npairs, sizeof lm_pairs[0], compare_lm_pair_by_load_addr);
	BIG_UNLOCK
}
void __delete_file_metadata(struct file_metadata **p) __attribute__((weak,visibility("protected")));
void __delete_file_metadata(struct file_metadata **p)
{
	__runt_deinit_file_metadata(*p);
	__private_free(*p);
	BIG_LOCK
	/* Clear both pointers in the pair */
	bzero((char *)((uintptr_t) p - offsetof(struct lm_pair, fm)), sizeof (struct lm_pair));
	qsort(lm_pairs, npairs, sizeof lm_pairs[0], compare_lm_pair_by_load_addr);
	--npairs;
	BIG_UNLOCK
}
struct file_metadata *__alloc_file_metadata(unsigned nsegs) __attribute__((weak,visibility("protected")));
struct file_metadata *__alloc_file_metadata(unsigned nsegs)
{
	size_t meta_sz = offsetof(struct file_metadata, segments)
		+ nsegs * sizeof (struct segment_metadata);
	void *meta = __private_malloc(meta_sz);
	if (!meta) abort();
	bzero(meta, meta_sz);
	return meta;
}

int __reopen_file(const char *filename) __attribute__((weak,visibility("protected")));
int __reopen_file(const char *filename)
{
	return open(filename, O_RDONLY);
}

struct lm_pair *lookup_by_addr(void *addr)
{
#define proj_npair_load_addr(p) (p)->lm->l_addr
	if (npairs == 0) return NULL;
	struct lm_pair *found = bsearch_leq_generic(struct lm_pair, (uintptr_t) addr,
		&lm_pairs[0], npairs, proj_npair_load_addr);
	if (!found) return NULL;
	/* Sanity check: we know addr is >= the load address of this file,
	 * but it within the file's dynamic extent? */
	uintptr_t query_vaddr = (uintptr_t) addr - found->lm->l_addr;
	if (query_vaddr < found->fm->vaddr_end) return found;
	return NULL;
#undef proj_npair_load_addr
}
struct link_map *__runt_files_lookup_by_addr(void *addr)
{
	if (!__librunt_is_initialized) __librunt_global_init();
	struct lm_pair *p = lookup_by_addr(addr);
	return p ? p->lm : NULL;
}

static struct file_metadata *metadata_for_addr(void *addr)
{
	struct lm_pair *p = lookup_by_addr(addr);
	return p ? p->fm : NULL;
}
/* See note above! Don't call this; call its __wrap_ wrapper. If
 * there's no wrapper we'll --defsym it as an alias. */
struct file_metadata *__wrap___runt_files_metadata_by_addr(void *addr);
struct file_metadata *__runt_files_metadata_by_addr(void *addr)
{
	if (!__librunt_is_initialized) __librunt_global_init();
	return metadata_for_addr(addr);
}

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata);
struct segments
{
	const ElfW(Phdr) *phdrs;
	ElfW(Half) phnum;
	unsigned nload;
};
static int discover_segments_cb(struct dl_phdr_info *info, size_t size, void *segments_as_void);

struct file_metadata *__wrap___runt_files_notify_load(void *handle, const void *load_site);

void __runt_files_init(void) __attribute__((constructor(102)));
void __runt_files_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		__runt_auxv_init();
		/* Snapshot the early libs. This is basically whatever was
		 * loaded by the dynamic linker at start-up. */
		init_early_libs();

		/* FIXME: arguably, for dynamically linked programs, the allocation
		 * site of files is somewhere inside the dynamic linker. E.g.
		 * if the linker was run by the kernel's loader (and not by directly
		 * running the linker on the command line, e.g.
		 * /path/to/ld.so /path/to/executable) it should be _dl_start, else
		 * it should be wherever in the dynamic linker did the load. We can
		 * distinguish all these cases, and should do.... */
		const void *program_entry_point = __runt_auxv_get_program_entry_point();

		/* We probably don't need to iterate over all DSOs -- those that have been
		 * dlopened by us since execution started (e.g. the dlbind lib)
		 * were already notified/added earlier. So we only iterate
		 * over those we snapshotted. But if we *haven't* run dlopen
		 * at all yet, just iterate over everything. */
		assert(early_lib_handles[0]);
		for (unsigned i = 0; i < MAX_EARLY_LIBS; ++i)
		{
			if (!early_lib_handles[i]) break;
			__wrap___runt_files_notify_load(early_lib_handles[i],
				program_entry_point);
		}
		initialized = 1;
		trying_to_initialize = 0;
	}
}

static ElfW(Phdr) *find_mapped_phdrs(struct link_map *l, int fd, ElfW(Ehdr) *out_ehdr, struct segments *out_sinfo)
{
	/* 0. With just the link map l, we know that
	 *    -- the mapping at l->l_ld is the PT_LOAD overlapping the PT_DYNAMIC
	 *    -- something *may* be mapped at l->l_addr, and if so, we can assume it
	 *         is one of the PT_LOADs. */
	ElfW(Ehdr) ehdr;
	ssize_t nread = pread(fd, &ehdr, sizeof ehdr, 0); // XXX: don't assume file begins at offset 0?
		// this can easily be rewritten to do sequential I/O, seeking forward for each phdr
		// (but remember to rewind it to its original position)
	if (nread != sizeof ehdr) abort();
	if (out_ehdr) *out_ehdr = ehdr;
	ElfW(Phdr) phdrs[ehdr.e_phnum];
	if (out_sinfo) out_sinfo->phnum = ehdr.e_phnum;
	unsigned nload = 0;
	for (unsigned i = 0; i < ehdr.e_phnum; ++i)
	{
		nread = pread(fd, &phdrs[i], sizeof phdrs[0], ehdr.e_phoff + i * ehdr.e_phentsize);
		if (nread != sizeof phdrs[0]) abort();
		if (phdrs[i].p_type == PT_LOAD) ++nload;
	}
	if (out_sinfo) out_sinfo->nload = nload;
	/* Now we've taken a copy of the program headers. That might allow us to infer
	 * that they're already mapped. */
#if 0 /* PT_PHDR is actually irrelevant, but if it weren't, we might do this. */
	ElfW(Phdr) *pt_phdr = NULL;
	for (unsigned i = 0; i < ehdr.e_phnum; ++i)
	{
		if (phdrs[i].p_type == PT_PHDR) { pt_phdr = &phdrs[i]; break; }
	}
#endif
	/* Does any PT_LOAD cover the phdrs themselves? NOTE that this doens't depend
	 * on whether there's a PT_PHDR. */
	ElfW(Addr) phdrs_mapped_vaddr = (ElfW(Addr))-1;
	for (unsigned i = 0; i < ehdr.e_phnum; ++i)
	{
		if (    phdrs[i].p_type == PT_LOAD
		     && phdrs[i].p_offset <= ehdr.e_phoff
		     && (0 != (phdrs[i].p_flags & PF_R))
		     && phdrs[i].p_offset + phdrs[i].p_filesz >=
		            ehdr.e_phoff + ehdr.e_phentsize * ehdr.e_phnum)
		{
			/* This means we've found a phdr that overlaps e_phoff in offset-space
			 * and covers the entirety of the phdrs, and is readable.
			 * In theory there could be more than one of these. Take the first. */
			phdrs_mapped_vaddr = phdrs[i].p_vaddr + (ehdr.e_phoff - phdrs[i].p_offset);
		}
	}
	ElfW(Phdr) *found;
	if (phdrs_mapped_vaddr != (ElfW(Addr))-1) found = (void*)(l->l_addr + phdrs_mapped_vaddr);
	else found = NULL;
	if (out_sinfo) out_sinfo->phdrs = found;
	return found;
	// if found is null, the caller will have to map them separately
	// XXX: we've already taken a copy, so isn't this a wasted effort? Just use our copy?
	// Maybe, but it's more uniform to have them be one of our extra_mappings, so that e.g. we
	// munmap them rather than freeing the memory holding the copy.
}

static void *get_or_map_extra_file_range_fd_no_phdrs(struct link_map *l, struct extra_mapping (*extra_mappings)[MAPPING_MAX],
		size_t length, int fd, off_t offset); // sub-helper
static void *get_or_map_file_range(struct link_map *l,
	ElfW(Phdr) *phdrs, unsigned phnum,
	struct extra_mapping (*extra_mappings)[MAPPING_MAX],
	size_t length, int fd, off_t offset)
{
	/* Check whether we already have this range, *either*
	 * - in an existing memory mapping resulting from a LOAD phdr, or
	 * - in an extra mapping we made earlier.
	 *
	 * Subtlety: don't assume the 'phdrs' we're passed are the PT_LOADed phdr -- they
	 * might be a copy, and the caller might be using us to map the true phdr data.
	 * But if we *are* passed the true phdr data (a mapping thereof), we don't want a
	 * duplicate mapping -- and this is the common case, the dynamic linker has mapped
	 * the phdrs itself (cf. just read()ing them).
	 *
	 * This is confusing. It comes down to: don't make an extra_mapping of
	 * the phdrs unless the dynamic linker didn't map them as part of any PT_LOAD.
	 *
	 * Previously this function is wrong when asked for a non-phdr data, but when
	 * phdrs are not located yet. We need a bootstrapping stage where we get hold of the
	 * phdrs mapping, or make it if the dynamic linker didn't. Reading the phdrs by file
	 * I/O is a step that enables us to *find* the already-existing mapping if there is
	 * one. That's get_or_map_extra_file_range_fd_no_phdrs. We have this right now, I think.
	 */
	if (phdrs) for (unsigned i = 0; i < phnum; ++i)
	{
		ElfW(Phdr) *phdr = &phdrs[i];
		/* Conservatively we can only permit non-writable LOADs here,
		 * because file and memory may have diverged. A common culprit
		 * is copy relocs... copy-relocatable data might be placed in a
		 * region of the file that overlaps the mapped section headers,
		 * say (seen in a Debian build of xterm 312-2). This is because
		 * copy-relocated data only requires "uninitialized memory" --
		 * unlike both BSS (where we want fresh-mapped zeroes) and
		 * local rodata or initialized data from the file (where we'd want
		 * to map that data, so by definition wouldn't allocate it where
		 * the memory mapping would be containing random other stuff like
		 * section headers).
		 *
		 * HACK: we allow the first page because being able to map the
		 * ehdr is important.
		 */
		if (phdr->p_type == PT_LOAD &&
			(!(phdr->p_flags & PF_W)
				|| (offset == 0 && length <= MIN_PAGE_SIZE)
			)
		)
		{
			ElfW(Addr) real_end = ROUND_UP(phdr->p_offset + phdr->p_filesz, MIN_PAGE_SIZE);
			if (phdr->p_offset <= (ElfW(Off)) offset &&
					real_end >= offset + length)
			{
				// we can just return the address within that already-mapped phdr
				// (and it doesn't matter whether the phdrs we used to locate it are
				// a "true" phdr mapping or a file I/O copy)
				return (char*) l->l_addr + phdr->p_vaddr +
					(offset - phdr->p_offset);
			}
		}
	}
	/* Without an fd (e.g. for the vdso) we can only return existing mappings. */
	if (fd == -1) return NULL;
	return get_or_map_extra_file_range_fd_no_phdrs(l, extra_mappings, length, fd, offset);
}
static void *get_or_map_extra_file_range_fd_no_phdrs(struct link_map *l, struct extra_mapping (*extra_mappings)[MAPPING_MAX],
		size_t length, int fd, off_t offset)
{
	/* Now we can try making a fresh mapping. But maybe an existing one will do. */
	unsigned midx = 0;
	for (; midx < MAPPING_MAX; ++midx)
	{
		struct extra_mapping *m = &(*extra_mappings)[midx];
		if (!m->mapping_pagealigned)
		{
			// this is a free slot. we fill from index 0 upwards, so no more
			break;
		}
		if (m->mapping_pagealigned
			&& (unsigned long) m->fileoff_pagealigned <= (unsigned long) offset
			&& (unsigned long) m->fileoff_pagealigned + m->size >= (unsigned long) offset + length)
		{
			return m->mapping_pagealigned + (offset - m->fileoff_pagealigned);
		}
	}
	/* OK. We need to create a new extra mapping, unless there's no room... */
	if (midx == MAPPING_MAX) return NULL;
	// tweak our offset/length
	off_t rounded_offset = ROUND_DOWN(offset, MIN_PAGE_SIZE);
	length += offset - rounded_offset;
	length = ROUND_UP(length, MIN_PAGE_SIZE);
	// FIXME: racy
	void *ret = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, rounded_offset);
	if (!MMAP_RETURN_IS_ERROR(ret))
	{
		(*extra_mappings)[midx] = (struct extra_mapping) {
			.mapping_pagealigned = ret,
			.fileoff_pagealigned = rounded_offset,
			.size = length
		};
		return (char*) ret + (offset - rounded_offset);
	}
	return NULL;
}

struct file_metadata *__runt_files_create_metadata(struct link_map *handle, const void *load_site_if_known);

/* IMPORTANT: don't call this directly. We want to be able to wrap it.
 * But we call it from this file; that won't be wrapped unless we
 * ensure it's called on an undefined symbol. So when building a DSO
 * containing this file, we must --defsym __wrap___runt_files_notify_load=__runt_files_notify_load.
 * FIXME: can I use the .gnu.warning magic to generate a warning if this
 * file calls directly to __runt_files_notify_load? Perhaps by setting
 * the asm name of __runt_files_notify_load?
 *
 * TODO: lift out of this a generic visit_elf_metadata (felf.h? lifting any
 * file-level stuff out of relf.h). This would not assume that we have a
 * link map entry... ELF header and program headers initially. Take a
 * callback for get_or_map. */
struct file_metadata *__wrap__runt_files_notify_load(void *handle, const void *load_site);
struct file_metadata *__runt_files_notify_load(void *handle, const void *load_site)
{
	struct link_map *l = (struct link_map *) handle;
	/* Do we already know about this obj?
	 * If so, we might simply be lacking its load_site. */
	struct file_metadata *existing = __wrap___runt_files_metadata_by_addr(l->l_ld);
	if (existing)
	{
		if (load_site && !existing->load_site) existing->load_site = load_site;
		return existing;
	}
	return __runt_files_create_metadata(l, load_site);
}
/* What's the difference between this and notify_load? Only the
 * better name and the fact that notify_load is explicitly supplying
 * the load site, which we do not expect our caller to know. */
struct file_metadata *__runt_files_get_or_create_metadata(struct link_map *l)
{
	/* Do we already know about this obj? */
	struct file_metadata *existing = __wrap___runt_files_metadata_by_addr(l->l_ld);
	if (existing) return existing;
	/* FIXME: this could be racy. */
	return __runt_files_create_metadata(l, /* load_site */ NULL);
}

struct file_metadata *__runt_files_create_metadata(struct link_map *l, const void *load_site_if_known)
{
	const char *tmp = dynobj_name_from_dlpi_name(l->l_name,
		(void*) l->l_addr);
	/* To avoid reentrancy problems when initializing any meta-DSO we may load,
	 * avoid hanging on to the static buffer pointer returned by
	 * dynobj_name_from_dlpi_name... do the strdup here, and we will push
	 * this pointer into the file_metadata struct later, whose deallocator will
	 * free it. */
	const char *dynobj_name = __private_strdup(tmp);
	debug_printf(1, "librunt notified of load of object %s\n", dynobj_name);
	/* FIXME: if we had the original fd that was exec'd or mmap'd, that would be great.
	 * If we were in a libgerald-like ld.so extension context we could do this. *OR*,
	 * in the exec case, very recent glibc ld.so will support AT_EXECFD: see
	 * https://inbox.sourceware.org/libc-alpha/20260715-work-glibc-binfmt_misc-v1-0-b3b14336e664@kernel.org/
	 *
	 * We encapsulate __reopen_file so that clients with particular contextual
	 * requirements can provide their own file opener. liballocs uses this
	 * to do raw_open() not libc open(). libsystrap could do the same, but currently
	 * doesn't. TODO: can we use this to avoid the race condition somehow, at least
	 * in some clients?
	 *
	 * Another way to ensure we could reopen the file is if we could get a file
	 * descriptor onto the file behind any memory mapping. Using /proc/self/map_files,
	 * this is possible. So probably we should use this... if we fail, reopen it racily
	 * but warn. Use a readdir/sscanf loop to match the dirent spanning l_ld (.dynamic). FIXME.
	 */
	int fd = __reopen_file(dynobj_name);
	ElfW(Phdr) *phdrs = NULL;
	ElfW(Ehdr) ehdr; // will be filled only by find_mapped_phdrs
	bzero(&ehdr, sizeof ehdr);
	struct segments sinfo = (struct segments) { .nload = 0 };
	if (fd >= 0)
	{
		phdrs = find_mapped_phdrs(l, fd, &ehdr, &sinfo);
	}
	else
	{
		// warn, at a debug level that depends on whether the path looks sane
		debug_printf((dynobj_name && dynobj_name[0] == '/' ? 0 : 5),
			"could not re-open `%s'\n", l->l_name);
		fd = -1;
		/* We can still work with this, but
		 * - we can't make new mappings
		 * - we can't get hold of phdrs by ourselves -- only dl_iterate_phdr. */
	}
	if (!sinfo.nload) // this is true only if we have no fd (or the file is bad somehow)
	{
		// XXX: is this safe? we are doing it only if we have no fd, but maybe need to be tighter?
		// If librunt is not yet initialized, it may not be safe
		if (__librunt_is_initialized)
		{
			/* We can't read the phdrs by file I/O (no fd), and we
			 * can't read from from the ld.so because the only public API
			 * will crash. What to do? TODO: let's figure out *why* we don't get
			 * the original dl_iterate_phdr. It's in libc!
			 * It seems that RTLD_NEXT is the culprit: first it wants to find
			 * ourselves, but if we're in the trace-syscalls-ld.so (or whatever),
			 * we don't exist yet. OK, worked around in preload.c: look for libc.so.6's handle. */
			dl_for_one_object_phdrs(l, discover_segments_cb, &sinfo);
			assert(sinfo.nload != 0);
			// XXX: if we do call it, can we save the ElfW(Phdr)* pointer it gives us?
			// Yes, I think saving it is fair game. It will only become invalid if
			// the object is unloaded.
			phdrs = (ElfW(Phdr)*) sinfo.phdrs;
		} // otherwise warn
		else debug_printf(0, "no fd for file `%s' and too early to get phdrs via libc\n", l->l_name);
		// TODO: there's one further trick we could use, just in memory.
		// If l_addr is mapped (as it is with the vdso) and begins \x7fELF,
		// try to read the ELF contents directly from memory. We accept this as
		// correct, rather than just coincidental data, only if we reach the PT_DYNAMIC
		// at an address that agrees with l_ld. TODO: how to test whether it's mapped?
		// One approximation is whether it's within the same page as l_ld.
	} // else we will fill in the phdrs below
	// now we can allocate the metadata structure
	/* PROBLEM: clients like liballocs want to extend this structure.
	 * So we should let them.
	 * We've already abstracted the insert and delete functions.
	 * How to abstract allocation? */
	struct file_metadata *meta = __alloc_file_metadata(sinfo.nload);
	assert(meta);
	meta->l = l;
	meta->phnum = sinfo.phnum;
	meta->load_site = load_site_if_known; /* may be null at this stage */
	meta->filename = dynobj_name; // here we take ownership of the name string strdup'd above
	meta->nload = sinfo.nload;
	meta->vaddr_begin = (uintptr_t)-1;
	meta->vaddr_end = 0;
	if (!phdrs && ehdr.e_phoff && fd != -1)
	{
		// spend an extra mapping to map the program headers
		// XXX: could just rely on dl_iterate_phdr as called above, but we know we want to avoid that
		phdrs = get_or_map_extra_file_range_fd_no_phdrs(l, &meta->extra_mappings,
			 ehdr.e_phnum * ehdr.e_phentsize, fd, ehdr.e_phoff);
	}
	meta->phdrs = phdrs;
	//assert(meta->phdrs);
	// we might not have phdrs!

	/* Look up the mapping sequence for this file. Note that
	 * although a file is notionally sparse, modern glibc's ld.so
	 * does ensure that it is spanned by a contiguous sequence of
	 * memory mappings, by first mapping a no-permissions chunk
	 * and then mprotecting various bits. FIXME: what about other
	 * ld.sos which may not do it this way? It would be bad if
	 * files could interleave with one another... we should
	 * probably just not support that case.
	 * SUBTLETY: this contiguous sequence does not start at the
	 * load address -- it starts at the first LOAD's base vaddr.
	 * See the hack in liballocs's mmap.c.
	 *
	 * TODO: instead of relying on dl_iterate_phdr, we may want to
	 * provide our own dl_for_one_object_phdrs (polyfill-style).
	 * That means we need to ensure we have the phdrs ourselves, one way
	 * or another.
	 *
	 * Once we have those, we can provide a phdr iterator and have
	 * discover_segments_cb use that instead.
	 *
	 * Note that to avoid circularities, get_or_map_file_range does not
	 * receive our metadata any more. It receives only phdrs and the extra
	 * mappings array. In future it could proceed using phdrs we have
	 * temporarily snarfed ourselves, by file I/O if necessary, rather than
	 * those exposed by dl_iterate_phdr. We will always try to find the existing
	 * mapping, if it falls within a PT_LOAD; if it doesn't, we will use our
	 * file-I/O'd copy, rather than the ld.so's file-I/O'd copy.
	 */
	if (phdrs) for (int i = 0; i < meta->phnum; ++i)
	{
		if (phdrs[i].p_type == PT_LOAD)
		{
			/* We can round down to int because vaddrs *within* an object 
			 * will not be more than 2^31 from the object base. */
			if (phdrs[i].p_vaddr < meta->vaddr_begin) meta->vaddr_begin = phdrs[i].p_vaddr;
			uintptr_t max_plus_one = phdrs[i].p_vaddr + phdrs[i].p_memsz;
			if (max_plus_one > meta->vaddr_end) meta->vaddr_end = max_plus_one;
		}
	}
	else meta->vaddr_end = -1;
	/* We still haven't filled in everything... */
	__insert_file_metadata(l, meta);
	/* The only semi-portable way to get phdrs is to iterate over
	 * *all* the phdrs. But we only want to process a single file's
	 * phdrs now. Our callback must do the test. We used to call the
	 * callback through dl_for_one_object_phdrs, but we've already got
	 * the phdrs if they can be got, so the "callback" now uses the metadata
	 * directly, which we pass as its void* arg. */
	int dlpi_ret = add_all_loaded_segments_for_one_file_only_cb(NULL, 0, meta);
	assert(dlpi_ret != 0);
	//assert(meta->phdrs);
	/* ^^ commented out because we may not get phdrs in some awkward cases e.g. if file is the vdso. */
	assert(!meta->phnum || meta->phnum != -1);
	/* Now fill in the PT_DYNAMIC stuff. */
	/* Linux's vdso doesn't get its dynstr/dynsym pointers relocated
	 * (i.e. the vdso's load address is not added to them), but other
	 * libs do get this fixup. We can detect and handle this. */
#define MAYBE_FIXUP(addr) \
	(((uintptr_t)(addr) < meta->l->l_addr) ? (meta->l->l_addr + (addr)) : (addr))
	meta->dynsym = (ElfW(Sym) *) MAYBE_FIXUP(dynamic_lookup(meta->l->l_ld, DT_SYMTAB)->d_un.d_ptr); /* always mapped by ld.so */
	meta->dynstr = (unsigned char *) MAYBE_FIXUP(dynamic_lookup(meta->l->l_ld, DT_STRTAB)->d_un.d_ptr); /* always mapped by ld.so */
	meta->dynstr_end = meta->dynstr + dynamic_lookup(meta->l->l_ld, DT_STRSZ)->d_un.d_val; /* always mapped by ld.so */
	/* Now we have the most file metadata we can get without re-mapping extra
	 * parts of the file. */
	meta->ehdr = get_or_map_file_range(l, meta->phdrs, meta->phnum, &meta->extra_mappings, MIN_PAGE_SIZE, fd, 0);
	if (!meta->ehdr) goto out;
	assert(0 == memcmp(meta->ehdr, "\177ELF", 4));
	bzero(meta->build_id, sizeof meta->build_id);
	size_t shdrs_sz = meta->ehdr->e_shnum * meta->ehdr->e_shentsize;
	// assert sanity
#define MAX_SANE_SHDRS_SIZE 512*sizeof(ElfW(Shdr))
	assert(shdrs_sz < MAX_SANE_SHDRS_SIZE);
	meta->shdrs = get_or_map_file_range(l, meta->phdrs, meta->phnum, &meta->extra_mappings, shdrs_sz, fd, meta->ehdr->e_shoff);
	if (meta->shdrs)
	{
#ifndef NDEBUG /* basic sanity checks for an ELF header */
		for (unsigned i = 0; i < meta->ehdr->e_shnum; ++i)
		{
			assert(i == 0 || meta->shdrs[i].sh_offset >= sizeof (ElfW(Ehdr)));
			assert(i == 0 || meta->shdrs[i].sh_size < UINT_MAX);
			assert(meta->shdrs[i].sh_size == 0 || meta->shdrs[i].sh_entsize == 0
				|| meta->shdrs[i].sh_entsize <= meta->shdrs[i].sh_size);
		}
#endif
		for (unsigned i = 0; i < meta->ehdr->e_shnum; ++i)
		{
#define GET_OR_MAP_SCN(__j) get_or_map_file_range(l, meta->phdrs, meta->phnum, &meta->extra_mappings, meta->shdrs[(__j)].sh_size, fd, meta->shdrs[(__j)].sh_offset)
			if (meta->shdrs[i].sh_type == SHT_DYNSYM)
			{
				meta->dynsymndx = i;
				meta->dynstrndx = meta->shdrs[i].sh_link;
			}
			if (meta->shdrs[i].sh_type == SHT_SYMTAB)
			{
				meta->symtabndx = i;
				meta->symtab = GET_OR_MAP_SCN(i);
				meta->strtabndx = meta->shdrs[i].sh_link;
				meta->strtab = GET_OR_MAP_SCN(meta->shdrs[i].sh_link);
			}
			if (i == meta->ehdr->e_shstrndx)
			{
				meta->shstrtab = GET_OR_MAP_SCN(i);
			}
#undef GET_OR_MAP_SCN
		}
		/* Now we have shstrtab if there is one. Re-scan for any section we can
		 * only recognise by name. */
		if (meta->shstrtab)
		{
			for (unsigned i = 0; i < meta->ehdr->e_shnum; ++i)
			{
				if (meta->shdrs[i].sh_type == SHT_NOTE &&
					0 == strcmp(".note.gnu.build-id", (char*) &meta->shstrtab[meta->shdrs[i].sh_name]))
				{
					/* The build ID section begins with 16 bytes of identifier. HACK: just skip
					 * these. We should check they match the GNU marker. FIXME. */
					if (meta->shdrs[i].sh_size < 16 + sizeof meta->build_id)
					{
						debug_printf(0, "Ignoring .note.gnu.build-id in '%s' that is less than the expected size (16 + %d bytes)\n",
							l->l_name, (int) sizeof meta->build_id);
						break;
					}
					ssize_t ret = pread(fd, meta->build_id, sizeof meta->build_id, meta->shdrs[i].sh_offset + 16);
					if (ret != sizeof meta->build_id)
					{
						bzero(meta->build_id, sizeof meta->build_id);
						debug_printf(1, "Failed to read .note.gnu.build-id from '%s'\n", l->l_name);
					}
				}
			}
		}
		else
		{
			debug_printf(1,
				"Warning: no shstrtab in '%s' so we cannot scan for named sections (e.g. .note.gnu.build-id)\n",
				l->l_name);
		}

		/* Now define sections for all the allocated sections in the shdrs
		 * which overlap this phdr. */
		for (ElfW(Shdr) *shdr = meta->shdrs; shdr != meta->shdrs + meta->ehdr->e_shnum; ++shdr)
		{
			if ((shdr->sh_flags & SHF_ALLOC) &&
					shdr->sh_size > 0)
			{
				__runt_sections_notify_define_section(meta, shdr);
			}
		}
		// FIXME: the starts bitmaps need to be attached either to sections or
		// to segments (if we don't have section headers). That's a bit nasty.
		// It probably still works though.
	}
out:
	if (fd >= 0) close(fd);
	return meta;
}
void __runt_deinit_file_metadata(void *fm) __attribute__((visibility("protected")));
void __runt_deinit_file_metadata(void *fm)
{
	struct file_metadata *meta = (struct file_metadata *) fm;
	__private_free((void*) meta->filename);
	for (unsigned i = 0; i < MAPPING_MAX; ++i)
	{
		if (meta->extra_mappings[i].mapping_pagealigned)
		{
			munmap(meta->extra_mappings[i].mapping_pagealigned,
				meta->extra_mappings[i].size);
		}
	}
}

static int discover_segments_cb(struct dl_phdr_info *info, size_t size, void *segments_as_void)
{
	struct segments *out = (struct segments *) segments_as_void;
	out->phnum = info->dlpi_phnum;
	out->phdrs = info->dlpi_phdr;
	unsigned nload = 0;
	for (int i = 0; i < info->dlpi_phnum; ++i)
	{
		if (info->dlpi_phdr[i].p_type == PT_LOAD) ++nload;
	}
	out->nload = nload;
	return 1; // can stop now
}

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info_ignored, size_t size_ignored, void *file_metadata)
{
	/* Produce the sorted symbols vector for this file. 
	 * We do this here because dynsym is shared across the whole file. */
	struct file_metadata *meta = (struct file_metadata *) file_metadata;
	unsigned nload = 0;
	for (unsigned i = 0; i < meta->phnum; ++i)
	{
		// if this phdr's a LOAD
		if (meta->phdrs[i].p_type == PT_LOAD)
		{
			__runt_segments_notify_define_segment(
					meta,
					i,
					nload++
				);
		}
	}
	return 1;
}
/* FIXME: would be better if our dlclose hook gave us more than
 * just a filename. But what can it give us? We only know that
 * the ld.so really does the unload *after* it's happened, when
 * the structures have been removed. There is also a danger of
 * races here. */
void __runt_files_notify_unload(const char *copied_filename)
{
	if (initialized)
	{
		assert(copied_filename);
		for (struct lm_pair *p = &lm_pairs[0]; p < &lm_pairs[npairs]; ++p)
		{
			if (!(p->lm)) break;
			if (0 == strcmp(p->fm->filename, copied_filename))
			{
				__delete_file_metadata(&p->fm);
			}
		}
	}
}

const void *
__runt_find_section_boundary(
	unsigned char *search_addr,
	ElfW(Word) flags,
	_Bool backwards,
	struct file_metadata **out_fm,
	unsigned *out_shndx)
{
	/* Depending on whether backwards is {false,true}
	 * we want to find some section's {base,end} address
	 * that is {geq, leq} the search address
	 * and where that section has all the flags in "flags".
	 * We do this with a linear pass over the section headers.
	 * We cannot assume that they are sorted by address, since
	 * the ELF spec does not require that (as far as I can see).
	 * It doesn't seem worth caching a sorted representation of
	 * the section headers. */
	struct file_metadata *fm = __wrap___runt_files_metadata_by_addr(search_addr);
	if (!fm) return backwards ? NULL : (void*)-1;
	uintptr_t vaddr = (uintptr_t) search_addr - fm->l->l_addr;
	uintptr_t ret = find_section_boundary(vaddr, flags, backwards, fm->shdrs, fm->ehdr->e_shnum,
		out_shndx);
	if (!ret || ret == (uintptr_t)-1) return (void*) ret;
	if (out_fm) *out_fm = fm;
	return (const void*) (fm->l->l_addr + ret);
}
