#define _GNU_SOURCE
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
#include "librunt_private.h"
int fstat(int fd, struct stat *buf);

/* Used to ensure --wrappability of the relevant symbols.
 * See note on __runt_files_notify_load below. */
struct file_metadata *__wrap___runt_files_notify_load(void *handle, const void *load_site);
struct file_metadata *__wrap___runt_files_metadata_by_addr(void *addr);

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
	if (!p1->lm) /* p1 compares higher */ return 1;
	if (!p2->lm) /* p2 compares higher */ return -1;
	intptr_t addr1 = (intptr_t) p1->lm->l_addr;
	intptr_t addr2 = (intptr_t) p2->lm->l_addr;
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
	if (!initialized) __runt_files_init();
	struct lm_pair *p = lookup_by_addr(addr);
	return p ? p->lm : NULL;
}

static struct file_metadata *metadata_for_addr(void *addr)
{
	struct lm_pair *p = lookup_by_addr(addr);
	return p ? p->fm : NULL;
}
struct file_metadata *(__attribute__((warning("do not call __runt_files_metadata_by_addr from files.c")))
 __runt_files_metadata_by_addr)(void *addr)
{
	if (!initialized) __runt_files_init();
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

struct file_metadata *__runt_files_notify_load(void *handle, const void *load_site);

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

static void *get_or_map_file_range(struct file_metadata *file,
	size_t length, int fd, off_t offset)
{
	/* Check whether we already have this range, either in a LOAD phdr or
	 * in an extra mapping we made earlier. */
	for (unsigned i = 0; i < file->phnum; ++i)
	{
		ElfW(Phdr) *phdr = &file->phdrs[i];
		if (phdr->p_type == PT_LOAD)
		{
			if (phdr->p_offset <= (ElfW(Off)) offset &&
					phdr->p_offset + phdr->p_filesz >= offset + length)
			{
				// we can just return the address within that phdr
				return (char*) file->l->l_addr + phdr->p_vaddr +
					(offset - phdr->p_offset);
			}
		}
	}
	/* Without an fd (e.g. for the vdso) we can only return existing mappings. */
	if (fd == -1) return NULL;
	unsigned midx = 0;
	for (; midx < MAPPING_MAX; ++midx)
	{
		struct extra_mapping *m = &file->extra_mappings[midx];
		if (!m->mapping_pagealigned)
		{
			// this is a free slot. we fill from index 0 upwards, so no more
			break;
		}
		if (m->mapping_pagealigned
			&& m->fileoff_pagealigned <= offset
			&& m->fileoff_pagealigned + m->size >= offset + length)
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
		file->extra_mappings[midx] = (struct extra_mapping) {
			.mapping_pagealigned = ret,
			.fileoff_pagealigned = rounded_offset,
			.size = length
		};
		return (char*) ret + (offset - rounded_offset);
	}
	return NULL;
}

/* IMPORTANT: don't call this directly. We want to be able to wrap it.
 * But we call it from this file; that won't be wrapped unless we
 * ensure it's called on an undefined symbol. So when building a DSO
 * containing this file, we must --defsym __wrap___runt_files_notify_load=__runt_files_notify_load.
 * FIXME: can I use the .gnu.warning magic to generate a warning if this
 * file calls directly to __runt_files_notify_load? */
struct file_metadata *(__attribute__((warning("do not call __runt_files_notify_load from files.c"))) __runt_files_notify_load)
	(void *handle, const void *load_site)
{
	struct link_map *l = (struct link_map *) handle;
	const char *tmp = dynobj_name_from_dlpi_name(l->l_name,
		(void*) l->l_addr);
	/* To avoid reentrancy problems when initializing any meta-DSO we may load,
	 * avoid hanging on to the static buffer pointer returned by
	 * dynobj_name_from_dlpi_namethat... do the strdup here, but we will push
	 * this pointer into the file_metadata struct later, whose deallocator will
	 * free it. */
	const char *dynobj_name = __private_strdup(tmp);
	debug_printf(1, "librunt notified of load of object %s\n", dynobj_name);
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
	 * See the hack in mmap.c. */
	struct segments sinfo = (struct segments) { .nload = 0 };
	dl_for_one_object_phdrs(l, discover_segments_cb, &sinfo);
	assert(sinfo.nload != 0);
	/* PROBLEM: clients like liballocs want to extend this structure.
	 * So we should let them.
	 * We've already abstracted the insert and delete functions.
	 * How to abstract allocation? */
	struct file_metadata *meta = __alloc_file_metadata(sinfo.nload);
	assert(meta);
	meta->load_site = load_site;
	meta->filename = dynobj_name;
	meta->l = l;
	meta->phdrs = (ElfW(Phdr) *) sinfo.phdrs;
	meta->phnum = sinfo.phnum;
	meta->nload = sinfo.nload;
	meta->vaddr_begin = (uintptr_t)-1;
	meta->vaddr_end = 0;
	for (int i = 0; i < meta->phnum; ++i)
	{
		if (sinfo.phdrs[i].p_type == PT_LOAD)
		{
			/* We can round down to int because vaddrs *within* an object 
			 * will not be more than 2^31 from the object base. */
			if (sinfo.phdrs[i].p_vaddr < meta->vaddr_begin) meta->vaddr_begin = sinfo.phdrs[i].p_vaddr;
			uintptr_t max_plus_one = sinfo.phdrs[i].p_vaddr + sinfo.phdrs[i].p_memsz;
			if (max_plus_one > meta->vaddr_end) meta->vaddr_end = max_plus_one;
		}
	}
	/* We still haven't filled in everything... */
	__insert_file_metadata(l, meta);
	/* The only semi-portable way to get phdrs is to iterate over
	 * *all* the phdrs. But we only want to process a single file's
	 * phdrs now. Our callback must do the test. */
	int dlpi_ret = dl_for_one_object_phdrs(l, add_all_loaded_segments_for_one_file_only_cb, meta);
	assert(dlpi_ret != 0);
	assert(meta->phdrs);
	assert(meta->phnum && meta->phnum != -1);
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
	/* FIXME: we'd much rather not do open() on l->l_name (race condition) --
	 * if we had the original fd that was exec'd, that would be great. If we
	 * were in a libgerald- */
	int fd = __reopen_file(meta->filename);
	if (fd < 0)
	{
		// warn, at a debug level that depends on whether the path looks sane
		debug_printf((meta->filename && meta->filename[0] == '/' ? 0 : 5),
			"could not re-open `%s'\n", l->l_name);
		fd = -1; /* We can still work with this, just not make new mappings. */
	}
	meta->ehdr = get_or_map_file_range(meta, MIN_PAGE_SIZE, fd, 0);
	if (!meta->ehdr) goto out;
	assert(0 == memcmp(meta->ehdr, "\177ELF", 4));
	size_t shdrs_sz = meta->ehdr->e_shnum * meta->ehdr->e_shentsize;
	// assert sanity
#define MAX_SANE_SHDRS_SIZE 512*sizeof(ElfW(Shdr))
	assert(shdrs_sz < MAX_SANE_SHDRS_SIZE);
	meta->shdrs = get_or_map_file_range(meta, shdrs_sz, fd, meta->ehdr->e_shoff);
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
#define GET_OR_MAP_SCN(__j) get_or_map_file_range(meta, meta->shdrs[(__j)].sh_size, fd, meta->shdrs[(__j)].sh_offset)
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
	out:
		if (fd >= 0) close(fd);
	}
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

static int add_all_loaded_segments_for_one_file_only_cb(struct dl_phdr_info *info, size_t size, void *file_metadata)
{
	/* Produce the sorted symbols vector for this file. 
	 * We do this here because dynsym is shared across the whole file. */
	struct file_metadata *meta = (struct file_metadata *) file_metadata;
	unsigned nload = 0;
	for (unsigned i = 0; i < info->dlpi_phnum; ++i)
	{
		// if this phdr's a LOAD
		if (info->dlpi_phdr[i].p_type == PT_LOAD)
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
	ElfW(Shdr) *best = NULL;
	ptrdiff_t best_diff = PTRDIFF_MAX;
	for (ElfW(Shdr) *cur = fm->shdrs;
			cur != fm->shdrs + fm->ehdr->e_shnum;
			++cur)
	{
		// is cur closer than 'best'?
		if (!(cur->sh_flags & flags)) continue;
		// the forward or backward distance from search_addr to cur's boundary
		ptrdiff_t cur_diff = 
			backwards ? (intptr_t) vaddr - (cur->sh_addr + cur->sh_size)
			          : (intptr_t) cur->sh_addr - vaddr;
		// if the diff is <0, it means we're on the wrong side of the boundary
		if (cur_diff < 0) continue;
		// i.e. we want the smallest positive distance
		if (cur_diff < best_diff)
		{ best = cur; best_diff = cur_diff; continue; }
	}
	if (!best) return backwards ? NULL : (void*)-1;
	if (out_fm) *out_fm = fm;
	if (out_shndx) *out_shndx = (best - fm->shdrs);
	return (const void*) (fm->l->l_addr +
		(backwards ? (best->sh_addr + best->sh_size) : best->sh_addr));
}
