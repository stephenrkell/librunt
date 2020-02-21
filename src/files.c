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

/* This file's logic really belongs in the dynamic linker.
 * It is responding to load and unload events.
 * Also, it'd be great if we could keep a file descriptor on
 * all the files we loaded -- rather than having to look them up again
 * by name.
 * We also want phdr, ehdr and shdr access. */

static _Bool trying_to_initialize;
static _Bool initialized;

// we define this a bit closer to the allocating code, but declare it now
static void free_file_metadata(void *fm);

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
static void insert_pair(struct link_map *lm, struct file_metadata *fm)
{
	BIG_LOCK
	lm_pairs[npairs++] = (struct lm_pair) { .lm = lm, .fm = fm };
	qsort(lm_pairs, npairs, sizeof lm_pairs[0], compare_lm_pair_by_load_addr);
	BIG_UNLOCK
}
static void delete_pair(struct lm_pair **p)
{
	free_file_metadata((*p)->fm);
	BIG_LOCK
	*p = NULL;
	qsort(lm_pairs, npairs, sizeof lm_pairs[0], compare_lm_pair_by_load_addr);
	--npairs;
	BIG_UNLOCK
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
struct file_metadata *__runt_files_metadata_by_addr(void *addr)
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

void __runt_files_notify_load(void *handle, const void *load_site);

void __runt_files_init(void) __attribute__((constructor(102)));
void __runt_files_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
#if 0
		/* Initialize what we depend on. */
		__mmap_allocator_init();
#endif
		__runt_auxv_init();
		/* FIXME: arguably, for dynamically linked programs, the allocation
		 * site of these is somewhere inside the dynamic linker. E.g.
		 * if the linker was run by the kernel's loader (and not by directly
		 * running the linker on the command line, e.g.
		 * /path/to/ld.so /path/to/executable) it should be _dl_start, else
		 * it should be wherever in the dynamic linker did the load. We can
		 * distinguish all these cases, and should do.... */
#if 1
		const void *program_entry_point = __runt_auxv_get_program_entry_point();
#else
		char dummy;
		ElfW(auxv_t) *auxv = get_auxv(environ, &dummy);
		assert(auxv);
		ElfW(auxv_t) *entry_auxv = auxv_lookup(auxv, AT_ENTRY);
		const void *program_entry_point = (const void *) entry_auxv->a_un.a_val;
#endif

		/* We probably don't need to iterate over all DSOs -- those that have been
		 * dlopened by us since execution started (e.g. the dlbind lib)
		 * were already notified/added earlier. So we only iterate
		 * over those we snapshotted. But if we *haven't* run dlopen
		 * at all yet, just iterate over everything. */
		if (early_lib_handles[0])
		{
			for (unsigned i = 0; i < MAX_EARLY_LIBS; ++i)
			{
				if (!early_lib_handles[i]) break;
				__runt_files_notify_load(early_lib_handles[i],
					program_entry_point);
			}
		}
		else
		{
			for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
			{
				__runt_files_notify_load(l, program_entry_point);
			}
		}
		/* For all loaded objects... */
		if (__librunt_debug_level >= 10)
		{
			for (struct link_map *l = _r_debug.r_map; l; l = l->l_next)
			{
				/* l_addr isn't guaranteed to be mapped, so use _DYNAMIC a.k.a. l_ld'*/
				void *query_addr = l->l_ld;
#if 0
				struct big_allocation *containing_mapping =__lookup_bigalloc_top_level(query_addr);
				struct big_allocation *containing_file = __lookup_bigalloc_under(
					query_addr, &__static_file_allocator, containing_mapping, NULL);
				assert(containing_file);
#endif
				struct file_metadata *file = 
#if 0
						containing_file->meta.un.opaque_data.data_ptr;	
#else
					metadata_for_addr((void*) l->l_addr);
#endif
				for (unsigned i_seg = 0; i_seg < file->nload; ++i_seg)
				{
					union sym_or_reloc_rec *metavector = file->segments[i_seg].metavector;
					size_t metavector_size = file->segments[i_seg].metavector_size;
#if 0
					// we print the whole metavector
					for (unsigned i = 0; i < metavector_size / sizeof *metavector; ++i)
					{
						fprintf(stream_err, "At %016lx there is a static alloc of kind %u, idx %08u, type %s\n",
							file->l->l_addr + vaddr_from_rec(&metavector[i], file),
							(unsigned) (metavector[i].is_reloc ? REC_RELOC : metavector[i].sym.kind),
							(unsigned) (metavector[i].is_reloc ? 0 : metavector[i].sym.idx),
							UNIQTYPE_NAME(
								metavector[i].is_reloc ? NULL :
								(struct uniqtype *)(((uintptr_t) metavector[i].sym.uniqtype_ptr_bits_no_lowbits)<<3)
							)
						);
					}
#endif
				}
			}
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

void __runt_files_notify_load(void *handle, const void *load_site)
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
	debug_printf(1, "notified of load of object %s\n", dynobj_name);
#if 0
	/* Load the separate meta-object for this object. */
	void *meta_obj_handle = NULL;
	int ret_meta = dl_for_one_object_phdrs(handle,
		load_and_init_all_metadata_for_one_object, &meta_obj_handle);
#endif
	// meta_obj_handle may be null -- we continue either way
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
#if 0
	struct big_allocation *lowest_containing_mapping_bigalloc = NULL;
	struct mapping_entry *m = __liballocs_get_memory_mapping(
		(void*) (l->l_addr + bounds.lowest_mapped_vaddr),
		&lowest_containing_mapping_bigalloc);
	struct big_allocation *highest_containing_mapping_bigalloc = NULL;
	m = __liballocs_get_memory_mapping(
		(void*) (l->l_addr + bounds.limit_vaddr - 1),
		&highest_containing_mapping_bigalloc);
	/* We should have seen the mmap that created the bigalloc. If we haven't,
	 * it probably means that we haven't turned on systrapping yet. That's
	 * a logic error in liballocs; we should have done that by now. */
	if (!lowest_containing_mapping_bigalloc) abort();
	if (!highest_containing_mapping_bigalloc) abort();
	if (highest_containing_mapping_bigalloc != lowest_containing_mapping_bigalloc) abort();
	struct big_allocation *containing_mapping_bigalloc = lowest_containing_mapping_bigalloc;
	size_t file_bigalloc_size = (uintptr_t)((char*) l->l_addr + bounds.limit_vaddr)
		- (uintptr_t) lowest_containing_mapping_bigalloc->begin;
#endif
	struct segments sinfo = (struct segments) { .nload = 0 };
	dl_for_one_object_phdrs(l, discover_segments_cb, &sinfo);
	assert(sinfo.nload != 0);
	size_t meta_sz = offsetof(struct file_metadata, segments)
		+ sinfo.nload * sizeof (struct segment_metadata);
	struct file_metadata *meta = __private_malloc(meta_sz);
	if (!meta) abort();
	bzero(meta, meta_sz);
	meta->load_site = load_site;
	meta->filename = dynobj_name;
	meta->l = l;
#if 0
	meta->meta_obj_handle = meta_obj_handle;
	meta->extrasym = (meta_obj_handle ? dlsym(meta_obj_handle, "extrasym") : NULL);
#endif
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
	insert_pair(l, meta);
#if 0
	/* We want to create a single "big allocation" for the whole file. 
	 * However, that's a problem ta least in the case of executables
	 * mapped by the kernel: there isn't a single mapping sequence. We
	 * fixed that in allocators/mmap.c: if we detect a hole, we map
	 * it PROT_NONE, and ensure the rules on extending mapping_sequences
	 * will swallow this into the same sequence. */
	struct big_allocation *b = __liballocs_new_bigalloc(
		(void*) lowest_containing_mapping_bigalloc->begin, // the file begins at a page boundary
		file_bigalloc_size,
		(struct meta_info) {
			.what = DATA_PTR,
			.un = {
				opaque_data: { 
					.data_ptr = (void*) meta,
					.free_func = &free_file_metadata
				}
			}
		},
		containing_mapping_bigalloc,
		&__static_file_allocator
	);
	b->suballocator = &__static_segment_allocator;
	char dummy;
	ElfW(auxv_t) *auxv = get_auxv(environ, &dummy);
	assert(auxv);
	ElfW(auxv_t) *ph_auxv = auxv_lookup(auxv, AT_PHDR);
	if (FILE_META_DESCRIBES_EXECUTABLE(meta))
	{
		assert(!executable_file_bigalloc);
		executable_file_bigalloc = b;
	}
#endif
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
	 * if we had the original fd that was exec'd, that would be great. */
#if 0
	int fd = raw_open(meta->filename, O_RDONLY);
#endif
	int fd = open(meta->filename, O_RDONLY);
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
#if 0
	init_allocsites_info(meta);
	init_frames_info(meta);
#endif
}
static void free_file_metadata(void *fm)
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
	__private_free(meta);
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

void __runt_files_notify_unload(const char *copied_filename)
{
	if (initialized)
	{
		assert(copied_filename);
#if 0
		/* For all big allocations, if we're the allocator and the filename matches, 
		 * delete them. */
		for (struct big_allocation *b = &big_allocations[0]; b != &big_allocations[NBIGALLOCS]; ++b)
		{
			if (BIGALLOC_IN_USE(b) && b->allocated_by == &__static_file_allocator)
			{
				struct file_metadata *meta = (struct file_metadata *) b->meta.un.opaque_data.data_ptr;
				if (0 == strcmp(copied_filename, meta->filename))
				{
					/* unload meta-object */
					dlclose(meta->meta_obj_handle);
					/* It's a match, so delete. FIXME: don't match by name (fragile);
					 * load addr is better */
					__liballocs_delete_bigalloc_at(b->begin, &__static_file_allocator);
				}
			}
		}
#else
		// FIXME: free the file metadata
#endif
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
	struct file_metadata *fm = __runt_files_metadata_by_addr(search_addr);
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
