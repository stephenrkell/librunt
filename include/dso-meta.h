#ifndef LIBRUNT_DSO_META_H_
#define LIBRUNT_DSO_META_H_

#include <sys/time.h>
#include <elf.h>
#include <dlfcn.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <link.h> /* for ElfW() */
#ifdef __cplusplus
}
#endif
#ifdef __cplusplus
#include <cstdbool>
#endif
#include "bitmap.h"
void abort(void) __attribute__((noreturn)); /* keep dependencies down */

union sym_or_reloc_rec;
struct segment_metadata
{
	unsigned phdr_idx;
	union sym_or_reloc_rec *metavector; /* addr-sorted list of relevant dynsym/symtab/extrasym/reloc entries */
	size_t metavector_size;
	bitmap_word_t *starts_bitmap; // maybe!
};

/* Hmm -- with -Wl,-q we might get lots of reloc section mappings. Is this enough? */
/* This is basically our supplement to the stuff we can access
 * from the struct link_map entries in the ld.so. There is some
 * duplication, mainly because we don't want to depend on impl-
 * -specific stuff in there. */
#define MAPPING_MAX 16
struct file_metadata
{
	const char *filename;
	const void *load_site;
	struct link_map *l;

	ElfW(Phdr) *phdrs; /* always mapped or copied by ld.so */
	ElfW(Half) phnum;
	unsigned nload; /* number of segments that are LOADs */
	uintptr_t vaddr_begin; /* the lowest mapped vaddr in the object */
	uintptr_t vaddr_end; /* one past the last mapped vaddr in the object */

	ElfW(Sym) *dynsym; /* always mapped by ld.so */
	unsigned char *dynstr; /* always mapped by ld.so */
	unsigned char *dynstr_end;

	ElfW(Half) dynsymndx; // section header idx of dynsym, or 0 if none such
	ElfW(Half) dynstrndx;

	struct extra_mapping
	{
		void *mapping_pagealigned;
		size_t fileoff_pagealigned; // avoid off_t to be glibc/musl-agnostic
		size_t size;
	} extra_mappings[MAPPING_MAX];

	ElfW(Ehdr) *ehdr;
	ElfW(Shdr) *shdrs;
	unsigned char *shstrtab;
	ElfW(Sym) *symtab; // NOTE this really is symtab, not dynsym
	ElfW(Half) symtabndx;
	unsigned char *strtab; // NOTE this is strtab, not dynstr
	ElfW(Half) strtabndx;

	/* "Starts" are symbols with length (spans).
	   We don't index symbols that are not spans.
	   If we see multiple spans covering the same address, we discard one
	   of them heuristically.
	   The end result is a list of spans, in address order, with distinct starts.
	   Our sorted metavector has one record per indexed span.
	   Logically the content is a pointer to its ELF metadata *and* its type.
	   For spans that are in dynsym, it points to their dynsym entry.
	*/
	struct segment_metadata segments[1];
	/* We would use a variable-length [] array, BUT we want to embed
	 * this struct into another struct (in liballocs), and that doesn't
	 * work because the type becomes incomplete. So use [1]. This is
	 * skirting UB in C, but no worse than struct dirent (? FIXME). */
};
#define FILE_META_DESCRIBES_EXECUTABLE(meta) \
	((meta)->l->l_name && (meta)->l->l_name[0] == '\0') /* FIXME: better test? */
#define STARTS_BITMAP_NWORDS_FOR_PHDR(ph) \
    (ROUND_UP((ph)->p_vaddr + (ph)->p_memsz, sizeof (void*)) - ROUND_DOWN((ph)->p_vaddr, sizeof (void*)) \
    / (sizeof (void*)))
/* Sometimes we will need to get back to containing struct from a
 * file_metadata embedded within. */
#define CONTAINER_OF(ptr, outer_type, member) \
	((outer_type *)(((uintptr_t)(ptr)) - offsetof(outer_type, member)))

void __runt_deinit_file_metadata(void *fm) __attribute__((visibility("protected")));

inline 
ElfW(Sym) *__runt_files_get_symtab_by_idx(struct file_metadata *meta, ElfW(Half) i)
{
	if (meta->symtab && meta->symtabndx == i) return meta->symtab;
	else if (meta->dynsym && meta->dynsymndx == i) return meta->dynsym;
	return NULL;
}


struct file_metadata *__runt_files_notify_load(void *handle, const void *load_site) __attribute__((visibility("protected")));
void __runt_files_notify_unload(const char *copied_filename) __attribute__((visibility("protected")));

const void *
__runt_find_section_boundary(
	unsigned char *search_addr,
	ElfW(Word) flags,
	_Bool backwards,
	struct file_metadata **out_fm,
	unsigned *out_shndx) __attribute__((visibility("protected")));

void __runt_segments_notify_define_segment(
	struct file_metadata *meta,
	unsigned phndx,
	unsigned loadndx
) __attribute__((visibility("protected")));
void __runt_sections_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
) __attribute__((visibility("protected")));

#ifdef _GNU_SOURCE /* We use the GNU C "statement expressions" extension */
/* Macro which open-codes a binary search over a sorted array
 * of T, returning a pointer to the highest element that
 * is greater than or equal to the target. To get an integer
 * value out of a T t, we use proj(t). DO NOT USE 'return' in this macro! */
#define /* T* */  bsearch_leq_generic(T, target_proj_val, /*  T*  */ base, /* unsigned */ n, proj) \
	({ \
		T *upper = base + n; \
		T *lower = base; \
		T *ret = NULL; \
		if (upper - lower == 0) abort(); \
		if (proj(lower) >= target_proj_val) \
		{ \
			while (upper - lower != 1) \
			{ \
				T *mid = lower + ((upper - lower) / 2); \
				if (proj(mid) > target_proj_val) \
				{ \
					/* we should look in the lower half */ \
					upper = mid; \
				} \
				else lower = mid; \
			} \
			assert(proj(lower) <= target_proj_val); \
			/* if we didn't hit the max item, assert the next one is greater */ \
			assert(lower == base + n - 1 \
				 || proj(lower+1) > target_proj_val); \
			/* If all elements are > the target, return NULL */ \
			ret = (proj(lower) <= target_proj_val) ? lower : NULL; \
		} \
		ret; \
	})
#endif

#endif
