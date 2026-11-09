#ifndef RELF_H_
#define RELF_H_

#include <felf.h> /* file-level helpers, not reflective / dynamic-linking helpers */

#ifdef __cplusplus
extern "C" {
#endif

#include "elfw.h"
#include "vas.h"

size_t strlen(const char *s); /* avoid string.h */

#ifdef __FreeBSD__
/* FreeBSD is POSIXly-correct by avoiding the typename "auxv_t". 
 * For now, we hack around this, but we should really follow its
 * lead. */
typedef Elf32_Auxinfo Elf32_auxv_t;
typedef Elf64_Auxinfo Elf64_auxv_t;
#endif

/* #include <link.h> -- we don't do this because it can pollute us with libc stuff
 * when clients (like trap-syscalls) want to use us in sub-libc (asm-level) code. 
 * Use RELF_DEFINE_STRUCTURES instead. */

#undef strncmp
int strncmp(const char *s1, const char *s2, size_t n);
#undef strcmp
int strcmp(const char *s1, const char *s2);

extern char **environ;
/* avoid stdlib.h */
extern void abort(void) __attribute__((noreturn));
void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));


/* some stdio.h-avoidance */
struct _IO_FILE;
int fprintf(struct _IO_FILE * restrict,  const char * restrict, ...);
int fflush(struct _IO_FILE *);
#ifndef stderr  /* guard against musl's #definition of stderr */
extern struct _IO_FILE *const stderr;
#endif

/* 

ELF introspection routines.

Some properties:

- do not use libdl/ldso calls likely to do allocation or syscalls (dlopen, dlsym)
- hence safe to use from a no-syscalls-please context (e.g. syscall emulator, allocator instrumentation)

BARELY POSSIBLE without syscalls, libdl/allocation: or nonportable logic
- get auxv
=> get phdrs
... we use a hacky "likely to work, vaguely portable" method to get auxv

*/


#ifndef LINK_MAP_STRUCT_TAG
#define LINK_MAP_STRUCT_TAG link_map
#endif

#ifndef R_DEBUG_STRUCT_TAG
#define R_DEBUG_STRUCT_TAG r_debug
#endif

#ifndef R_DEBUG_MAKE_ENUMERATOR
#define R_DEBUG_MAKE_ENUMERATOR(p) p
#endif

#include "bsearch.h" /* used in get_auxv_limits */

/* To add saturatingwise, we add the smaller of
 * (the-other-arg, dist-to-the-max). We can use vas.h's
 * MINPTR/MAXPTR here because they are defined on uintptr_t. */
#define RELF_ADD_SATURATING(x, y, max) \
  ((x) + MINPTR( (max)-(x), (y) ))

/* This is a giant HACK that is needed only because we might be reading
 * _DYNAMIC entries before or after they get relocated by ADJUST_DYN_INFO.
 * We relocate if we see 'x' less than their maximum vaddr (i.e. the limit
 * of the intra-DSO address space... NOT the DSO's limit in the overall
 * address space).
 * 
 * This logic only works on objects whose load address (high_base_addr)
 * is greater than their maximum vaddr, i.e. the unrelocated vaddr passed
 * as 'x'. If 'x' is greater than the base addr, we won't relocate. This
 * is usually correct, but BEWARE... e.g. if low load addrs are in use.
 *
 * Back in 32-bit-land, we have a problem. If we approximate limit_vaddr
 * to 4GB, we will relocate unconditionally. We can tweak the size down
 * to 1GB, say, but it doesn't really help. What we want is a cheap way
 * to guesstimate the maximum vaddr for a given object. Getting the phdrs
 * is not always easy. Or isn't it? In librunt I think we have them. So
 * it's just in this header, that is supposed to be standalone, where
 * we have a problem.
 */
#define RELF_MAYBE_ADJUST3(x, high_base_addr, limit_vaddr) ( \
   ( ((uintptr_t)(x)) < ((uintptr_t)(limit_vaddr)) ) \
        ? (((uintptr_t)(x)) + ((uintptr_t)(high_base_addr))) \
        : (x) \
 )

#define RELF_MAYBE_ADJUST(x, high_base_addr) \
   (RELF_MAYBE_ADJUST3(x, high_base_addr, BIGGEST_SANE_DSO_VADDR))

#ifdef RELF_DEFINE_STRUCTURES
struct LINK_MAP_STRUCT_TAG
{
	ElfW(Addr) l_addr;
	char *l_name;
	ElfW(Dyn) *l_ld;
	struct LINK_MAP_STRUCT_TAG *l_next;
	struct LINK_MAP_STRUCT_TAG *l_prev;
};
struct R_DEBUG_STRUCT_TAG
{
	int r_version;

	struct LINK_MAP_STRUCT_TAG *r_map;
	ElfW(Addr) r_brk;
	enum {
		R_DEBUG_MAKE_ENUMERATOR(RT_CONSISTENT),
		R_DEBUG_MAKE_ENUMERATOR(RT_ADD),
		R_DEBUG_MAKE_ENUMERATOR(RT_DELETE)
	} r_state;
	ElfW(Addr) r_ldbase;
};

#endif

#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT ((void*)0) /* HACK: GNU-specific? */
#endif
#ifndef RTLD_NEXT
#define RTLD_NEXT ((void*)-1) /* HACK: GNU-specific? */
#endif

extern ElfW(Dyn) _DYNAMIC[] __attribute__((weak));
extern int _fini __attribute__((weak));
extern int _init __attribute__((weak));
extern struct R_DEBUG_STRUCT_TAG _r_debug __attribute__((weak));

static inline
struct LINK_MAP_STRUCT_TAG*
get_lowest_loaded_object_above(void *ptr);
static inline
ElfW(Sym) *get_dynsym(struct LINK_MAP_STRUCT_TAG *l);
static inline
ElfW(Word) *get_gnu_hash(struct LINK_MAP_STRUCT_TAG *l);
static inline
ElfW(Word) *get_sysv_hash(struct LINK_MAP_STRUCT_TAG *l);
static inline
unsigned char *get_dynstr(struct LINK_MAP_STRUCT_TAG *l);


#ifndef ALIGNOF
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define ALIGNOF _Alignof
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define ALIGNOF alignof
#else
#define ALIGNOF(t) offsetof (struct { char c; t memb; }, memb)
#endif
#endif

/* Although we have no intention of modifying the strings in 'environ',
 * declaring it 'const' causes too many headaches, because char**
 * cannot be implicitly converted to 'const char **'. */
static inline
ElfW(auxv_t) *get_auxv_via_environ(char **environ, void *stackptr, void *stack_upper_bound)
{
	/* This somewhat unsound but vaguely portable mechanism for getting auxv
	 * works as follows.
	 * 
	 * - The caller supplies a pointer to an environment table. 
	 *   It is important that at least one environment variable in this
	 *   array comes from the actual auxv, rather than being modified.
	 *   So, e.g. a process which empties out its environment on startup
	 *   would not be able to find the auxv this way after doing the emptying.
	 * 
	 * - The caller also supplies a pointer to the initial stack.
	 *   any environment pointer which is *greater* than this value
	 *   will be treated as a pointer into the auxv env, and used
	 *   as a basis for search. For sanity, we check for any loaded object
	 *   at a *higher* base address (sometimes the vdso gets loaded here),
	 *   and use its load address as an upper bound
	 */

	for (char **p_str = &environ[0]; *p_str; ++p_str)
	{
		if (*p_str > (const char*) stackptr && *p_str < (const char *) stack_upper_bound)
		{
			uintptr_t search_addr = (uintptr_t) *p_str;
			/* We're pointing at chars in an asciiz blob high on the stack. 
			 * The auxv is somewhere below us. */
			 
			/* 1. Down-align our pointer to alignof auxv_t. */
			search_addr &= ~(ALIGNOF(ElfW(auxv_t)) - 1);
			
			/* 2. Search *downwards* for a full auxv_t's worth of zeroes
			 * s.t. the next-lower word is a non-zero blob of the same size. 
			 * This is the AT_NULL record; we shouldn't have such a blob
			 * of zeroes elsewhere in this region, because even if we have
			 * 16 bytes of padding between asciiz and auxv, that will only
			 * account for one auxv_t's blob. We assume that what padding
			 * there is is all zeroes, and that asciiz data does not contain 
			 * all-zero chunks.
			 * 
			 * NOTE: not portable to (hypothetical) platforms where AT_NULL 
			 * has a nonzero (but ignored) a_val.
			 */
			
#ifndef AT_MAX
#define AT_MAX 0x1000
#endif
			ElfW(auxv_t) *searchp = (ElfW(auxv_t) *) search_addr;
			#define IS_AT_NULL(p) ((p)->a_type == AT_NULL && (p)->a_un.a_val == 0)
			#define IS_PLAUSIBLE_NONNULL_AT(p) \
				((p)->a_type != AT_NULL && (p)->a_type < AT_MAX)
			/* NOTE: we decrement searchp by _Alignof (auxv_t), *not* its size. */
			#define NEXT_SEARCHP(p) ((ElfW(auxv_t) *) ((uintptr_t) (p) - ALIGNOF(ElfW(auxv_t))))
			/* PROBLEM: we might be seeing a misaligned view: the last word
			 * of AT_NULL, then some padding (zeroes); the searchp-1 will also
			 * be a misaligned view of auxv that easily passes the not-AT_NULL check.
			 * This means we've exited the loop too eagerly! We need to go as far as 
			 * we can, i.e. get the *last* plausible location (this is more robust
			 * than it sounds :-). 
			 * 
			 * OH, but we might *still* be seeing a misaligned view: if the previous
			 * auxv record has a zero a_val, then we'll go back one too far.
			 * So add in the plausibility condition: the a_type field should
			 * be nonzero and less than AT_MAX (HACK: which we make a guess at). */
			while (!(
					    (IS_AT_NULL(searchp)               && IS_PLAUSIBLE_NONNULL_AT(searchp - 1))
					&& !(IS_AT_NULL(NEXT_SEARCHP(searchp)) && IS_PLAUSIBLE_NONNULL_AT(NEXT_SEARCHP(searchp) - 1))
			))
			{
				searchp = NEXT_SEARCHP(searchp);
			}
			#undef IS_AT_NULL
			#undef NEXT_SEARCHP
			ElfW(auxv_t) *at_null = searchp;
			if (!(at_null->a_type == AT_NULL && !at_null->a_un.a_val)) __assert_fail("found end of auxv", __FILE__, __LINE__, __func__);
			
			/* Search downwards for the beginning of the auxv. How can we
			 * recognise this? It's preceded by the envp's terminating zero word. 
			 * BUT CARE: some auxv entries are zero words! 
			 * How can we distinguish this? Immediately below
			 * auxv is envp, which ends with a NULL word preceded by some 
			 * pointer. All pointer values are higher than auxv tag values! so
			 * we can use that (NASTY HACK) to identify it. 
			 * 
			 * In the very unlikely case that the envp is empty, we will see 
			 * another NULL instead of a pointer. So we can handle that too. */
			ElfW(auxv_t) *at_search = at_null;
			while (!(
					((void**) at_search)[-1] == NULL
				&&  (
						((void**) at_search)[-2] > (void*) AT_MAX
					||  ((void**) at_search)[-2] == NULL
					)
				))
			{
				--at_search;
			}
			/* Now at_search points to the first word after envp's null terminator, i.e. auxv[0]! */
			ElfW(auxv_t) *auxv = at_search;
			return auxv;
		}
	}
	
	return NULL;
}

static inline
ElfW(auxv_t) *auxv_lookup(ElfW(auxv_t) *a, ElfW(Addr) tag)
{
	for (ElfW(auxv_t) *aux = a; aux->a_type != AT_NULL; ++aux)
	{
		if (aux->a_type == tag)
		{
			return aux;
		}
	}
	return NULL;
}

static inline
ElfW(auxv_t) *get_auxv(char **environ, void *stackptr)
{
	struct LINK_MAP_STRUCT_TAG *found = get_lowest_loaded_object_above(stackptr);
	void *stack_upper_bound;
	if (found) stack_upper_bound = (void*) found->l_addr;
	else stack_upper_bound = (void*) -1;
	return get_auxv_via_environ(environ, stackptr, stack_upper_bound);
}

extern void *__libc_stack_end __attribute__((weak));
static inline
ElfW(auxv_t) *get_auxv_via_libc_stack_end(void)
{
	/* __libc_stack_end, if defined, should hold the address
	 * of argc on the initial stack. This is a GNUism. */
	if (!&__libc_stack_end || !__libc_stack_end) return NULL;
	uintptr_t *pos = (uintptr_t *) __libc_stack_end;
	unsigned long nargs = *pos;
	if (!(nargs > 0)) __assert_fail("nargs check", __FILE__, __LINE__, __func__);

	++pos;
	for (unsigned i = 0; i < nargs; ++i) ++pos;
	if (!(!*pos)) __assert_fail("null terminator at the end of argv", __FILE__, __LINE__, __func__);
	while (!*pos) ++pos;
	while (*pos) ++pos; // envp vector
	while (!*pos) ++pos;
	ElfW(auxv_t) *auxv = (ElfW(auxv_t) *) pos;
	if (!(auxv->a_type <= AT_MAX)) __assert_fail("a_type below AT_MAX", __FILE__, __LINE__, __func__);
	return auxv;
}

static inline
ElfW(auxv_t) *auxv_xlookup(ElfW(auxv_t) *a, ElfW(Addr) tag)
{
	ElfW(auxv_t) *found = auxv_lookup(a, tag);
	if (!found) __assert_fail("found expected auxv tag", __FILE__, __LINE__, __func__);
	return found;
}

// this mirrors the order of content in the auxv
enum auxv_component { AUXV_ARGCOUNT, AUXV_ARG_VECTOR, AUXV_ENV_VECTOR, AUXV_AUX_VECTOR, AUXV_ASCIIZ };

struct auxv_limits
{
	ElfW(auxv_t) *aux_vector_start;
	ElfW(auxv_t) *aux_vector_terminator;
	const char **env_vector_start;
	const char **env_vector_terminator;
	const char **arg_vector_start;
	const char **arg_vector_terminator;
	const char *asciiz_start;
	const char *asciiz_end;
	intptr_t *p_argcount;
};

/* used with qsort in get_auxv_limits */
static inline int compare_unsigned_long(const void *p1_as_void, const void *p2_as_void)
{
	unsigned long *p1 = (unsigned long *) p1_as_void;
	unsigned long *p2 = (unsigned long *) p2_as_void;
	return (*p1 < *p2) ? -1 : (*p1 == *p2) ? 0 : 1;
}
#define auxv_ptr_tags(v) \
 v(AT_PHDR) \
 v(AT_BASE) \
 v(AT_ENTRY) \
 v(AT_PLATFORM) \
 v(AT_BASE_PLATFORM) \
 v(AT_RANDOM) \
 v(AT_EXECFN) \
 v(AT_SYSINFO)
#define auxv_string_tags(v) \
 v(AT_PLATFORM) \
 v(AT_BASE_PLATFORM) \
 v(AT_EXECFN) \
 v(AT_RANDOM) /* not ASCII data, but Linux puts it among the asciiz */

static inline
struct auxv_limits get_auxv_limits(ElfW(auxv_t) *aux_vector_start)
{
#ifdef __cplusplus
	struct auxv_limits lims = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };
#else
	struct auxv_limits lims = { .aux_vector_terminator = NULL };
#endif
	const char *lowest_asciiz_seen = (const char*) -1; // dummy initial value
	/* As we visit string pointers that might point into the asciiz area,
	 * we keep track of the range of addresses seen, to get the bounds of
	 * the asciiz block. PROBLEM: if anyone has done surgery
	 * on these vectors since startup, there could be pointers pointing elsewhere,
	 * which will confuse us.
	 *
	 * Can we detect these? The "real" asciiz area is definitely above the auxv itself.
	 * For now we are asking the caller for an upper bound, but how will it know what
	 * to say? A better idea would be to track the contiguous run of pages, starting
	 * with PAGENUM(p_auxv). If we see a discontinuity in page numbers, we assume that
	 * the strings beyond the discontinuity are "non-local" i.e. don't belong to this
	 * asciiz block.
	 *
	 * If we were liballocs, we could do better because we could probe an arbitrary
	 * page for emptiness-or-otherwise. I think this will do for now though.
	 *
	 * We need to collect a set of pagenums as we go. A subtlety: we don't want only to
	 * heed the start address of each string pointer, but also the pages it passes over
	 * i.e. in [str, str + strlen(str) + 1[. That means the upper bound for the size of
	 * this set is the length of referenced string data (in pages, rounded up).
	 *
	 * To avoid a malloc/realloc loop, we count an upper bound of the number of distinct
	 * pages, in one pass -- a string of NBYTES touches at most 1 + ROUND_UP(NBYTES/PAGE_SIZE) pages.
	 * Then alloca some space for the set, which we build in another pass. Finally we look
	 * for the longest contiguous run starting from EITHER PAGENUM(end-of-vectors) OR
	 * PAGENUM(end-of-vectors-rounded up by 16 bytes)  -- corner cases ahoy.
	 */
	unsigned max_distinct_pages = 0;
	lims.aux_vector_start = aux_vector_start;
	lims.aux_vector_terminator = aux_vector_start;
	while (lims.aux_vector_terminator->a_type != AT_NULL) ++lims.aux_vector_terminator;

	/* aux_vector_start[0] is the first word higher than envp's null terminator. */
	lims.env_vector_terminator = ((const char**) aux_vector_start) - 1;
	/* In some strange cases we get multiple words of zero terminator. */
	while (!*((char**) lims.env_vector_terminator - 1)) --lims.env_vector_terminator;
	/* Now the terminator is as low as it can go. If it's not null, it means we
	 * didn't go around the loop above even once, meaning aux_vector_start - 1 was
	 * non-null to begin with. */
	if (!(!*lims.env_vector_terminator)) __assert_fail("found envp terminator", __FILE__, __LINE__, __func__);
	lims.env_vector_start = lims.env_vector_terminator;
	while (*((char**) lims.env_vector_start - 1)) --lims.env_vector_start;

	/* arg_vector_terminator is the next word lower than envp's first entry. */
	lims.arg_vector_terminator = ((const char**) lims.env_vector_start) - 1;
	if (!(!*lims.arg_vector_terminator)) __assert_fail("found argv terminator", __FILE__, __LINE__, __func__);
	lims.arg_vector_start = lims.arg_vector_terminator;
	unsigned nargs = 0;
	/* To search for the start of the array, we look for an integer that is
	 * a plausible argument count... which won't look like any pointer we're seeing. */
	#define MAX_POSSIBLE_ARGS 4194304
	while (*((uintptr_t*) lims.arg_vector_start - 1) > MAX_POSSIBLE_ARGS)
	{
		--lims.arg_vector_start;
		++nargs;
	}
	if (!(*((uintptr_t*) lims.arg_vector_start - 1) == nargs)) __assert_fail("argv vector length match", __FILE__, __LINE__, __func__);
	lims.p_argcount = (intptr_t*) lims.arg_vector_start - 1; // libcrunch-unfriendly cast, just FYI

#define expand_auxv_string_tags(tag) || p->a_type == tag
	/* Now we have the arg vectors and env vectors, loop through them
	 * to get the highest char pointer we see  */
#define VISIT_ALL_STRINGS(action) do { \
	for (const char **p = lims.arg_vector_start; p != lims.arg_vector_terminator; ++p) \
	{ \
		action(*p); \
	} \
	for (const char **p = lims.env_vector_start; p != lims.env_vector_terminator; ++p) \
	{ \
		action(*p); \
	} \
	for (ElfW(auxv_t) *p = aux_vector_start; p != lims.aux_vector_terminator; ++p) \
	{ \
		/* Check for AT_RANDOM, AT_PLATFORM and anything else that might */ \
		/* be pointing at data in the vague asciiz area, so we can remember the */ \
		/* highest address. */ \
		if (0 auxv_string_tags(expand_auxv_string_tags)) \
		{ \
			action((char*) p->a_un.a_val); \
		} \
	} } while(0)
#define SEEN_POSSIBLE_ASCIIZ_POINTER(p) do { \
    if ((uintptr_t) (p) > (uintptr_t) (lims.env_vector_terminator + 1)) { \
      if ((uintptr_t) (p) < (uintptr_t) lowest_asciiz_seen) { \
        lowest_asciiz_seen = (char*) (p); \
      } \
      max_distinct_pages += (1 + \
        (((uintptr_t) ROUND_UP_PTR_TO_PAGE(strlen((char*)(p)) + 1)) >> LOG_MIN_PAGE_SIZE) \
      ); \
    } \
  } while (0)
	VISIT_ALL_STRINGS(SEEN_POSSIBLE_ASCIIZ_POINTER);
	/* Now we've done a pass over all strings. We have an upper bound on how many
	 * distinct page numbers might be touched. But we need to do a pass again, unfortunately. */
	assert(max_distinct_pages > 0);
	unsigned long asciiz_pagenums[max_distinct_pages];
	unsigned n_pagenums_used = 0;
	bzero(asciiz_pagenums, max_distinct_pages * sizeof asciiz_pagenums[0]);
	/* We don't need to deduplicate, because we allocated a large enough array
	 * to deal with the case where all strings occupy distinct pagenums. */
#define ENUMERATE_ASCIIZ_CANDIDATE_PAGES(p) do { \
  unsigned long first_page_num = ((uintptr_t) (p)) >> LOG_MIN_PAGE_SIZE; \
  unsigned long last_page_num = ((uintptr_t) (((char*)(p)) + 1 + strlen((char*)(p)))) >> LOG_MIN_PAGE_SIZE; \
  do { \
    assert(n_pagenums_used < max_distinct_pages); \
    asciiz_pagenums[n_pagenums_used++] = first_page_num++; \
  } while (first_page_num < last_page_num); \
} while (0)
	VISIT_ALL_STRINGS(ENUMERATE_ASCIIZ_CANDIDATE_PAGES);
	/* Now we have a big array of page numbers, with many duplicates. Sort it. */
	qsort(&asciiz_pagenums[0], n_pagenums_used, sizeof asciiz_pagenums[0], compare_unsigned_long);
	fprintf(stderr, "enumerated %ld (likely highly duplicated) asciiz pages\n", (long) n_pagenums_used);
	if (n_pagenums_used > 0)
	{
		fprintf(stderr, "first and last: %p, %p\n",
			(void*) asciiz_pagenums[0],
			(void*) asciiz_pagenums[n_pagenums_used-1]
		);
	}
	fflush(stderr);
	/* Now we still have the duplicates, but we can just skip over them. */
#define proj(n) (*(n))
	unsigned long *found = bsearch_leq_generic(unsigned long, PAGENUM(lims.env_vector_terminator + 1),
			&asciiz_pagenums[0],
			n_pagenums_used,
			proj);
#undef proj
	/* play forwards until the first >= */
	if (found)
	{
		while (*found < PAGENUM(lowest_asciiz_seen) && found != &asciiz_pagenums[n_pagenums_used])
		{
			fprintf(stderr, "skipping too-low pagenum %p\n", (void*) *found); fflush(stderr);
			++found;
		}
	}
	/* we can only bsearch for entries <= , so if everything is >, we must intervene */
	if (!found && n_pagenums_used > 0 && asciiz_pagenums[0] >= PAGENUM(lims.env_vector_terminator + 1))
	{
		found = &asciiz_pagenums[0];
		fprintf(stderr, "initial asciiz pagenum %p\n", (void*) *found); fflush(stderr);
	}
	if (!found || found == &asciiz_pagenums[n_pagenums_used])
	{
		/* This means we found no strings at all pointing to at/above the auxv terminator.
		 * That's very strange, but could be e.g. if the program emptied its environment and
		 * rewrote its argv, or simply detached its asciiz data and located it somewhere lower
		 * in memory. */
		fprintf(stderr, "auxv/vectors beginning at %p suspiciously free of pointers to nearby string data"
			" (searched for pagenum <= 0x%lx across %d entries; lowest seen: %p vs %p\n", aux_vector_start,
				PAGENUM(lims.env_vector_terminator + 1), n_pagenums_used, lowest_asciiz_seen,
				(n_pagenums_used > 0) ? (void*) asciiz_pagenums[0] : (void*)-1);
		fflush(stderr);
		// assert(lowest_asciiz_seen == (const char*) -1);
		/* We can't assert that we didn't see *anything* -- can we

(gdb) print lowest_asciiz_seen 
$1 = 0x7fffffffcf69 "\2751K\224ixq\272\213\2259\352A\273\344Lx86_64"

	-- this is the lowest of all string pointers seen that were > aux_vector_start

(gdb) print (void*) asciiz_pagenums[0]
$3 = (void *) 0x7fffffffc

	-- this is the lowest pagenum of all string pointers that were > aux_vector_Start

found

	-- this is the highest pagenum *less than or equal to* PAGENUM(lims.aux_vector_terminator + 1)
		-- but there might reasonably not be anything less! if all strings are above. 
 */
	}
	else
	{
		unsigned long *found_lower = found;
		/* Now look for a contiguous range of pages */
		while (found + 1 != &asciiz_pagenums[n_pagenums_used]
				&& *(found + 1) <= *found + 1)
		{
			fprintf(stderr, "searching beyond included pagenum %p\n", (void*) *found);
			fflush(stderr);

			++found;
		}
		unsigned long *found_upper = found;

		/* Now do one last pass over the strings. */
		char *asciiz_upper_bound = (char*)(
				(((uintptr_t) *found_upper) << LOG_MIN_PAGE_SIZE)
				+ MIN_PAGE_SIZE
		);
		char *highest_asciiz_end_seen = NULL;
#define IDENTIFY_HIGHEST_ASCIIZ_BYTE(p) do { \
    char *end = (char*)(p) + strlen((char*)(p)) + 1; \
    if ((char*)(p) >= lowest_asciiz_seen && \
        end > highest_asciiz_end_seen && \
        end <= asciiz_upper_bound) \
    { highest_asciiz_end_seen = end; } \
} while (0)
		VISIT_ALL_STRINGS(IDENTIFY_HIGHEST_ASCIIZ_BYTE);

		/* Now for the asciiz. We lump it all in one chunk. */
		lims.asciiz_start = lowest_asciiz_seen;
		/* On Linux there is normally a zero word at the end of asciiz, but
		 * we can't rely on this e.g. because of valgrind's user-mode exec,
		 * which does not add a zero word. */
		lims.asciiz_end = highest_asciiz_end_seen;
	}

	return lims;
}
#undef expand_auxv_string_tags

struct auxv_copy_status
{
	enum auxv_component last_component_copied;
	size_t nbytes_used;
	ElfW(auxv_t) *maybe_auxv;
};
static inline
struct auxv_copy_status copy_and_resize_auxv(
	void *dest,
	ElfW(auxv_t) *p_src_auxv,
	struct auxv_limits *maybe_limits_cached,
	unsigned n_aux_entries_incl_terminator,
	ElfW(auxv_t) *in_additional_aux_entries,
	unsigned n_env_entries_incl_terminator,
	char **in_additional_env_entries,
	unsigned n_arg_entries_incl_terminator,
	char **in_additional_arg_entries,
	unsigned total_bytes_at_dest,
	char *in_additional_asciiz_data,
	size_t in_additional_asciiz_data_nbytes
)
{
	char *dest_start = dest;
	char *dest_end = dest_start + total_bytes_at_dest;
	char *pos = dest;
	struct auxv_limits tmp_limits;
	struct auxv_limits *limits;
	if (maybe_limits_cached) limits = maybe_limits_cached;
	else { tmp_limits = get_auxv_limits(p_src_auxv); limits = &tmp_limits; }

/* TODO: give these macros protected name like BYTES_REMAINING_, so that neither
 * they nor our later undef clobbers any user macros. */
#define BYTES_REMAINING (dest_end - pos)
#define BYTES_USED (pos - dest_start)

	ElfW(auxv_t) *out_auxv = NULL;
#define CHECK_DEST_LIMIT(needed_end_outpos, elt) do { \
    if ((needed_end_outpos) - pos > BYTES_REMAINING) { \
      fprintf(stderr, "ran out of bytes at " # elt " (needed %ld, remaining %ld)\n", (long) ((needed_end_outpos) - pos), (long)(BYTES_REMAINING) ); fflush(stderr); \
      return (struct auxv_copy_status) { \
        .nbytes_used = pos - dest_start, \
        .last_component_copied = ((elt)-1), \
        .maybe_auxv = out_auxv \
       }; \
    } \
  } while (0)

#define MEMCPY_AND_INCREMENT(src, nbytes, elt) \
  do { \
    CHECK_DEST_LIMIT(pos + (nbytes), elt); \
    memcpy( pos, (src), (nbytes) ); \
    pos += (nbytes); \
  } while (0)

/* We should never have to align up the position. It makes it
 * harder for clients to calculate the size they need. Since
 * we put the asciiz (lower-alignment) stuff at the end,
 * and auxv entries have only word alignment (ASSUMPTION),
 * there's no need to insert padding. */
#if 0
#define ALIGN_UP_TO(n, elt) do { \
    char *endpos = ROUND_UP_PTR(pos, (n)); \
    CHECK_DEST_LIMIT(endpos, (elt)); \
    pos = endpos; \
  } while (0)
#else
#define ALIGN_UP_TO(n, elt) do { \
    assert((uintptr_t) pos % (n) == 0); \
} while (0)
#endif

	/* Copy the argcount. */
	MEMCPY_AND_INCREMENT(limits->p_argcount, sizeof *limits->p_argcount, AUXV_ARGCOUNT);
#define COPY_VEC(T, frag, FRAG) /* HACK: to leave dest_frag_vector_start decl in calling scope, delay */ \
                                /* the do {} while (0)... don't use after do/while/if without { } ! */ \
	ALIGN_UP_TO(_Alignof (T), AUXV_ ## FRAG ## _VECTOR); \
	T* dest_ ## frag ## _vector_start = (T*) pos; \
	do { \
	/* Copy up to the size the caller wanted. */ \
	/* XXX: should we size using the without-terminator size? */ \
	/* HACK: use MINPTR, defined on uintptr_t; we have no MIN() here */ \
	size_t n_copied_from_src =  MINPTR( \
			n_ ## frag ## _entries_incl_terminator, \
			1u + (limits-> frag ## _vector_terminator - limits-> frag ## _vector_start) \
		); \
	MEMCPY_AND_INCREMENT(limits-> frag ## _vector_start, \
		sizeof (T) * n_copied_from_src, \
		AUXV_ ## FRAG ## _VECTOR \
	); \
	/* How many have we copied? */ \
	if (n_copied_from_src < n_ ## frag ##_entries_incl_terminator) \
	{ \
		/* The caller asks to fill in some more. We may or may not */ \
		/* have copied a terminator already... have we? */ \
		size_t n_more_to_copy; \
		uintptr_t testword; \
		if (n_copied_from_src > 0 && \
		  (memcpy(&testword, &dest_ ## frag ## _vector_start[n_copied_from_src - 1], sizeof testword), !testword)) /* <-- strict-aliasing-safe HACK for char* or auxv_t* */ \
		{ \
			/* We copied a terminator earlier. Need to overwrite it. */ \
			pos -= sizeof (T); \
			n_more_to_copy = /* target n */ n_ ## frag ##_entries_incl_terminator - \
			   /* one of the ones we copied earlier is not useful */ (n_copied_from_src - 1) - \
			   1 /* need a terminator; no point creating this by copy */; \
		} \
		else \
		{ \
		    /* We didn't copy a terminator earlier.  */ \
			n_more_to_copy = /* target n */ n_ ## frag ##_entries_incl_terminator - \
			   n_copied_from_src - 1 /* need a terminator; no point creating this by copy */; \
		} \
		MEMCPY_AND_INCREMENT(in_additional_ ## frag ## _entries, \
		    sizeof (T) * n_more_to_copy, AUXV_ ## FRAG ## _VECTOR); \
		/* Increment pos to make space for the terminator that we didn't create by copy. */ \
		pos += sizeof (T); \
	} \
	/* ensure termination */ \
	bzero(&dest_ ## frag ## _vector_start[n_ ## frag ##_entries_incl_terminator - 1], sizeof (T)); \
} while (0)
	COPY_VEC(char*, arg, ARG);
	COPY_VEC(char*, env, ENV);
	COPY_VEC(ElfW(auxv_t), aux, AUX);
	out_auxv = dest_aux_vector_start;

	/* asciiz. Conceptually we view the asciiz data as logically detached
	 * from the auxv, i.e. does not have to follow in memory. If we run
	 * out of room, we can simply omit to copy it. The caller in effect
	 * requests this by specifying a buffer size s.t. it will lack room
	 * fo *any* asciz. The size needed for such a partially copied auxv
	 * is naturally calculated from the return value of get_auxv_limits.
	 * But yes, the caller has to calculate the size s.t. asciz won't be
	 * copied, but everything before will. */

	/* Here is a real example of how Linux fills the asciz/auxv boundary
	 * area, from high to low...

0x7fffffffcf50: 0x74732f6c61636f6c      0x6f772f6e65687065
0x7fffffffcf40: 0x0     0x2f7261762f000000                       <-- another alignment boundary... 0x7fffffffcf4b is the executable filename, then next pos rounded down to 0x7fffffffcf40. This is the initial arch_align_stack position.
0x7fffffffcf30: 0x573c83132de8016       0x34365f36387835         <-- ... AT_RANDOM continuing, then "x86_64" (7 bytes at 0x7fffffffcf39)
0x7fffffffcf20: 0x0     0x5d24c5d7d1c75500                       <-- 9 zero (padding) bytes, then AT_RANDOM
0x7fffffffcf10: 0x0     0x0                                      <-- auxv terminator
0x7fffffffcf00: 0xf     0x7fffffffcf39                           <-- auxv entry (AT_PLATFORM)
0x7fffffffcef0: 0x1f    0x7fffffffefa7                           <-- auxv entry (AT_EXECFN)
0x7fffffffcee0: 0x1a    0x2                                      <-- auxv entry (AT_HWCAP2)
0x7fffffffced0: 0x19    0x7fffffffcf29                           <-- auxv entry (AT_RANDOM)
0x7fffffffcec0: 0x17    0x0
0x7fffffffceb0: 0xe     0x3e8
0x7fffffffcea0: 0xd     0x3e8
0x7fffffffce90: 0xc     0x3e8
0x7fffffffce80: 0xb     0x3e8
0x7fffffffce70: 0x9     0x5555555550e0 <_start>
0x7fffffffce60: 0x8     0x0
0x7fffffffce50: 0x7     0x7ffff7fcb000                           <-- auxv entry (AT_BASE)
0x7fffffffce40: 0x5     0xd
0x7fffffffce30: 0x4     0x38
0x7fffffffce20: 0x3     0x555555554040                           <-- auxv entry (AT_PHDR)
0x7fffffffce10: 0x11    0x64
0x7fffffffce00: 0x6     0x1000
0x7fffffffcdf0: 0x10    0xbfebfbff
0x7fffffffcde0: 0x33    0x6f0
0x7fffffffcdd0: 0x21    0x7ffff7fc9000                           <-- auxv entry (AT_SYSINFO_EHDR)
	 
	 Yes, AT_RANDOM really does point to 0x7fffffffcf39
	 How does this come to be? see fs/binfmt_elf.c.

	 These STACK_ALLOC macros are growing the stack downwards.
	 The 9 thing is simply a reflection of how many bytes are in the strings.
	 We get an unaligned AT_RANDOM because it has no alignment requirement so is just
	 blatted out after these strings.
	 
	 Note that initially, the asciiz strings are on the stack but
	 the aux vector is not -- nor are the arg vector or env vector, not argc.
	 So we add the AT_RANDOM data quite early.
	 We did, however, do arch_align_stack... did this do anything? Yes. 
	         if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
                sp -= prandom_u32_max(8192);
        return sp & ~0xf;
	
	Note that on some MIPS ABIs, the mask is ~7 not ~15

static int
create_elf_tables(struct linux_binprm *bprm, const struct elfhdr *exec,
		unsigned long interp_load_addr,
		unsigned long e_entry, unsigned long phdr_addr)
{
	unsigned long p = bprm->p;
...
	p = arch_align_stack(p);                                // see above!
...
	u_platform = NULL;
	if (k_platform) {
		size_t len = strlen(k_platform) + 1;

		u_platform = (elf_addr_t __user *)STACK_ALLOC(p, len);
		if (copy_to_user(u_platform, k_platform, len))
			return -EFAULT;
	}
...
	memset(elf_info, 0, (char *)mm->saved_auxv +
			sizeof(mm->saved_auxv) - (char *)elf_info);
...
	// And advance past the AT_NULL entry.
	elf_info += 2;
...
	ei_index = elf_info - (elf_addr_t *)mm->saved_auxv;
	sp = STACK_ADD(p, ei_index);
...
	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);

 These STACK_ADD and STACK_ROUND are sized in elf_addr_t units, i.e. words.

	items = (argc + 1) + (envc + 1) + 1;
	bprm->p = STACK_ROUND(sp, items);
...
	sp = (elf_addr_t __user *)bprm->p;
*/
	char *copied_out_old_asciiz_start = pos;
	enum auxv_component last_copied = AUXV_AUX_VECTOR;
	size_t nbytes_old_asciiz_to_copy = MINPTR(limits->asciiz_end - limits->asciiz_start,
		BYTES_REMAINING);
	if (nbytes_old_asciiz_to_copy != 0)
	{
		MEMCPY_AND_INCREMENT(limits->asciiz_start,
			nbytes_old_asciiz_to_copy,
			AUXV_AUX_VECTOR);
		*(pos-1) = '\0';
	}
	/* "one past the null terminator" is the last valid offset... our bounds check includes the NUL */
	unsigned long max_offset_into_copied_old_asciiz = pos - copied_out_old_asciiz_start;
	// caller-suppied *extra* asciiz
	char *out_additional_asciiz_start = pos;
	if (in_additional_asciiz_data && in_additional_asciiz_data_nbytes > 0)
	{
		fprintf(stderr, "copying additional asciiz (beginning: \"%s\") to memory starting at %p\n",
			in_additional_asciiz_data, out_additional_asciiz_start);
		MEMCPY_AND_INCREMENT(in_additional_asciiz_data, in_additional_asciiz_data_nbytes,
			AUXV_AUX_VECTOR);
		*(pos-1) = '\0';
	}
	unsigned long max_offset_into_out_additional_asciiz = pos - out_additional_asciiz_start;
	/* Only declare us as having copied AUXV_ASCIIZ if we copied all the original
	 * and as many bytes as requested of the additional. */
	if ((pos - copied_out_old_asciiz_start) == (limits->asciiz_end - limits->asciiz_start)
			+ (in_additional_asciiz_data ? (ssize_t) in_additional_asciiz_data_nbytes : 0))
	{
		last_copied = AUXV_ASCIIZ;
	}

	/* We need to rewrite the argv/env/auxv entries if they point into the asciiz! */
#define REWRITE_VECTOR(T, start, proj, null_proj, filter) \
	for (T *p_ent = (start); !!null_proj(p_ent); ++p_ent) \
	{ \
		if (!(filter(p_ent))) continue; \
		char *ptr = (char*) proj(p_ent); \
		fprintf(stderr, "(0) considering adjusting a vector value %p (\"%s\")" \
		   " in az %p-%p +n az %p-%p\n", ptr, ptr, \
			limits->asciiz_start, limits->asciiz_end, \
			in_additional_asciiz_data ?: NULL, \
			in_additional_asciiz_data ? ((char*) in_additional_asciiz_data + in_additional_asciiz_data_nbytes) : NULL); \
		fflush(stderr); \
		if (ptr >= limits->asciiz_start && ptr < limits->asciiz_end) \
		{ \
			unsigned long offset = ptr - limits->asciiz_start; \
			size_t len = strnlen(ptr, limits->asciiz_end - ptr); \
			fprintf(stderr, "(1) start falls withing asciiz; end? len %ld, in offset 0x%lx, max out offset 0x%lx\n", (long) len, (long) offset, (long) max_offset_into_copied_old_asciiz); fflush(stderr); \
			if (offset + len + 1 <= max_offset_into_copied_old_asciiz) { \
				fprintf(stderr, "(2) end also\n"); fflush(stderr); \
			    char *old_p = proj(p_ent); \
				proj(p_ent) = copied_out_old_asciiz_start + offset; \
				fprintf(stderr, "(3) adjusted a vector value (\"%s\") in asciiz:" \
				   " offset 0x%lx is now at %p\n", old_p, offset, proj(p_ent)); \
				fflush(stderr); \
			} \
		} \
		else if (in_additional_asciiz_data && ptr >= in_additional_asciiz_data && \
		  ptr < in_additional_asciiz_data + in_additional_asciiz_data_nbytes) \
		{ \
			unsigned long offset_within_in_additional_asciiz = ptr - in_additional_asciiz_data; \
			/* length of the string in the input data */ \
			size_t len = strnlen(ptr, in_additional_asciiz_data_nbytes - \
			    offset_within_in_additional_asciiz); \
			fprintf(stderr, "(4) start falls withing additional; end? len %ld, in offset 0x%lx, max out offset 0x%lx\n", (long) len, offset_within_in_additional_asciiz, max_offset_into_out_additional_asciiz); fflush(stderr); \
			if (offset_within_in_additional_asciiz + len + 1 <= max_offset_into_out_additional_asciiz) { \
			   fprintf(stderr, "(5) end also\n"); fflush(stderr); \
			   char *old_p = proj(p_ent); \
			   proj(p_ent) = out_additional_asciiz_start + offset_within_in_additional_asciiz; \
				fprintf(stderr, "(6) adjusted a vector value (\"%s\") in additional asciiz:" \
				   " offset 0x%lx is now at %p + %lx = %p (was %p)\n", old_p, \
					(long) offset_within_in_additional_asciiz, out_additional_asciiz_start, \
					offset_within_in_additional_asciiz, (void*)(proj(p_ent)), old_p); \
				fflush(stderr); \
			} else { \
			  fprintf(stderr, "fishy: no room adjust a vector value (\"%s\") in additional asciiz:" \
			   " offset 0x%lx is at %p + %lx = %p\n", (char*) (proj(p_ent)), \
				(long) offset_within_in_additional_asciiz, out_additional_asciiz_start, \
				offset_within_in_additional_asciiz, (void*)(proj(p_ent))); \
 \
			}\
		} \
	}
#define proj(p_ent) (*(p_ent))
#define filter(p_ent) 1
	REWRITE_VECTOR(char*, dest_arg_vector_start, proj, proj, filter);
	REWRITE_VECTOR(char*, dest_env_vector_start, proj, proj, filter);
#undef proj
#undef filter
#define proj(p_ent) (p_ent)->a_un.a_val
#define null_proj(p_ent) (p_ent)->a_type
#define expand_auxv_string_tags(tag) || p_ent->a_type == tag
#define filter(p_ent) (0 auxv_string_tags(expand_auxv_string_tags))
	/* filter for the string-bearing auxv entries */
	REWRITE_VECTOR(ElfW(auxv_t), dest_aux_vector_start, proj, null_proj, filter);
#undef expand_auxv_string_tags
#undef filter
#undef proj
#if 0
	for (ElfW(auxv_t) *p_ent = dest_aux_vector_start; p_ent->a_type != AT_NULL; ++p_ent)
	{
		ElfW(auxv_t) ent = *p_ent;
		if ((char*) ent.a_un.a_val >= limits->asciiz_start && 
				(char*) ent.a_un.a_val < limits->asciiz_end)
		{
			/* Only do the rewrite for tags that are known to point to strings?
			 * but WARN if we see one that looks like a string ptr  */
#define expand_auxv_string_tags(tag) || ent.a_type == tag
			if (0 auxv_string_tags(expand_auxv_string_tags))
#undef expand_auxv_string_tags
			{
				unsigned long offset = (char*) ent.a_un.a_val - limits->asciiz_start;
				size_t len = strnlen((char*) ent.a_un.a_val,
					limits->asciiz_end - (char*) ent.a_un.a_val);
				/* We detect the case where the characters lie outside the range that
				 * has been copied. Use +1 so that we don't write new unterminated
				 * strings, even though via strnlen we guard against reading these. */
				if (offset + len + 1 <= max_offset_into_copied_old_asciiz)
				{
					p_ent->a_un.a_val = (uintptr_t) (copied_out_old_asciiz_start + offset);
				}
			}
			else
			{
				fprintf(stderr, "suspiciously string-pointer-like value in auxv entry with type 0x%lx\n",
					(long) ent.a_type);
				fflush(stderr);
			}
		}
	} /* end for auxv entry to rewrite */
#endif
	/* If we skipped copying the asciiz, the pointers in the vectors should be
	 * unmolested. */
	/* TODO: using this to move the stack *except* the asciiz may break librunt's method
	 * for discovering the auxv in the first place. I think the right method would
	 * - read /proc/self/stat to get the arg/env area pointers
	 * - if moving any of the stack, use prctl(PR_SET_MM) to update the relevant kernel pointers.
	 */
	return (struct auxv_copy_status) {
		.nbytes_used = pos - dest_start,
		.last_component_copied = last_copied,
		.maybe_auxv = out_auxv
	};
}
#undef BYTES_REMAINING
#undef CHECK_DEST_LIMIT
#undef MEMCPY_AND_INCREMENT
#undef ALIGN_UP_TO
#undef COPY_VEC

/* These are nasty. We include our own strcmp and strchr so that we can search environment
 * strings without being dependent on dynamically linked libc functions. Similarly we have
 * a way to search environment strings located not via the global 'environ'. This is so that
 * we can run very early. The only code that uses this, to my knowledge, is in liballocs
 * (pageindex.c). I thought about moving them to liballocs but have decided to leave these
 * here for now... since we deal with auxv, we deal with environment strings and we are
 * intending to cater to "sensitive contexts" where libc functions aren't available. */
static inline int relf_strncmp_(const char *str1, const char *str2, size_t n)
{
	const char *orig_str1 = str1;
	while (str1 - orig_str1 < (ptrdiff_t) n)
	{
		signed diff = *str1 - *str2;
		if (0 != diff) return diff; /* found a non-equal character; diff has correct sign */
		if (!*str1) /* they're equal! *str2 is also NUL */ break;
		++str1;
		++str2;
	}
	/* If we got here, we've compared n characters without seeing a diff */
	return 0;
}
static inline char *relf_strchr_(const char *s, int c)
{
	while (*s && *s != c) ++s;
	if (*s == c) return (char*) s;
	return NULL;
}
static inline char **environ_get_env_vector_ptr(const char *name, char **environ, const char **maybe_out_equals_pos)
{
	const char *var;
	while (NULL != (var = *(environ++)))
	{
		const char *equals_pos = relf_strchr_(var, '=');
		if (!equals_pos || equals_pos == var) continue; // weird string
		if (0 == relf_strncmp_(name, var, equals_pos - var))
		{
			// hit!
			if (maybe_out_equals_pos) *maybe_out_equals_pos = equals_pos;
			return environ - 1;
		}
	}
	return NULL;
}
static inline char *environ_getenv(const char *name, char **environ)
{
	const char *equals_pos = NULL;
	char **found = environ_get_env_vector_ptr(name, environ, &equals_pos);
	if (found) return (char*)(equals_pos + 1);
	return NULL;
}

static inline char **get_auxv_environ(ElfW(auxv_t) *auxv)
{
	struct auxv_limits l = get_auxv_limits(auxv);
	return (char**) l.env_vector_start;
}

static inline
ElfW(Dyn) *find_dynamic(char **environ, void *stackptr)
{
	if (&_DYNAMIC[0]) return &_DYNAMIC[0];
	else
	{
		ElfW(auxv_t) *auxv = get_auxv(environ, stackptr);
		if (auxv)
		{
			// ElfW(auxv_t) found_phdr = auxv
			__assert_fail("implementation", __FILE__, __LINE__, __func__);
			// FIXME: Complete
		}
	}
	return NULL; /* shuts up frontc */
}

static inline
ElfW(Dyn) *local_dynamic_xlookup(ElfW(Sword) tag)
{
	return dynamic_xlookup(_DYNAMIC, tag);
}

static inline
uintptr_t guess_load_addr_early(void)
{
	/* We want a way to get our load address, including early i.e. before
	 * ADJUST_DYN_INFO has happened (but usually after bootstrap relocation).
	 *
	 * The current object's load address is... &DYNAMIC minus the value of
	 * the _DYNAMIC symbol. But we can't get at our own dynsym unless we
	 * already know our own load addr, or at least unless our own _DYNAMIC
	 * has already been ADJUST_DYN_INFO'd (which we don't want to assume).
	 *
	 * If only _DYNAMIC pointed at something we could get the address of.
	 * (Like itself!)
	 * Some such entities are: (from  readelf -d hello | egrep '0x[0-9a-f]{3,}$' | tr -s '[:blank:]' '\t' | cut -f4,
	 * then grep readelf -s)
	 *
		__init_array_end
		__init_array_start
		_GLOBAL_OFFSET_TABLE_
		_init
		_fini
	 *
	 * ... but not all binaries will have all of these. _init and _fini seem
	 * like the most reliable.
	 */
	for (ElfW(Dyn) *d = &_DYNAMIC[0]; d->d_tag != DT_NULL; ++d)
	{
		if (d->d_tag == DT_FINI && &_fini)
		{
			uintptr_t load_addr = (uintptr_t) &_fini - d->d_un.d_ptr;
			// might be 0! but if so, ADJUST_DYN_INFO has happened
			return load_addr;
		}
		if (d->d_tag == DT_INIT && &_init)
		{
			uintptr_t load_addr = (uintptr_t) &_init - d->d_un.d_ptr;
			// might be 0! but if so, ADJUST_DYN_INFO has happened
			return load_addr;
		}
	}
	return (uintptr_t) -1;
}

static inline 
struct R_DEBUG_STRUCT_TAG *find_r_debug(void)
{
// 	/* If we have DT_DEBUG in our _DYNAMIC, try that. */
// 	ElfW(Dyn) *found = &_DYNAMIC ? dynamic_lookup(_DYNAMIC, DT_DEBUG) : NULL;
// 	if (found) return (struct R_DEBUG_STRUCT_TAG *) found->d_un.d_ptr;
// 	else
// 	{
// 		/* HMM. We need to get the _DYNAMIC section from another object, 
// 		 * like ld.so or the executable. Can we do this portably? I don't think so. */
// 		
// 		/* Fall back to the _r_debug "convention" */
// 		if (NULL != &_r_debug)
// 		{
// 			return &_r_debug;
// 		}
// 		__assert_fail("found r_debug", __FILE__, __LINE__, __func__);
// 	}
	if (&_r_debug) return &_r_debug;
	/* We've tried linking against an _r_debug and it didn't work. This presumably means that we are the dynamic linker, or are somehow involved in bootstrapping its operation (e.g. we are a chain loader). Here we are assuming that local reference works, i.e. we are getting our own _DYNAMIC. */
	ElfW(Dyn) *found = &_DYNAMIC ? dynamic_lookup(_DYNAMIC, DT_DEBUG) : NULL;
	if (found)
	{
		/* HACK: we need our own load address if we're to do RELF_MAYBE_ADJUST.
		 * How can we get it? */
		uintptr_t guessed_load_addr = guess_load_addr_early();
		if (guessed_load_addr == (uintptr_t) -1)
		{
			// This means we didn't find a symbol we could use to infer the load addr.
			// Not much we can do! Zero makes RELF_MAYBE_ADJUST a no-op.
			guessed_load_addr = 0;
		}
#if 0
		/* An example of debugging printout that works even very early during startup.
		 * This debugging printout appears only if librunt.h is included before relf.h.
		 * Leaving this here just to illustrate. */
		write_ulong((uintptr_t) guessed_load_addr);
		write_string("\n");
		write_ulong(found->d_un.d_ptr);
		write_string("\n");
#endif
		return (struct R_DEBUG_STRUCT_TAG *) RELF_MAYBE_ADJUST(found->d_un.d_ptr, guessed_load_addr);
	}
	return NULL;
}
static inline
struct LINK_MAP_STRUCT_TAG*
get_highest_loaded_object_below(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-lower one. */
	struct LINK_MAP_STRUCT_TAG *highest_lower_seen = NULL;
	struct r_debug *r = find_r_debug();
	for (struct LINK_MAP_STRUCT_TAG *l = r->r_map; l; l = l->l_next)
	{
		if ((char*) l->l_addr <= (char*) ptr
			&& (!highest_lower_seen || 
				(char*) l->l_addr > (char*) highest_lower_seen->l_addr))
		{
			highest_lower_seen = l;
		}
	}
	return highest_lower_seen;
}
static inline
struct LINK_MAP_STRUCT_TAG *
get_lowest_loaded_object_above(void *ptr)
{
	/* Walk all the loaded objects' load addresses. 
	 * The load address we want is the next-higher one. */
	struct LINK_MAP_STRUCT_TAG *lowest_higher_seen = NULL;
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map; l; l = l->l_next)
	{
		if ((char*) l->l_addr > (char*) ptr
				&& (!lowest_higher_seen || 
					(char*) l->l_addr < (char*) lowest_higher_seen->l_addr))
		{
			lowest_higher_seen = l;
		}
	}
	return lowest_higher_seen;
}

static inline void *get_local_load_addr(void)
{
	return (void*) get_highest_loaded_object_below((void*) &get_local_load_addr)->l_addr;
}

extern int _etext;
static inline void *get_local_text_segment_end(void)
{
	char *our_load_addr = (char*) get_local_load_addr();
	uintptr_t etext_value = (uintptr_t) &_etext;
	// MONSTER HACK: sometimes _etext references are relocated, others not.
	// FIXME: understand this
	return (void*) RELF_MAYBE_ADJUST(etext_value, our_load_addr);
}

// HACK: not actually possible in general, because we use phdrs
static inline void *get_text_segment_end_from_load_addr(void *load_addr)
{
	/* monster HACK; consider searching for an _etext or etext symbol first */
	ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) load_addr;
	ElfW(Phdr) *phdrs = (ElfW(Phdr) *)((char*) ehdr + ehdr->e_phoff);
	return (char *) load_addr + phdrs[0].p_memsz; // another monster HACK
}

static inline
struct LINK_MAP_STRUCT_TAG*
get_link_map(void *ptr)
{
	return get_highest_loaded_object_below(ptr);
}

static inline
void *find_ldso_base(char **environ, void *stackptr)
{
	ElfW(auxv_t) *at_interp = auxv_xlookup(get_auxv(environ, stackptr), AT_BASE);
	void *ldso_base = (void*) at_interp->a_un.a_val;
	if (!ldso_base)
	{
		/* This happens if the program is running the ld.so explicitly, i.e. 
		 *    /path/to/ld.so ./program
		 * ... in which case we *still* want the base of the ld.so, and
		 * it really won't be 0. Hmm.
		 * 
		 * Turns out that _r_debug tells us this!
		 * 
		 * If we didn't have r_debug, we could use a symbol that we know is defined
		 * in the ld.so. BUT ARGH. If we use a data symbol like _r_debug itself we might 
		 * get a copy reloc. If we use a text symbol we'll get a PLT entry. Getting
		 * an address that is genu-winely in the ld.so, via a public interface, is hard. */
		
		ldso_base = (void*) find_r_debug()->r_ldbase;
	}
	return ldso_base;
}

static inline
ElfW(Sym) *get_dynsym_from_dyn(ElfW(Dyn) *d, uintptr_t load_addr)
{
	ElfW(Addr) a = dynamic_xlookup(d, DT_SYMTAB)->d_un.d_ptr;
	return a ? (ElfW(Sym) *) RELF_MAYBE_ADJUST(a, load_addr) : NULL;
}
static inline
ElfW(Sym) *get_dynsym(struct LINK_MAP_STRUCT_TAG *l)
{
	return get_dynsym_from_dyn(l->l_ld, l->l_addr);
}
static inline
ElfW(Word) *get_gnu_hash_from_dyn(ElfW(Dyn) *d, uintptr_t load_addr)
{
	ElfW(Dyn) *gnu_hash_ent = dynamic_lookup(d, DT_GNU_HASH);
	ElfW(Word) *gnu_hash = gnu_hash_ent ? (ElfW(Word) *) RELF_MAYBE_ADJUST(gnu_hash_ent->d_un.d_ptr, load_addr) : NULL;
	return gnu_hash;
}
static inline
ElfW(Word) *get_gnu_hash(struct LINK_MAP_STRUCT_TAG *l)
{
	return get_gnu_hash_from_dyn(l->l_ld, l->l_addr);
}
static inline
ElfW(Word) *get_sysv_hash_from_dyn(ElfW(Dyn) *d, uintptr_t load_addr)
{
	ElfW(Dyn) *hash_ent = dynamic_lookup(d, DT_HASH);
	ElfW(Word) *hash = hash_ent ? (ElfW(Word) *) RELF_MAYBE_ADJUST(hash_ent->d_un.d_ptr, load_addr) : NULL;
	return hash;
}
static inline
ElfW(Word) *get_sysv_hash(struct LINK_MAP_STRUCT_TAG *l)
{
	return get_sysv_hash_from_dyn(l->l_ld, l->l_addr);
}
static inline
unsigned char *get_dynstr_from_dyn(ElfW(Dyn) *d, uintptr_t load_addr)
{
	unsigned char *strtab = (unsigned char *) RELF_MAYBE_ADJUST(dynamic_xlookup(d, DT_STRTAB)->d_un.d_ptr, load_addr);
	return strtab;
}
static inline
unsigned char *get_dynstr(struct LINK_MAP_STRUCT_TAG *l)
{
	return get_dynstr_from_dyn(l->l_ld, l->l_addr);
}

static inline
unsigned long dynamic_symbol_count_from_dyn(ElfW(Dyn) *dyn, uintptr_t load_addr)
{
	ElfW(Word) *hash = get_sysv_hash_from_dyn(dyn, load_addr);
	if (hash) return dynamic_symbol_count_fast((Elf64_Sym*) NULL, NULL, hash);
	ElfW(Sym) *dynsym = get_dynsym_from_dyn(dyn, load_addr);
	unsigned char *dynstr = get_dynstr_from_dyn(dyn, load_addr);
	return dynamic_symbol_count_fast(dynsym, dynstr, hash);
}
static inline
unsigned long dynamic_symbol_count(ElfW(Dyn) *dyn /* unused */, struct LINK_MAP_STRUCT_TAG *l)
{
	return dynamic_symbol_count_from_dyn(l->l_ld, l->l_addr);
}

static inline
ElfW(Sym) *hash_lookup_local(const char *sym)
{
	ElfW(Word) *hash = (ElfW(Word) *) local_dynamic_xlookup(DT_HASH)->d_un.d_ptr;
	unsigned long local_base = (unsigned long) get_local_load_addr();
	if ((unsigned long) hash < local_base)
	{
		// FIXME: really want to print a warning here
		return NULL; // HACK: x86-64 vdso workaround
	}
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const unsigned char *strtab = (const unsigned char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	return hash_lookup(hash, symtab, strtab, sym);
}

static inline
ElfW(Sym) *gnu_hash_lookup_local(const char *sym)
{
	ElfW(Word) *hash = (ElfW(Word) *) local_dynamic_xlookup(DT_GNU_HASH)->d_un.d_ptr;
	unsigned long local_base = (unsigned long) get_local_load_addr();
	if ((unsigned long) hash < local_base)
	{
		// FIXME: really want to print a warning here
		return NULL; // HACK: x86-64 vdso workaround
	}
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const unsigned char *strtab = (const unsigned char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	return gnu_hash_lookup(hash, symtab, strtab, sym);
}

static inline 
uintptr_t guess_page_size_unsafe(void)
{
	int x;
	ElfW(auxv_t) *p_auxv = get_auxv(environ, &x);
	if (!p_auxv) abort();
	return auxv_xlookup(p_auxv, AT_PAGESZ)->a_un.a_val;
}

static inline 
void *get_exe_handle(void)
{
	int x;
	ElfW(auxv_t) *p_auxv = get_auxv(environ, &x);
	if (!p_auxv) abort();
	void *entry = (void*) auxv_xlookup(p_auxv, AT_ENTRY)->a_un.a_val;
	return get_highest_loaded_object_below(entry);
}

static inline
ElfW(Sym) *symbol_lookup_linear_local(const char *sym)
{
	ElfW(Sym) *symtab = (ElfW(Sym) *) local_dynamic_xlookup(DT_SYMTAB)->d_un.d_ptr;
	const unsigned char *strtab = (const unsigned char *) local_dynamic_xlookup(DT_STRTAB)->d_un.d_ptr;
	const unsigned char *strtab_end = strtab + local_dynamic_xlookup(DT_STRSZ)->d_un.d_val;
	/* Nasty hack: assume dynstr follows dynsym. */
	/* Round down to the alignment of ElfW(Sym). */
	ElfW(Sym) *symtab_end = (ElfW(Sym)*) RELF_ROUND_DOWN_PTR_(strtab, ALIGNOF(ElfW(Sym)));
	return symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym);
}

static inline
ElfW(Sym) *symbol_lookup_in_dyn(ElfW(Dyn) *d, uintptr_t load_addr, const char *sym)
{
	ElfW(Word) *hash = get_sysv_hash_from_dyn(d, load_addr);
	ElfW(Word) *gnu_hash = get_gnu_hash_from_dyn(d, load_addr);
	ElfW(Sym) *symtab = get_dynsym_from_dyn(d, load_addr);
	if (!symtab) return 0;
	ElfW(Sym) *symtab_end = symtab + dynamic_symbol_count_from_dyn(d, load_addr);
	unsigned char *strtab = get_dynstr_from_dyn(d, load_addr);
	unsigned char *strtab_end = strtab + dynamic_xlookup(d, DT_STRSZ)->d_un.d_val;

	/* Try the GNU hash lookup, if we can. Or else try SvsV hash.
	 * If we found no hash table of either kind, try linear. */
	ElfW(Sym) *found = NULL;
	if (gnu_hash) found = gnu_hash_lookup(gnu_hash, symtab, strtab, sym);
	else if (hash) found = hash_lookup(hash, symtab, strtab, sym);
	else found = symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym);
	return found;
}

static inline
ElfW(Sym) *symbol_lookup_in_object(struct LINK_MAP_STRUCT_TAG *l, const char *sym)
{
	return symbol_lookup_in_dyn(l->l_ld, l->l_addr, sym);
}

/* preserve NULLs */
#define LOAD_ADDR_FIXUP_GIVEN_BASE(b, p) \
	((!(p)) ? NULL : ((void*) (((char*) (p)) + (b))))
#define LOAD_ADDR_FIXUP_IN_OBJ(l, p) \
	LOAD_ADDR_FIXUP_GIVEN_BASE((l)->l_addr, p)
#define LOAD_ADDR_FIXUP(p, p_into_obj) \
	LOAD_ADDR_FIXUP_IN_OBJ( (get_link_map( (p_into_obj) )), (p) )

static inline
void *sym_to_addr(ElfW(Sym) *sym)
{
	if (!sym) return NULL;
	/* HACK for ifunc */
	if (ELFW_ST_TYPE(sym->st_info) == STT_GNU_IFUNC)
	{
		void *(*ifunc)(void) = (void*(*)(void)) LOAD_ADDR_FIXUP(sym->st_value, sym);
		return ifunc();
	}
	else return LOAD_ADDR_FIXUP(sym->st_value, sym);
}

//static inline
//void *sym_to_addr_in_object(struct LINK_MAP_STRUCT_TAG *l, ElfW(Sym) *sym)
//{
//	if (!sym) return NULL;
//	return LOAD_ADDR_FIXUP_IN_OBJ(l, sym->st_value);
//}

static inline
void *sym_to_addr_given_base(uintptr_t base, ElfW(Sym) *sym)
{
	if (!sym) return NULL;
	return LOAD_ADDR_FIXUP_GIVEN_BASE(base, sym->st_value);
}

static inline
void *fake_dlsym(void *handle, const char *symname)
{
	/* Which object do we want? It's either
	 * "the first" (RTLD_DEFAULT);
	 * "the one after us (RTLD_NEXT);
	 * "this one". */

	struct LINK_MAP_STRUCT_TAG *ourselves = NULL;
	if (handle == RTLD_NEXT)
	{
		if (!(_DYNAMIC)) __assert_fail("_DYNAMIC found", __FILE__, __LINE__, __func__);

	}
	for (struct LINK_MAP_STRUCT_TAG *l = find_r_debug()->r_map;
			l;
			l = l->l_next)
	{
		_Bool had_seen_ourselves = (ourselves != NULL);

		if (l->l_ld == _DYNAMIC)
		{
			ourselves = l;
		}
		
		/* Is this object eligible? */
		if (handle == l
				|| handle == RTLD_DEFAULT
				|| (handle == RTLD_NEXT && had_seen_ourselves))
		{
			/* Does this object have the symbol? */
			ElfW(Sym) *found = symbol_lookup_in_object(l, symname);
			if (found && found->st_shndx != SHN_UNDEF)
			{
				return sym_to_addr(found);
			}
			
			if (handle == l)
			{
				/* Symbol not found. We can stop now. */
				goto not_found;
			}
			// else continue around the loop
		}
	}
	
not_found:
	/* Symbol not found. FIXME: we really want to set dlerror, but we can't. 
	 * Ideally we'd make a libdl call that sets it to something. But we can't
	 * reliably do that from here. Instead, we use MAP_FAILED to signal error. */
	return (void*) -1;
	
}

static inline
int walk_symbols_in_object(struct LINK_MAP_STRUCT_TAG *l,
	int (*cb)(ElfW(Sym) *, void *), void *arg)
{
	ElfW(Sym) *symtab = get_dynsym(l);
	if (!symtab) return 0;

	unsigned char *strtab = get_dynstr(l);
	if (!strtab) return 0;
	
	ElfW(Word) *gnu_hash = get_gnu_hash(l);
	if (gnu_hash) return gnu_hash_walk_syms(gnu_hash, cb, symtab, strtab, arg);
	
	ElfW(Word) *hash = get_sysv_hash(l);
	if (hash) return hash_walk_syms(hash, cb, symtab, arg);
	
	return 0;
}

struct fake_dladdr_args
{
	void *in_sought_addr;
	ElfW(Sym) *out_found_sym;
};

static inline int fake_dladdr_cb(ElfW(Sym) *p_sym, void *args)
{
	struct fake_dladdr_args *found = (struct fake_dladdr_args *) args;
	void *addr = sym_to_addr(p_sym);
	if ((unsigned long) found->in_sought_addr - (unsigned long) addr < p_sym->st_size)
	{
		found->out_found_sym = p_sym;
		return 1;
	}
	return 0;
}

static inline
int fake_dladdr(void *addr, const char **out_fname, void **out_fbase, const char **out_sname,
	void **out_saddr)
{
	struct LINK_MAP_STRUCT_TAG *l = get_highest_loaded_object_below(addr);
	struct fake_dladdr_args args = { /* in */ addr, /* out */ NULL };
	int success = walk_symbols_in_object(l, fake_dladdr_cb, &args);
	if (success)
	{
		if (out_fname) *out_fname = l->l_name;
		if (out_fbase) *out_fbase = (void*) l->l_addr;
		if (out_sname) 
		{
			ElfW(Dyn) *dynstr_ent = dynamic_lookup(l->l_ld, DT_STRTAB);
			if (dynstr_ent)
			{
				char *dynstr = (char *) dynstr_ent->d_un.d_ptr;
				if ((intptr_t) dynstr >= 0)
				{
					*out_sname = &dynstr[args.out_found_sym->st_name];
					goto done_dynstr;
				}
			}
			*out_sname = NULL;
		}
	done_dynstr:
		if (out_saddr) *out_saddr = sym_to_addr(args.out_found_sym);
	}
	return success; /* i.e. "return 0 on error", like dladdr */
}

static inline uintptr_t
find_section_boundary(
	uintptr_t vaddr,
	ElfW(Word) flags,
	_Bool backwards,
	ElfW(Shdr) *shdrs,
	unsigned nshdr,
	unsigned *out_shndx)
{
	ElfW(Shdr) *best = NULL;
	ptrdiff_t best_diff = PTRDIFF_MAX;
	for (ElfW(Shdr) *cur = shdrs;
			cur != shdrs + nshdr;
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
	if (!best) return backwards ? 0 : (uintptr_t)-1;
	if (out_shndx) *out_shndx = (best - shdrs);
	return (backwards ? (best->sh_addr + best->sh_size) : best->sh_addr);
}

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
