#ifndef RELF_H_
#define RELF_H_

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#endif

#include <stddef.h> /* for offsetof */
#include <stdint.h>
size_t strlen(const char *s); /* avoid string.h */
#include <elf.h>
#include "elfw.h"
#include "vas.h" /* hmm -- may pollute namespace, but see how we go */
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
#if __STDC_VERSION__ >= 201112L
_Noreturn
#endif
/* musl's 'line' is signed, but glibc's is unsigned. It doesn't matter
 * in practice but the compiler will throw a fit. We tried to be slick
 * by omitting argument specs, but that doesn't work in C++. */
extern void
__assert_fail (
const char *assertion, const char *file,
#if !defined(__musl__) && !defined(ASSERT_FAIL_LINE_SIGNED)
	unsigned
#endif
        int line, const char *function
)
#ifdef __cplusplus
throw()
#endif
#if __STDC_VERSION__ >= 201112L
 __attribute__((__noreturn__))
#endif
;
extern char **environ;
extern void abort(void) __attribute__((noreturn));

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

struct auxv_limits
{
	ElfW(auxv_t) *auxv_array_terminator;
	const char **env_vector_start;
	const char **env_vector_terminator;
	const char **argv_vector_start;
	const char **argv_vector_terminator;
	const char *asciiz_start;
	const char *asciiz_end;
	intptr_t *p_argcount;
};

static inline
struct auxv_limits get_auxv_limits(ElfW(auxv_t) *auxv_array_start)
{
#ifdef __cplusplus
	struct auxv_limits lims = { 0, 0, 0, 0, 0, 0, 0, 0 };
#else
	struct auxv_limits lims = { .auxv_array_terminator = NULL };
#endif
	const char *highest_asciiz_seen = (const char*) auxv_array_start; // dummy initial value

	lims.auxv_array_terminator = auxv_array_start;
	while (lims.auxv_array_terminator->a_type != AT_NULL)
	{
		/* FIXME: check for AT_RANDOM, AT_PLATFORM and anything else that might
		 * be pointing at data in the vague asciiz area, so we can remember the
		 * highest address. */
		++lims.auxv_array_terminator;
	}

	/* auxv_array_start[0] is the first word higher than envp's null terminator. */
	lims.env_vector_terminator = ((const char**) auxv_array_start) - 1;
	/* In some strange cases we get multiple words of zero terminator. */
	while (!*((char**) lims.env_vector_terminator - 1)) --lims.env_vector_terminator;
	if (!(!*lims.env_vector_terminator)) __assert_fail("found envp terminator", __FILE__, __LINE__, __func__);
	lims.env_vector_start = lims.env_vector_terminator;
	while (*((char**) lims.env_vector_start - 1)) --lims.env_vector_start;

	/* argv_vector_terminator is the next word lower than envp's first entry. */
	lims.argv_vector_terminator = ((const char**) lims.env_vector_start) - 1;
	if (!(!*lims.argv_vector_terminator)) __assert_fail("found argv terminator", __FILE__, __LINE__, __func__);
	lims.argv_vector_start = lims.argv_vector_terminator;
	unsigned nargs = 0;
	/* To search for the start of the array, we look for an integer that is
	 * a plausible argument count... which won't look like any pointer we're seeing. */
	#define MAX_POSSIBLE_ARGS 4194304
	while (*((uintptr_t*) lims.argv_vector_start - 1) > MAX_POSSIBLE_ARGS)
	{
		--lims.argv_vector_start;
		++nargs;
	}
	if (!(*((uintptr_t*) lims.argv_vector_start - 1) == nargs)) __assert_fail("argv vector length match", __FILE__, __LINE__, __func__);
	lims.p_argcount = (intptr_t*) lims.argv_vector_start - 1;

	/* Now we have the arg vectors and env vectors, loop through them
	 * to get the highest char pointer we see. */
	for (const char **p = lims.argv_vector_start; p != lims.argv_vector_terminator; ++p)
	{
		if ((*p) > highest_asciiz_seen) highest_asciiz_seen = *p;
	}
	for (const char **p = lims.env_vector_start; p != lims.env_vector_terminator; ++p)
	{
		if ((*p) > highest_asciiz_seen) highest_asciiz_seen = *p;
	}

	/* Now for the asciiz. We lump it all in one chunk. */
	lims.asciiz_start = (char*) (lims.auxv_array_terminator + 1);
	/* On Linux there is normally a zero word at the end of asciiz, but
	 * we can't rely on this e.g. because of valgrind's user-mode exec,
	 * which does not add a zero word. */
	lims.asciiz_end = highest_asciiz_seen + strlen(highest_asciiz_seen) + 1;

	return lims;
}

static inline int my_strcmp(const char *str1, const char *str2)
{
	signed diff;
	while (1)
	{
		diff = *str1 - *str2;
		if (!*str1 || !*str2 || 0 != diff) break;
		++str1;
		++str2;
	}
	if (!*str1 && *str2) return -1;
	if (!*str2 && *str1) return 1;
	return diff;
}
static inline char *my_strchr(const char *s, int c)
{
	while (*s && *s != c) ++s;
	if (*s == c) return (char*) s;
	return NULL;
}
static inline char *environ_getenv(const char *name, char **environ)
{
	const char *var;
	while (NULL != (var = *(environ++)))
	{
		const char *equals_pos = my_strchr(var, '=');
		if (!equals_pos || equals_pos == var) continue; // weird string
		if (0 == my_strcmp(name, equals_pos - 1))
		{
			// hit!
			return (char*)(equals_pos + 1);
		}
	}
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
ElfW(Dyn) *dynamic_lookup(ElfW(Dyn) *d, ElfW(Sword) tag)
{
	for (ElfW(Dyn) *dyn = d; dyn->d_tag != DT_NULL; ++dyn)
	{
		if (dyn->d_tag == tag)
		{
			return dyn;
		}
	}
	return NULL;
}

static inline
ElfW(Dyn) *dynamic_xlookup(ElfW(Dyn) *dyn, ElfW(Sword) tag)
{
	ElfW(Dyn) *found = dynamic_lookup(dyn, tag);
	if (!found) __assert_fail("expected dynamic tag", __FILE__, __LINE__, __func__);
	return found;
}

static inline
ElfW(Dyn) *local_dynamic_xlookup(ElfW(Sword) tag)
{
	return dynamic_xlookup(_DYNAMIC, tag);
}

static inline 
unsigned long
elf64_hash(const unsigned char *name)
{
	uint64_t h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000))) h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

/* Straight from the System V GABI spec v4.1 */
static inline 
unsigned long
elf32_hash(const unsigned char *name)
{
	uint32_t h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000)))
		{
			h ^= g >> 24;
		}
		h &= ~g;
	}
	return h;
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
unsigned long dynamic_symbol_count_fast(ElfW(Sym) *dynsym, unsigned char *dynstr, ElfW(Word) *sysv_hash)
{
	if (sysv_hash) return sysv_hash[1];
	if (!dynsym || !dynstr) return 0;
	/* dynsym_nasty_hack */
	/* Take a wild guess, by assuming dynstr directly follows dynsym. */
	if (!((unsigned char *) dynstr > (unsigned char *) dynsym)) __assert_fail("dynstr position assumption", __FILE__, __LINE__, __func__);
	// round down, because dynsym might be padded
	return ((unsigned char *) dynstr - (unsigned char *) dynsym) / sizeof (ElfW(Sym));
}
static inline
unsigned long dynamic_symbol_count_from_dyn(ElfW(Dyn) *dyn, uintptr_t load_addr)
{
	ElfW(Word) *hash = get_sysv_hash_from_dyn(dyn, load_addr);
	if (hash) return dynamic_symbol_count_fast(NULL, NULL, hash);
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
ElfW(Sym) *hash_lookup(ElfW(Word) *hash, ElfW(Sym) *symtab, const unsigned char *strtab, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	ElfW(Word) nbucket = hash[0];
	ElfW(Word) nchain __attribute__((unused)) = hash[1];
	/* gcc accepts these funky "dependent types", but frontc doesn't */
	ElfW(Word) (*buckets)[/*nbucket*/] = (ElfW(Word)(*)[]) &hash[2];
	ElfW(Word) (*chains)[/*nchain*/] = (ElfW(Word)(*)[]) &hash[2 + nbucket];

	unsigned long h = elfw(hash)((const unsigned char *) sym);
	ElfW(Word) first_symind = (*buckets)[h % nbucket];
	ElfW(Word) symind = first_symind;
	for (; symind != STN_UNDEF; symind = (*chains)[symind])
	{
		ElfW(Sym) *p_sym = &symtab[symind];
		if (0 == strcmp((const char *) &strtab[p_sym->st_name], sym))
		{
			/* match! FIXME: symbol type filter, FIXME: versioning */
			found_sym = p_sym;
			break;
		}
	}
	
	return found_sym;
}

static inline
int hash_walk_syms(ElfW(Word) *hash, int (*cb)(ElfW(Sym) *, void *), ElfW(Sym) *symtab, void *arg)
{
	ElfW(Word) nbucket = hash[0];
	ElfW(Word) nchain __attribute__((unused)) = hash[1];
	ElfW(Word) (*buckets)[/*nbucket*/] = (ElfW(Word)(*)[]) &hash[2];
	ElfW(Word) (*chains)[/*nchain*/] = (ElfW(Word)(*)[]) &hash[2 + nbucket];

	for (unsigned bucketn = 0; bucketn < nbucket; ++bucketn)
	{
		for (ElfW(Word) symind = ((ElfW(Word) *)buckets)[bucketn]; 
				symind != STN_UNDEF; symind = (*chains)[symind])
		{
			ElfW(Sym) *p_sym = &symtab[symind];
			int ret = cb(p_sym, arg);
			if (ret) return ret;
			// else keep going
		}
	}
	return 0;
}

static inline uint_fast32_t
dl_new_hash(const char *s)
{
	uint_fast32_t h = 5381;
	for (unsigned char c = *s; c != '\0'; c = *++s)
	{
		h = h * 33 + c;
	}
	return h & 0xffffffff;
}

static inline
ElfW(Sym) *gnu_hash_lookup(ElfW(Word) *gnu_hash, ElfW(Sym) *symtab, const unsigned char *strtab, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	uint32_t hashval = dl_new_hash(sym);
	/* see: https://sourceware.org/ml/binutils/2006-10/msg00377.html */
	uint32_t *gnu_hash_words = (uint32_t *) gnu_hash;
	uint32_t nbuckets = gnu_hash_words[0];
	uint32_t symbias = gnu_hash_words[1]; // only symbols at symbias up are gnu_hash'd
	uint32_t maskwords = gnu_hash_words[2]; // number of ELFCLASS-sized words in pt2 of table
	uint32_t shift2 __attribute__((unused)) = gnu_hash_words[3];

	ElfW(Off) *bloom = (ElfW(Off) *) &gnu_hash_words[4];
	uint32_t *buckets = (uint32_t*) (bloom + maskwords);
	uint32_t *hasharr = buckets + nbuckets;
	
	
	/* Symbols in dynsyn (from symbias up) are sorted by ascending hash % nbuckets.
	 * The Bloom filter has k == 2, where the two different hash functions are
	 *   (1) the low-order 5 or 6 bits of dl_new_hash  (resp. on 32- and 64-bit ELF)
	 *   (2) the 5 or 6 bits starting from bit index `shift2' of the same. 
	 * 
	 * EXCEPT wait. both of these hash values are used to index the *same* word
	 * of the Bloom filter. So it's not one Bloom filter; it's a vector of one-word
	 * Bloom filters, of length `maskwords'. The particular word is extracted via

	  ElfW(Addr) bitmask_word
	    = bitmask[(new_hash / __ELF_NATIVE_CLASS)
		      & map->l_gnu_bitmask_idxbits]; // means maskwords - 1
	
	  meaning we wrap around: each word-sized Bloom filter covers a family of
	  hash values, each with varying low-order bits (we divide away the 5 or 6 lower bits)
	  but the same middle-order bits (the number depends on the choice of maskwords,
	  being some power of two; e.g. if we have 32 words, hashes with the same middle 
	  5 bits will be directed into the same word-sized Bloom filter).
	
	  Or I suppose you can think of this as one big Bloom filter where the two hash 
	  functions say:
	  
	  "take the high-and-middle-order bits of dl_new_hash,
	        append the low- (k==1) or somewhere-in-middle- (k==2) order 5 or 6 bits,
	        then look at the bottom ~14 bits of that" (for maskwords == 256 a.k.a. 2^8)
	
	  i.e. we've chosen shift2 and maskwords so that the middle-order bits we append
	  for the second hash function DON'T overlap with the high-and-middle-order
	  bits that we actually look at (bits 6..13 in the example above,
	  cf. shift2 which is 14, so positions 0..5 contain bits 14..19 of the dl_new_hash).
	  This does mean that the two hash values share their high-order bits (both are
	  bits 6..13 of the dl_new_hash value). I'm sure this increases the false-positive
	  rate of the Bloom filter, since for any given hashval, we hash it to the same
	  word of the filter. Oh well... we still have 32--64 bits to play with.
	
	  The Bloom filter has no correspondence with the bucket structure -- it just records
	  whether a given hash is (possibly) in the table or not.
	 */

	ElfW(Off) bloom_word
		= bloom[(hashval / (8*sizeof(ElfW(Off))))
				& (maskwords - 1)];

	unsigned int hash1_bitoff = hashval & (8*sizeof(ElfW(Off)) - 1);
	unsigned int hash2_bitoff = ((hashval >> shift2) & (8*sizeof(ElfW(Off)) - 1));

	if ((bloom_word >> hash1_bitoff) & 0x1 
			&& (bloom_word >> hash2_bitoff) & 0x1)
	{
		/* buckets are in the range 0..nbuckets.
		 * and bucket N contain the lowest M
		 * for which the hash % nbuckets of dynsym entry M's name
		 * equals N, or 0 for no such M.
		 * 
		 * The hash array (part four of the table) contains words such that word M
		 * is the hash of dynsyn N, with the low bit cleared,
		 * ORed with a new value for the low bit: 
		 * 1 if N is the maximum value (dynsymcount - 1)
		 *   or if symbol N was hashed into a different bucket than symbol N+1,
		 * 0 otherwise.
		 * 
		 * How do we use this array to walk a particular bucket?
		 * Recall that symbols in dynsym are sorted by ascending hash % nbuckets.
		 * In other words, they are grouped into ranges of equal hash % nbuckets already.
		 * The order in part four mirrors this ordering, but stores hashes (and one bit).
		 * So we basically want to walk this range of the array, from first to last.
		 * The low bit tells us when we've hit the end of the range.
		 * The bucket array tells us the starting index.
		 * Simples!
		 */
		
		uint32_t lowest_symidx = buckets[hashval % nbuckets]; // might be 0
		for (uint32_t symidx = lowest_symidx; 
				symidx; 
				symidx = (!(hasharr[symidx - symbias] & 1)) ? symidx + 1 : 0)
		{
			/* We know that hash-mod-nbuckets equals the right value,
			 * but what about the hash itself? Test this before we bother
			 * doing the full comparison. We have to live with not being
			 * able to test the lowest bit. */
			if (((hasharr[symidx - symbias] ^ hashval) >> 1) == 0)
			{
				if (0 == strcmp((const char *) &strtab[symtab[symidx].st_name], sym))
				{
					found_sym = &symtab[symidx];
					break;
				}
			}
		}
	}
	
	return found_sym;
}

static inline
int gnu_hash_walk_syms(ElfW(Word) *gnu_hash, int (*cb)(ElfW(Sym) *, void *), ElfW(Sym) *symtab, unsigned char *strtab, void *arg)
{
	uint32_t *gnu_hash_words = (uint32_t *) gnu_hash;
	uint32_t nbuckets = gnu_hash_words[0];
	uint32_t symbias = gnu_hash_words[1]; // only symbols at symbias up are gnu_hash'd
	uint32_t maskwords = gnu_hash_words[2]; // number of ELFCLASS-sized words in pt2 of table
	uint32_t shift2 __attribute__((unused)) = gnu_hash_words[3];

	ElfW(Off) *bloom = (ElfW(Off) *) &gnu_hash_words[4];
	uint32_t *buckets = (uint32_t*) (bloom + maskwords);
	uint32_t *hasharr __attribute__((unused)) = buckets + nbuckets;
	
	// uint32_t lowest_symidx = buckets[hashval % nbuckets]; // might be 0
	struct LINK_MAP_STRUCT_TAG *l = get_highest_loaded_object_below(gnu_hash);
	ElfW(Dyn) *d = (ElfW(Dyn) *) l->l_ld;
	unsigned symcount = dynamic_symbol_count_fast(symtab, strtab, NULL);
	for (uint32_t symidx = symbias; 
			symidx != symcount;
			symidx++)
	{
		/* We know that hash-mod-nbuckets equals the right value,
		 * but what about the hash itself? Test this before we bother
		 * doing the full comparison. We have to live with not being
		 * able to test the lowest bit. */
		int ret = cb(&symtab[symidx], arg);
		if (ret) return ret;
	}
	
	return 0;
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
ElfW(Sym) *symbol_lookup_linear(ElfW(Sym) *symtab, ElfW(Sym) *symtab_end,
	const unsigned char *strtab, const unsigned char *strtab_end, const char *sym)
{
	ElfW(Sym) *found_sym = NULL;
	for (ElfW(Sym) *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		signed long distance_to_strtab_end = strtab_end - &strtab[p_sym->st_name];
		if (distance_to_strtab_end > 0 &&
			0 == strncmp((const char*) &strtab[p_sym->st_name], sym, distance_to_strtab_end))
		{
			/* match */
			found_sym = p_sym;
			break;
		}
	}
	
	return found_sym;
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
