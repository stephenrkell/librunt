#ifndef FELF_H_
#define FELF_H_

/* felf.h: helpers for working with ELF files.
 *
 * Unlike relf.h, routines in this file don't assume that the ELF file
 * in question is loaded (e.g. by the dynamic linker of the current process).
 * We could just be working as a tool on the file.
 *
 * Unlike relf.h, we don't use ElfW(...) because we might be
 * working on either bit-width, regardless of machine. Instead
 * we use C11 _Generic. We try to avoid repeating the bodies of
 * functions, for larger functions.
 */
#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#endif

#include <stddef.h> /* for offsetof */
#include <stdint.h>
#include <string.h>
#include <elf.h>

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

static inline
Elf32_Dyn *dynamic_lookup_32(Elf32_Dyn *d, Elf32_Sword tag)
{
	for (Elf32_Dyn *dyn = d; dyn->d_tag != DT_NULL; ++dyn)
	{
		if (dyn->d_tag == tag)
		{
			return dyn;
		}
	}
	return NULL;
}
static inline
Elf64_Dyn *dynamic_lookup_64(Elf64_Dyn *d, Elf64_Sword tag)
{
	for (Elf64_Dyn *dyn = d; dyn->d_tag != DT_NULL; ++dyn)
	{
		if (dyn->d_tag == tag)
		{
			return dyn;
		}
	}
	return NULL;
}
#define dynamic_lookup(d, tag)   _Generic( (d), \
   Elf32_Dyn* : dynamic_lookup_32, \
   Elf64_Dyn* : dynamic_lookup_64  ) \
   ((d), (tag))

static inline
Elf32_Dyn *dynamic_xlookup_32(Elf32_Dyn *dyn, Elf32_Sword tag)
{
	Elf32_Dyn *found = dynamic_lookup_32(dyn, tag);
	if (!found) __assert_fail("expected dynamic tag", __FILE__, __LINE__, __func__);
	return found;
}
static inline
Elf64_Dyn *dynamic_xlookup_64(Elf64_Dyn *dyn, Elf64_Sword tag)
{
	Elf64_Dyn *found = dynamic_lookup_64(dyn, tag);
	if (!found) __assert_fail("expected dynamic tag", __FILE__, __LINE__, __func__);
	return found;
}
#define dynamic_xlookup(d, tag)   _Generic( (d), \
   Elf32_Dyn* : dynamic_xlookup_32, \
   Elf64_Dyn* : dynamic_xlookup_64  ) \
   ((d), (tag))

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
unsigned long dynamic_symbol_count_fast_32(Elf32_Sym *dynsym, unsigned char *dynstr, Elf32_Word *sysv_hash)
{
	if (sysv_hash) return sysv_hash[1];
	if (!dynsym || !dynstr) return 0;
	/* dynsym_nasty_hack */
	/* Take a wild guess, by assuming dynstr directly follows dynsym. */
	if (!((uintptr_t) dynstr > (uintptr_t) dynsym)) __assert_fail("dynstr position assumption", __FILE__, __LINE__, __func__);
	// round down, because dynsym might be padded
	return ((unsigned char *) dynstr - (unsigned char *) dynsym) / sizeof (Elf32_Sym);
}
static inline
unsigned long dynamic_symbol_count_fast_64(Elf64_Sym *dynsym, unsigned char *dynstr, Elf64_Word *sysv_hash)
{
	if (sysv_hash) return sysv_hash[1];
	if (!dynsym || !dynstr) return 0;
	/* dynsym_nasty_hack */
	/* Take a wild guess, by assuming dynstr directly follows dynsym. */
	if (!((uintptr_t) dynstr > (uintptr_t) dynsym)) __assert_fail("dynstr position assumption", __FILE__, __LINE__, __func__);
	// round down, because dynsym might be padded
	return ((unsigned char *) dynstr - (unsigned char *) dynsym) / sizeof (Elf64_Sym);
}

#define dynamic_symbol_count_fast(dynsym, dynstr, sysv_hash)  _Generic( (dynsym), \
   Elf32_Sym* : dynamic_symbol_count_fast_32, \
   Elf64_Sym* : dynamic_symbol_count_fast_64  ) \
   ((dynsym), (dynstr), (sysv_hash))

#define elft32_(frag) Elf32_ ## frag
#define elft64_(frag) Elf64_ ## frag
#define elff32_(frag) elf32_ ## frag
#define elff64_(frag) elf64_ ## frag
#define hash_lookup_body_(tmac, fmac) \
{ \
	tmac(Sym) *found_sym = NULL; \
	tmac(Word) nbucket = hash[0]; \
	tmac(Word) nchain __attribute__((unused)) = hash[1]; \
	/* gcc accepts these funky "dependent types", but frontc doesn't */ \
	tmac(Word) (*buckets)[/*nbucket*/] = (tmac(Word)(*)[]) &hash[2]; \
	tmac(Word) (*chains)[/*nchain*/] = (tmac(Word)(*)[]) &hash[2 + nbucket]; \
 \
	unsigned long h = fmac(hash)((const unsigned char *) sym); \
	tmac(Word) first_symind = (*buckets)[h % nbucket]; \
	tmac(Word) symind = first_symind; \
	for (; symind != STN_UNDEF; symind = (*chains)[symind]) \
	{ \
		tmac(Sym) *p_sym = &symtab[symind]; \
		if (0 == strcmp((const char *) &strtab[p_sym->st_name], sym)) \
		{ \
			/* match! FIXME: symbol type filter, FIXME: versioning */ \
			found_sym = p_sym; \
			break; \
		} \
	} \
	 \
	return found_sym; \
}
static inline
Elf32_Sym *hash_lookup_32(Elf32_Word *hash, Elf32_Sym *symtab, const unsigned char *strtab, const char *sym)
hash_lookup_body_(elft32_, elff32_)
static inline
Elf64_Sym *hash_lookup_64(Elf64_Word *hash, Elf64_Sym *symtab, const unsigned char *strtab, const char *sym)
hash_lookup_body_(elft64_, elff64_)
#define hash_lookup(hash, symtab, strtab, sym)   _Generic( (symtab), \
   Elf32_Sym* : hash_lookup_32, \
   Elf64_Sym* : hash_lookup_64  ) \
   ((hash), (symtab), (strtab), (sym))

#define hash_walk_syms_body_(tmac) \
{ \
	tmac(Word) nbucket = hash[0]; \
	tmac(Word) nchain __attribute__((unused)) = hash[1]; \
	tmac(Word) (*buckets)[/*nbucket*/] = (tmac(Word)(*)[]) &hash[2]; \
	tmac(Word) (*chains)[/*nchain*/] = (tmac(Word)(*)[]) &hash[2 + nbucket]; \
 \
	for (unsigned bucketn = 0; bucketn < nbucket; ++bucketn) \
	{ \
		for (tmac(Word) symind = ((tmac(Word) *)buckets)[bucketn];  \
				symind != STN_UNDEF; symind = (*chains)[symind]) \
		{ \
			tmac(Sym) *p_sym = &symtab[symind]; \
			int ret = cb(p_sym, arg); \
			if (ret) return ret; \
			/* else keep going */ \
		} \
	} \
	return 0; \
}
static inline
int hash_walk_syms_32(Elf32_Word *hash, int (*cb)(Elf32_Sym *, void *), Elf32_Sym *symtab, void *arg) \
hash_walk_syms_body_(elft32_)
static inline
int hash_walk_syms_64(Elf64_Word *hash, int (*cb)(Elf64_Sym *, void *), Elf64_Sym *symtab, void *arg) \
hash_walk_syms_body_(elft64_)
#define hash_walk_syms(h, cb, symtab, arg)   _Generic( (symtab), \
   Elf32_Sym* : hash_walk_syms_32, \
   Elf64_Sym* : hash_walk_syms_64  ) \
   ((h), (cb), (symtab), (arg))

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

#define gnu_hash_lookup_body_(tmac) \
{ \
	tmac(Sym) *found_sym = NULL; \
	uint32_t hashval = dl_new_hash(sym); \
	/* see: https://sourceware.org/ml/binutils/2006-10/msg00377.html */ \
	uint32_t *gnu_hash_words = (uint32_t *) gnu_hash; \
	uint32_t nbuckets = gnu_hash_words[0]; \
	uint32_t symbias = gnu_hash_words[1]; /* only symbols at symbias up are gnu_hash'd */ \
	uint32_t maskwords = gnu_hash_words[2]; /* number of ELFCLASS-sized words in pt2 of table */ \
	uint32_t shift2 __attribute__((unused)) = gnu_hash_words[3]; \
 \
	tmac(Off) *bloom = (tmac(Off) *) &gnu_hash_words[4]; \
	uint32_t *buckets = (uint32_t*) (bloom + maskwords); \
	uint32_t *hasharr = buckets + nbuckets; \
	 \
	 \
	/* Symbols in dynsyn (from symbias up) are sorted by ascending hash % nbuckets. */ \
	/* The Bloom filter has k == 2, where the two different hash functions are      */ \
	/*   (1) the low-order 5 or 6 bits of dl_new_hash  (resp. on 32- and 64-bit ELF) */ \
	/*   (2) the 5 or 6 bits starting from bit index `shift2' of the same.  */ \
	/*  */ \
	/* EXCEPT wait. both of these hash values are used to index the *same* word */ \
	/* of the Bloom filter. So it's not one Bloom filter; it's a vector of one-word */ \
	/* Bloom filters, of length `maskwords'. The particular word is extracted via */ \
 \
	 /*ElfW(Addr) bitmask_word */ \
	   /*= bitmask[(new_hash / __ELF_NATIVE_CLASS) */ \
		     /*& map->l_gnu_bitmask_idxbits]; // means maskwords - 1 */ \
	 \
	 /*meaning we wrap around: each word-sized Bloom filter covers a family of */ \
	 /*hash values, each with varying low-order bits (we divide away the 5 or 6 lower bits) */ \
	 /*but the same middle-order bits (the number depends on the choice of maskwords, */ \
	 /*being some power of two; e.g. if we have 32 words, hashes with the same middle  */ \
	 /*5 bits will be directed into the same word-sized Bloom filter). */ \
	 \
	 /*Or I suppose you can think of this as one big Bloom filter where the two hash  */ \
	 /*functions say: */ \
	 \
	 /*"take the high-and-middle-order bits of dl_new_hash, */ \
	       /*append the low- (k==1) or somewhere-in-middle- (k==2) order 5 or 6 bits, */ \
	       /*then look at the bottom ~14 bits of that" (for maskwords == 256 a.k.a. 2^8) */ \
	 \
	 /*i.e. we've chosen shift2 and maskwords so that the middle-order bits we append */ \
	 /*for the second hash function DON'T overlap with the high-and-middle-order */ \
	 /*bits that we actually look at (bits 6..13 in the example above, */ \
	 /*cf. shift2 which is 14, so positions 0..5 contain bits 14..19 of the dl_new_hash). */ \
	 /*This does mean that the two hash values share their high-order bits (both are */ \
	 /*bits 6..13 of the dl_new_hash value). I'm sure this increases the false-positive */ \
	 /*rate of the Bloom filter, since for any given hashval, we hash it to the same */ \
	 /*word of the filter. Oh well... we still have 32--64 bits to play with. */ \
	 \
	 /*The Bloom filter has no correspondence with the bucket structure -- it just records */ \
	 /*whether a given hash is (possibly) in the table or not. */ \
	\
 \
	tmac(Off) bloom_word \
		= bloom[(hashval / (8*sizeof(tmac(Off)))) \
				& (maskwords - 1)]; \
 \
	unsigned int hash1_bitoff = hashval & (8*sizeof(tmac(Off)) - 1); \
	unsigned int hash2_bitoff = ((hashval >> shift2) & (8*sizeof(tmac(Off)) - 1)); \
 \
	if ((bloom_word >> hash1_bitoff) & 0x1  \
			&& (bloom_word >> hash2_bitoff) & 0x1) \
	{ \
		/* buckets are in the range 0..nbuckets.*/ \
		/* and bucket N contain the lowest M*/ \
		/* for which the hash % nbuckets of dynsym entry M's name*/ \
		/* equals N, or 0 for no such M.*/ \
		 \
		/* The hash array (part four of the table) contains words such that word M*/ \
		/* is the hash of dynsyn N, with the low bit cleared,*/ \
		/* ORed with a new value for the low bit: */ \
		/* 1 if N is the maximum value (dynsymcount - 1)*/ \
		/*   or if symbol N was hashed into a different bucket than symbol N+1,*/ \
		/* 0 otherwise.*/ \
		 \
		/* How do we use this array to walk a particular bucket?*/ \
		/* Recall that symbols in dynsym are sorted by ascending hash % nbuckets.*/ \
		/* In other words, they are grouped into ranges of equal hash % nbuckets already.*/ \
		/* The order in part four mirrors this ordering, but stores hashes (and one bit).*/ \
		/* So we basically want to walk this range of the array, from first to last.*/ \
		/* The low bit tells us when we've hit the end of the range.*/ \
		/* The bucket array tells us the starting index.*/ \
		/* Simples!*/ \
		 \
		 \
		uint32_t lowest_symidx = buckets[hashval % nbuckets]; /* might be 0 */ \
		for (uint32_t symidx = lowest_symidx;  \
				symidx;  \
				symidx = (!(hasharr[symidx - symbias] & 1)) ? symidx + 1 : 0) \
		{ \
			/* We know that hash-mod-nbuckets equals the right value, */ \
			/* but what about the hash itself? Test this before we bother */ \
			/* doing the full comparison. We have to live with not being */ \
			/* able to test the lowest bit. */ \
			if (((hasharr[symidx - symbias] ^ hashval) >> 1) == 0) \
			{ \
				if (0 == strcmp((const char *) &strtab[symtab[symidx].st_name], sym)) \
				{ \
					found_sym = &symtab[symidx]; \
					break; \
				} \
			} \
		} \
	} \
	 \
	return found_sym; \
}
static inline
Elf32_Sym *gnu_hash_lookup_32(Elf32_Word *gnu_hash, Elf32_Sym *symtab, const unsigned char *strtab, const char *sym)
gnu_hash_lookup_body_(elft32_)
static inline
Elf64_Sym *gnu_hash_lookup_64(Elf64_Word *gnu_hash, Elf64_Sym *symtab, const unsigned char *strtab, const char *sym)
gnu_hash_lookup_body_(elft64_)
#define gnu_hash_lookup(gnu_hash, symtab, strtab, sym)   _Generic( (symtab), \
   Elf32_Sym* : gnu_hash_lookup_32, \
   Elf64_Sym* : gnu_hash_lookup_64 ) \
   ((gnu_hash), (symtab), (strtab), (sym))

#define gnu_hash_walk_syms_body_(tmac) \
{ \
	uint32_t *gnu_hash_words = (uint32_t *) gnu_hash; \
	uint32_t nbuckets = gnu_hash_words[0]; \
	uint32_t symbias = gnu_hash_words[1]; /* only symbols at symbias up are gnu_hash'd */ \
	uint32_t maskwords = gnu_hash_words[2]; /* number of ELFCLASS-sized words in pt2 of table */ \
	uint32_t shift2 __attribute__((unused)) = gnu_hash_words[3]; \
 \
	tmac(Off) *bloom = (tmac(Off) *) &gnu_hash_words[4]; \
	uint32_t *buckets = (uint32_t*) (bloom + maskwords); \
	uint32_t *hasharr __attribute__((unused)) = buckets + nbuckets; \
 \
	unsigned symcount = dynamic_symbol_count_fast(symtab, strtab, NULL); \
	for (uint32_t symidx = symbias;  \
			symidx != symcount; \
			symidx++) \
	{ \
		/* We know that hash-mod-nbuckets equals the right value, */ \
		/* but what about the hash itself? Test this before we bother */ \
		/* doing the full comparison. We have to live with not being */ \
		/* able to test the lowest bit. */ \
		int ret = cb(&symtab[symidx], arg); \
		if (ret) return ret; \
	} \
	 \
	return 0; \
}
static inline
int gnu_hash_walk_syms_32(Elf32_Word *gnu_hash, int (*cb)(Elf32_Sym *, void *), Elf32_Sym *symtab, unsigned char *strtab, void *arg)
gnu_hash_walk_syms_body_(elft32_)
static inline
int gnu_hash_walk_syms_64(Elf64_Word *gnu_hash, int (*cb)(Elf64_Sym *, void *), Elf64_Sym *symtab, unsigned char *strtab, void *arg)
gnu_hash_walk_syms_body_(elft64_)
#define gnu_hash_walk_syms(gnu_hash, cb, symtab, strtab, arg)   _Generic( (symtab), \
   Elf32_Sym* : gnu_hash_walk_syms_32, \
   Elf64_Sym* : gnu_hash_walk_syms_64 ) \
   ((gnu_hash), (cb), (symtab), (strtab), (arg))

static inline
Elf32_Sym *symbol_lookup_linear_32(Elf32_Sym *symtab, Elf32_Sym *symtab_end,
	const unsigned char *strtab, const unsigned char *strtab_end, const char *sym)
{
	Elf32_Sym *found_sym = NULL;
	for (Elf32_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
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
Elf64_Sym *symbol_lookup_linear_64(Elf64_Sym *symtab, Elf64_Sym *symtab_end,
	const unsigned char *strtab, const unsigned char *strtab_end, const char *sym)
{
	Elf64_Sym *found_sym = NULL;
	for (Elf64_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
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
#define symbol_lookup_linear(symtab, symtab_end, strtab, strtab_end, sym) _Generic( (symtab), \
   Elf32_Sym* : symbol_lookup_linear_32, \
   Elf64_Sym* : symbol_lookup_linear_64 ) \
   ((symtab), (symtab_end), (strtab), (strtab_end), (sym))

static inline
Elf32_Sym *symbol_lookup_linear_by_vaddr_greatest_le_32(Elf32_Sym *symtab, Elf32_Sym *symtab_end,
	unsigned long long vaddr)
{
	Elf32_Sym *found_greatest_le = NULL;
	for (Elf32_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		if (p_sym->st_value <= vaddr &&
				(!found_greatest_le || found_greatest_le->st_value < p_sym->st_value))
		{
			/* match */
			found_greatest_le = p_sym;
			if (found_greatest_le->st_value == vaddr) break; // can't do better than an exact hit
		}
	}
	return found_greatest_le;
}

static inline
Elf64_Sym *symbol_lookup_linear_by_vaddr_greatest_le_64(Elf64_Sym *symtab, Elf64_Sym *symtab_end,
	unsigned long long vaddr)
{
	Elf64_Sym *found_greatest_le = NULL;
	for (Elf64_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		if (p_sym->st_value <= vaddr &&
				(!found_greatest_le || found_greatest_le->st_value < p_sym->st_value))
		{
			/* match */
			found_greatest_le = p_sym;
			if (found_greatest_le->st_value == vaddr) break; // can't do better than an exact hit
		}
	}
	return found_greatest_le;
}
#define symbol_lookup_linear_by_vaddr_greatest_le(symtab, symtab_end, vaddr) _Generic( (symtab), \
   Elf32_Sym* : symbol_lookup_linear_by_vaddr_greatest_le_32, \
   Elf64_Sym* : symbol_lookup_linear_by_vaddr_greatest_le_64 ) \
   ((symtab), (symtab_end), (vaddr))

static inline
Elf32_Sym *symbol_lookup_linear_by_vaddr_contained_32(Elf32_Sym *symtab, Elf32_Sym *symtab_end,
	unsigned long long vaddr)
{
	Elf32_Sym *found_containing = NULL;
	for (Elf32_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		if (p_sym->st_value <= vaddr && p_sym->st_value + p_sym->st_size > vaddr)
		{
			/* match */
			found_containing = p_sym;
			break;
		}
	}
	return found_containing;
}
static inline
Elf64_Sym *symbol_lookup_linear_by_vaddr_contained_64(Elf64_Sym *symtab, Elf64_Sym *symtab_end,
	unsigned long long vaddr)
{
	Elf64_Sym *found_containing = NULL;
	for (Elf64_Sym *p_sym = &symtab[0]; p_sym <= symtab_end; ++p_sym)
	{
		if (p_sym->st_value <= vaddr && p_sym->st_value + p_sym->st_size > vaddr)
		{
			/* match */
			found_containing = p_sym;
			break;
		}
	}
	return found_containing;
}
#define symbol_lookup_linear_by_vaddr_contained(symtab, symtab_end, vaddr) _Generic( (symtab), \
   Elf32_Sym* : symbol_lookup_linear_by_vaddr_contained_32, \
   Elf64_Sym* : symbol_lookup_linear_by_vaddr_contained_64 ) \
   ((symtab), (symtab_end), (vaddr))


	/* Given a file for which we have the ELF header (just the value)
	 * and program headers (don't assume they must be mapped?),
	 * get the symbol tables, string tables, section headers, GNU build ID,
	 * dynamic section, ...
	 *
	 * Is one big visitor a good API? It deals with the fact that one thing can
	 * point to another.
	 *
	 * But why stop with the above choices of metadata? e.g. why not relocations?
	 * Maybe we should be defining a "follow" predicate? Each thing we visit
	 * can have some defined "what to follow" which will prnue the exploration.
	 *
	 * This is a lot like exploration of a graph, whether breadth-first or
	 * depth-first, with some custom predicate over which nodes or edges to explore.
	 *
	 * Why require the ehdr and phdrs? Just read the ehdr using get_or_map cb and
	 * work from there? */
	enum {
		ELF_VISIT_EHDR = 1 << 0,
		ELF_VISIT_PHDRS = 1 << 1,
		ELF_VISIT_SHDRS = 1 << 2, /* if you want the names, you have to snarf e_shstrndx from the ehdr */
		ELF_VISIT_DYNAMIC = 1 << 3,
		ELF_VISIT_DYNSYM = 1 << 4, /* if you want the string table, you have to snarf the dynamic section */
		ELF_VISIT_SYMTAB = 1 << 5, /* if you want the string table, you have to snarf the shdrs */
		ELF_VISIT_DYNREL = 1 << 6,
		ELF_VISIT_REL = 1 << 7,
		ELF_VISIT_BUILD_ID = 1 << 8 /* ,
			ELF_VISIT_PROGBITS,
			ELF_VISIT_NOBITS, ...?
			Maybe we should just let it visit the section headers,
			and if the section contents are of interest, the callback
			can act then.
		*/
	};
	// XXX: don't want to use ElfW here!
	typedef long elf_visit_cb_32(unsigned long kind, void *data, size_t datasz, Elf32_Off fileoff, Elf32_Addr vaddr, Elf32_Shdr *shdr_if_applicable, void *auxdata_if_applicable, void *arg);
	typedef long elf_visit_cb_64(unsigned long kind, void *data, size_t datasz, Elf64_Off fileoff, Elf64_Addr vaddr, Elf64_Shdr *shdr_if_applicable, void *auxdata_if_applicable, void *arg);
	typedef void *elf_get_or_map_cb(off_t fileoff, size_t len, void *arg);

static inline long
visit_elf_64(unsigned long to_visit, elf_visit_cb_64 *visit_cb, void *visit_arg, elf_get_or_map_cb *get_or_map, void *get_or_map_arg)
{
	/* Traverse what we know how to traverse, calling the callback if the user has so requested. */
	
	/* 0. ELF header */
	Elf64_Ehdr *ehdr = get_or_map(0, /*PAGE_SIZE*//*sysconf(_SC_PAGE_SIZE)*/ 4096, get_or_map_arg);
	if (!ehdr) return -ELF_VISIT_EHDR;
	if (to_visit & ELF_VISIT_EHDR) visit_cb(ELF_VISIT_EHDR, ehdr, ehdr->e_ehsize, 0, (Elf64_Addr)-1, NULL, NULL, visit_arg);

	/* 1. program headers */
	Elf64_Phdr *phdrs = get_or_map(ehdr->e_phoff, ehdr->e_phnum * ehdr->e_phentsize, get_or_map_arg);
	// XX: bootstrapping problem: get_or_map is supposed to know what is mapped already.
	// but the phdrs, for a loaded object, are already mapped, yet we don't know what addresses
	// that consists of. so we can't know whether we need to map. Need another way to start things off?
	// Actually I think that knowledge can live in get_or_map. It is primed with the program headers
	// out-of-band. That can be via a copy, whereas the pointer we get above is always to a mapping.

	if (!phdrs) return -ELF_VISIT_PHDRS;
	if (to_visit & ELF_VISIT_PHDRS) visit_cb(ELF_VISIT_PHDRS, phdrs, ehdr->e_phnum * ehdr->e_phentsize, ehdr->e_phoff, (Elf64_Addr)-1, NULL, ehdr, visit_arg);

	/* 2. section headers */
	Elf64_Shdr *shdrs = get_or_map(ehdr->e_shoff, ehdr->e_shnum * ehdr->e_shentsize, get_or_map_arg);
	if (!shdrs) return -ELF_VISIT_SHDRS;
	// we pull out shstrtab data as the auxdata
	char *shstrtab = ehdr->e_shstrndx ? get_or_map(shdrs[ehdr->e_shstrndx].sh_offset, shdrs[ehdr->e_shstrndx].sh_size, get_or_map_arg) : NULL;
	if (to_visit & ELF_VISIT_SHDRS) visit_cb(ELF_VISIT_SHDRS, shdrs, ehdr->e_shnum * ehdr->e_shentsize, ehdr->e_shoff, (Elf64_Addr)-1, &shdrs[ehdr->e_shstrndx], ehdr, visit_arg);

	/* 3. dynamic section */
#define find_shdr_of_type(t) \
    ({ Elf64_Shdr *shdr = NULL; \
       for (unsigned i = 1; i < ehdr->e_shnum; ++i) { \
         if (shdrs[i].sh_type == (t)) { shdr = &shdrs[i]; break; } \
       }; shdr; })
	Elf64_Shdr *dyn_shdr = find_shdr_of_type(SHT_DYNAMIC);
	if (dyn_shdr && (to_visit & ELF_VISIT_DYNAMIC))
	{
		Elf64_Dyn *dyn = get_or_map(dyn_shdr->sh_offset, dyn_shdr->sh_size, get_or_map_arg);
		visit_cb(ELF_VISIT_DYNAMIC, dyn, dyn_shdr->sh_size, dyn_shdr->sh_offset, dyn_shdr->sh_addr, dyn_shdr, NULL, visit_arg);
	}

	Elf64_Shdr *dynsym_shdr = find_shdr_of_type(SHT_DYNSYM);
	if (dynsym_shdr && (to_visit & ELF_VISIT_DYNSYM))
	{
		Elf64_Shdr* dynstr_shdr = &shdrs[dynsym_shdr->sh_link];
		char *dynstr = get_or_map(dynstr_shdr->sh_offset, dynstr_shdr->sh_size, get_or_map_arg);
		Elf64_Sym *dynsym = get_or_map(dynsym_shdr->sh_offset, dynsym_shdr->sh_size, get_or_map_arg);
		visit_cb(ELF_VISIT_DYNSYM, dynsym, dynsym_shdr->sh_size, dynsym_shdr->sh_offset, dynsym_shdr->sh_addr, dynsym_shdr, dynstr, visit_arg);
	}

	Elf64_Shdr *symtab_shdr = find_shdr_of_type(SHT_SYMTAB);
	if (symtab_shdr && (to_visit & ELF_VISIT_SYMTAB))
	{
		Elf64_Shdr* strtab_shdr = &shdrs[symtab_shdr->sh_link];
		char *strtab = get_or_map(strtab_shdr->sh_offset, strtab_shdr->sh_size, get_or_map_arg) ;
		Elf64_Sym *symtab = get_or_map(symtab_shdr->sh_offset, symtab_shdr->sh_size, get_or_map_arg);
		visit_cb(ELF_VISIT_SYMTAB, symtab, symtab_shdr->sh_size, symtab_shdr->sh_offset, symtab_shdr->sh_addr, symtab_shdr, strtab, visit_arg);
	}

	// FIXME: do rel

	/* Now we have shstrtab if there is one. Re-scan for any section we can
	 * only recognise by name. */
	if (shstrtab)
	{
	#define find_shdr_of_name(n) \
    ({ Elf64_Shdr *shdr = NULL; \
       for (unsigned i = 1; i < ehdr->e_shnum; ++i) { \
         if (0 == strcmp(&shstrtab[shdrs[i].sh_name], (n))){ shdr = &shdrs[i]; break; } \
       }; shdr; })
		Elf64_Shdr *build_id_shdr = find_shdr_of_name(".note.gnu.build-id");
		if (build_id_shdr->sh_type == SHT_NOTE
				 && ELF_VISIT_BUILD_ID)
		{
			unsigned char *build_id_data = get_or_map(build_id_shdr->sh_offset, build_id_shdr->sh_size, get_or_map_arg);
			visit_cb(ELF_VISIT_BUILD_ID, build_id_data, build_id_shdr->sh_size, build_id_shdr->sh_offset, build_id_shdr->sh_addr, build_id_shdr, NULL, visit_arg);
		}
	}
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* FELF_H_ */
