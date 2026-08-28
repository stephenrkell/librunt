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

#ifdef __cplusplus
}
#endif

#endif /* FELF_H_ */
