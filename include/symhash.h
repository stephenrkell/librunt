#ifndef LIBRUNT_SYMHASH_H_
#define LIBRUNT_SYMHASH_H_

#include <elf.h>
#include <assert.h>

/* Mutable implementation of the ELF SysV symbol hash table.
 * 
 * The table is fixed-size, for now, and uses an upper-bound
 * on the symtab size.
 *
 * This is mainly used in libdlbind right now. Note that there 
 * is no public look-up function! In the libdlbind use case, use
 * dlsym(). However, there are lookup routines in relf.h.
 */

static inline
unsigned long
elf64_sysv_hash(const unsigned char *name)
{
	unsigned long h = 0, g;
	while (*name)
	{
		h = (h << 4) + *name++;
		if (0 != (g = (h & 0xf0000000))) h ^= g >> 24;
		h &= 0x0fffffff;
	}
	return h;
}

static inline
void
elf64_sysv_hash_chain_sym(Elf64_Word *buckets,
		unsigned nbucket,
		unsigned nchain,
		const char *name,
		unsigned symind
		)
{
	assert(name[0] != '\0');
	
	/* Which bucket does the sym go in? */
	unsigned bucket = elf64_sysv_hash(name) % nbucket;
	/* Find a place to chain it */
	Elf64_Word *pos = &buckets[bucket];
	while (*pos != STN_UNDEF)
	{
		pos = &buckets[nbucket + *pos];
	}
	*pos = symind;
}

static inline
unsigned
elf64_sysv_hash_bucket_lookup(Elf64_Word *buckets,
		unsigned nbucket,
		unsigned nchain,
		const char *name,
		Elf64_Sym *symtab,
		const char *strtab
		)
{
	/* Which bucket does the sym go in? */
	unsigned bucket = elf64_sysv_hash(name) % nbucket;
	Elf64_Word *chain = buckets + nbucket;
	/* Find it */
	Elf64_Word *pos = &buckets[bucket];
	for (Elf64_Word *pos = &buckets[bucket]; *pos != STN_UNDEF; pos = &chain[*pos])
	{
		unsigned stroff = symtab[*pos].st_name;
		if (0 == strcmp(strtab + stroff, name)) return *pos;
	}
	return STN_UNDEF;
}

static inline
void
elf64_sysv_hash_put(
	char *section,            /* has section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,         /* nbucket -- must match existing section! */
	unsigned nsyms,           /* symbol table entry count */
	Elf64_Sym *symtab,    /* symbol table */
	const char *strtab,
	unsigned symind           /* assume this symind was unused previously! */
	)
{
	const char *key = &strtab[symtab[symind].st_name];
	
	// the empty string is always in the table
	if (*key == '\0') return;
	
	/* Assert that symname is not currently used */
	Elf64_Word *words = (Elf64_Word *) section;
	Elf64_Word *buckets = words + 2;
	assert(STN_UNDEF == elf64_sysv_bucket_lookup(buckets,
			nbucket,
			nsyms, /* nchain is nsyms */
			key,
			symtab,
			strtab
		)
	);
	
	/* Assert that symind is not in the table. */
	
	
	/* Chain it. */
	elf64_sysv_hash_chain_sym(buckets, nbucket, nsyms, key, symind);
}

static inline void
elf64_sysv_hash_init(
	char *section,            /* hash section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,          /* nbucket */
	unsigned nsyms,
	Elf64_Sym *symtab /* [nsyms] */,
	const char *strtab
	)
{
	/* nchain is nsyms */
	Elf64_Word *words = (Elf64_Word *) section;
	words[0] = nbucket;
	words[1] = nsyms; // i.e. nchain
	for (unsigned i = 1; i < nsyms; ++i)
	{
		const char *symname = &strtab[symtab[i].st_name];
		elf64_sysv_hash_put(section, size, nbucket, nsyms, symtab, strtab, i);
	}
}

static inline
Elf64_Sym *
elf64_sysv_hash_get(
	char *section,            /* has section */
	size_t size,              /* hash section size in bytes */
	unsigned nbucket,         /* nbucket -- must match existing section! */
	unsigned nsyms,           /* symbol table entry count */
	Elf64_Sym *symtab,    /* symbol table */
	const char *strtab,
	const char *key
	)
{	
	/* nchain is nsyms */
	Elf64_Word *words = (Elf64_Word *) section;
	/* Assert that symname is not currently used */
	unsigned pos = elf64_sysv_hash_bucket_lookup(&words[2],
			nbucket,
			nsyms,
			key,
			symtab,
			strtab
		);
	if (pos == STN_UNDEF) return NULL;
	else return symtab + pos;
}

// elf_hash_del(


#endif
