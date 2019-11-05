#ifndef LIBALLOCS_ALLOCMETA_DEFS_H_
#define LIBALLOCS_ALLOCMETA_DEFS_H_

struct uniqtype;
struct allocsite_entry
{
	unsigned long allocsite_vaddr;
	struct uniqtype *uniqtype;
};
struct frame_allocsite_entry
{
	unsigned offset_from_frame_base;
	struct allocsite_entry entry;
};

/* To test for a null (terminator) entry is tricky -- static-alloc names 
 * and addresses are all allowed to be null, as are the prev and/or next
 * pointers. But we shouldn't have *everything* be null except in a real
 * terminator entry. */
#define STATIC_ALLOCSITE_IS_NULL(p_ent) \
	(!(p_ent)->entry.allocsite && !(p_ent)->name)

/* This is basically our supplement to the stuff we can access
 * from the struct link_map entries in the ld.so. There is some
 * duplication, mainly because we don't want to depend on impl-
 * -specific stuff in there. */
#define _sym_or_reloc_kind(v, last_v) \
 v(REC_DYNSYM, 0) /* in the dynsym of the base object */ \
 v(REC_EXTRASYM, 1) /* extra symbols in the meta-object, generated by tools/extrasyms */ \
 v(REC_SYMTAB, 2) /* in the (static) symtab of the base object */ \
 v(REC_RELOC_DYN, 3) /* in the dynamic relocs of the base object */ \
 v(REC_RELOC, 4) /* in the (static) relocs re-emitted in the base object (if linked -Wl,-q) */ \
 last_v(REC_UNKNOWN, 0x8000)
#define _sym_or_reloc_kind_v(tok, n) tok = n,
#define _sym_or_reloc_kind_last_v(tok, n) tok = n
enum sym_or_reloc_kind
{
	_sym_or_reloc_kind(_sym_or_reloc_kind_v, _sym_or_reloc_kind_last_v)
};
#undef _sym_or_reloc_kind_v
#undef _sym_or_reloc_kind_last_v
/* We can pack all this into a single 64-bit word. But we can't declare
 * such structs statically in C, because we lack the relocs for the 44-bit
 * pointer field. We can do it in assembly, by factoring the 'kind' and 
 * 'idx' into the addend.
 *
 * Is this optimisation worth it? Potentially yes. We have one of these
 * records for every distinct string literal. Spending 16 bytes on each
 * could easily waste hundreds of kilobytes. These are not shareable
 * between processes. */
struct sym_or_reloc_rec // FIXME: check this matches the layout we get from the assembler
{
	unsigned kind:3; // an instance of sym_or_reloc_kind
	unsigned long uniqtype_ptr_bits_no_lowbits:44; // an address whose low-order 3 bits are 0
	unsigned idx:17; // at most 128K symbols of each kind, per segment
};
#define SYM_OR_RELOC_REC_WORD(kind, idx_as_unsigned_long, ptr_as_integer_incl_lowbits) \
	(((idx_as_unsigned_long) << 47) + (ptr_as_integer_incl_lowbits) + ((kind) & 0x7))

#endif
