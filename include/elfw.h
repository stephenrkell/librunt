#ifndef LIBRUNT_ELFW_H_
#define LIBRUNT_ELFW_H_

#ifndef __ELF_NATIVE_CLASS
#if defined(__x86_64__)
#define __ELF_NATIVE_CLASS 64
#define ELF_WORD_BITSIZE 64
#elif defined(__i386__)
#define __ELF_NATIVE_CLASS 32
#define ELF_WORD_BITSIZE 32
#else
#warning "Could not identify ELF native class; assuming ELF64"
#define __ELF_NATIVE_CLASS 64
#define we_defined_elf_native_class_
#endif
#else
// it's defined, and not by us, so use it
#define ELF_WORD_BITSIZE __ELF_NATIVE_CLASS
#endif

#ifndef ElfW
#define _ElfW_y(e,w,t)  e##w##t
#define _ElfW_x(e,w,t)  _ElfW_y(e, w, _##t)
#define ElfW(type)      _ElfW_x(Elf, __ELF_NATIVE_CLASS, type)
#endif

// same again but for lowercase identifier conventions
#ifndef elfw
#define _elfw_y(e,w,f)  e##w##f
#define _elfw_x(e,w,f)  _elfw_y(e, w, _##f)
#define elfw(frag)      _elfw_x(elf, __ELF_NATIVE_CLASS, frag)
#endif

/* Like ElfW() in link.h, but for the ELF{32,64}_ST_TYPE macros and similar. */
#define ELFW_ST_TYPE_y(p, enc) \
	ELF ## enc ## _ST_TYPE(p)
// pass-through dummy to actually substitute the "64" or "32", not paste tokens as given
#define ELFW_ST_TYPE_x(info, enc) \
	ELFW_ST_TYPE_y(info, enc)
// the actual macro we wanted to define
#define ELFW_ST_TYPE(info) \
	ELFW_ST_TYPE_x(info, __ELF_NATIVE_CLASS)

// same idea again
#define ELFW_ST_BIND_y(p, enc) \
	ELF ## enc ## _ST_BIND(p)
// pass-through dummy to actually substitute the "64" or "32", not paste tokens as given
#define ELFW_ST_BIND_x(info, enc) \
	ELFW_ST_BIND_y(info, enc)
// the actual macro we wanted to define
#define ELFW_ST_BIND(info) \
	ELFW_ST_BIND_x(info, __ELF_NATIVE_CLASS)

// same idea again
#define ELFW_ST_INFO_y(b, t, enc) \
	ELF ## enc ## _ST_INFO(b, t)
#define ELFW_ST_INFO_x(b, t, enc) \
	ELFW_ST_INFO_y(b, t, enc)
#define ELFW_ST_INFO(b, t) \
	ELFW_ST_INFO_x(b, t, __ELF_NATIVE_CLASS)

// and again
#define ELFW_R_TYPE_y(i, enc) \
	ELF ## enc ## _R_TYPE(i)
#define ELFW_R_TYPE_x(i, enc) \
	ELFW_R_TYPE_y(i, enc)
#define ELFW_R_TYPE(i) \
	ELFW_R_TYPE_x(i, __ELF_NATIVE_CLASS)
#define ELFW_R_SYM_y(i, enc) \
	ELF ## enc ## _R_SYM(i)
#define ELFW_R_SYM_x(i, enc) \
	ELFW_R_SYM_y(i, enc)
#define ELFW_R_SYM(i) \
	ELFW_R_SYM_x(i, __ELF_NATIVE_CLASS)

#if defined(we_defined_elf_native_class_)
#undef __ELF_NATIVE_CLASS
#endif

#endif
