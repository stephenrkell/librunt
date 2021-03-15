#ifndef LIBRUNT_VAS_H_
#define LIBRUNT_VAS_H_

#define MINIMUM_USER_ADDRESS  ((char*)0x400000) /* FIXME: less {x86-64,GNU/Linux}-specific please */
#define MAXIMUM_USER_ADDRESS  ((char*)(0x800000000000ul-1)) /* FIXME: less {x86-64,GNU/Linux}-specific please */

#ifndef WORD_BITSIZE
#define WORD_BITSIZE ((sizeof (void*))<<3)
#endif

#if defined(__x86_64__) || defined(x86_64)
#define ADDR_BITSIZE 48
#else
#define ADDR_BITSIZE WORD_BITSIZE
#endif

/* The biggest virtual address that we might find in an executable image. */
// #define BIGGEST_SANE_EXECUTABLE_VADDR  (1ull<<31)
#define BIGGEST_SANE_USER_ALLOC ((1ull<<32)-1ull)

#define MAXPTR(a, b) \
	((((uintptr_t)(a)) > ((uintptr_t)(b))) ? (a) : (b))

#define MINPTR(a, b) \
	((((uintptr_t)(a)) < ((uintptr_t)(b))) ? (a) : (b))

#define MIN_PAGE_SIZE 4096 /* FIXME: this is sysdep */
#define COMMON_PAGE_SIZE 4096 /* FIXME: this is sysdep */
#define LOG_MIN_PAGE_SIZE 12
#define LOG_COMMON_PAGE_SIZE 12

#define PAGENUM(p) (((uintptr_t) (p)) >> LOG_MIN_PAGE_SIZE)
#define ADDR_OF_PAGENUM(p) ((const void *) ((p) << LOG_MIN_PAGE_SIZE))

/* FIXME: these shouldn't be named RELF_* any more, but
 * I can't remember what namespace collision prompted
 * me to use the protected names. */
#define RELF_ROUND_DOWN_(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * ((uintptr_t) (p) / (align))))
#define RELF_ROUND_UP_(p, align) \
	(((uintptr_t) (p)) % (align) == 0 ? ((uintptr_t) (p)) \
	: (uintptr_t) ((align) * (1 + ((uintptr_t) (p) / (align)))))
#define RELF_ROUND_DOWN_PTR_(p, align) \
	((void*) (RELF_ROUND_DOWN_((p), (align))))
#define RELF_ROUND_UP_PTR_(p, align) \
	((void*) (RELF_ROUND_UP_((p), (align))))

#ifndef ROUND_DOWN
#define ROUND_DOWN(p, align) RELF_ROUND_DOWN_(p, align)
#endif
#ifndef ROUND_UP
#define ROUND_UP(p, align) RELF_ROUND_UP_(p, align)
#endif
#ifndef ROUND_DOWN_PTR
#define ROUND_DOWN_PTR(p, align) RELF_ROUND_DOWN_PTR_(p, align)
#endif
#ifndef ROUND_UP_PTR
#define ROUND_UP_PTR(p, align) RELF_ROUND_UP_PTR_(p, align)
#endif

#ifndef ROUND_DOWN_PTR_TO_PAGE
#define ROUND_DOWN_PTR_TO_PAGE(p) ROUND_DOWN_PTR((p), MIN_PAGE_SIZE)
#endif
#ifndef ROUND_UP_PTR_TO_PAGE
#define ROUND_UP_PTR_TO_PAGE(p) ROUND_UP_PTR((p), MIN_PAGE_SIZE)
#endif

#endif
