#ifndef LIBRUNT_PRIVATE_H_
#define LIBRUNT_PRIVATE_H_

#include <stdio.h>
#include "librunt.h"
#include "vas.h"

struct link_map;

extern void *(*orig_dlopen)(const char *, int) __attribute__((visibility("hidden")));

char *get_exe_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_basename(void) __attribute__((visibility("hidden")));
char *realpath_quick(const char *arg) __attribute__((visibility("hidden")));

void init_early_libs(void) __attribute__((visibility("hidden")));

extern int __librunt_debug_level;
extern FILE *stream_err;
#define debug_printf(lvl, fmt, ...) do { \
    if ((lvl) <= __librunt_debug_level) { \
      fprintf(stream_err, "%s: " fmt, get_exe_basename(), ## __VA_ARGS__ );  \
    } \
  } while (0)

void *__private_malloc(size_t sz);
void __private_free(void *ptr);
char *__private_strdup(const char *s);

#define MAX_EARLY_LIBS 128
extern struct link_map *early_lib_handles[MAX_EARLY_LIBS] __attribute((visibility("hidden")));

/* Convenience for code that does raw mmap. */
#ifndef MMAP_RETURN_IS_ERROR
#define MMAP_RETURN_IS_ERROR(p) \
        (((uintptr_t)(void*)-1 - (uintptr_t)(p)) < MIN_PAGE_SIZE)
#endif

const char *fmt_hex_num(unsigned long n) __attribute__((visibility("hidden")));

#endif
