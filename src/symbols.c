#define _GNU_SOURCE
#include <assert.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <limits.h>
#include <link.h>
#include "relf.h"
#include "librunt_private.h"
#include "dso-meta.h"

static _Bool trying_to_initialize;
static _Bool initialized;
void __runt_symbols_init(void) __attribute__((constructor(102)));
void __runt_symbols_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		trying_to_initialize = 1;
		/* Initialize what we depend on. */
		__runt_segments_init();
		__runt_sections_init();
		initialized = 1;
		trying_to_initialize = 0;
	}
}

/* FIXME: invalidate cache entries on dlclose().
 * FIXME: get rid of this cache. Integrate the dladdr cache into the usual memrange cache
 * and/or the new static file/symbol alloc metadata. That means this code can probably
 * move back to liballocs. Also we should change the name from dladdr_with_cache...
 * the main utility of this function is that it returns the struct directly, so can be
 * called from a debugger. */
#ifndef DLADDR_CACHE_SIZE
#define DLADDR_CACHE_SIZE 16
#endif
struct dladdr_cache_rec { const void *addr; Dl_info info; };
static struct dladdr_cache_rec dladdr_cache[DLADDR_CACHE_SIZE];
static unsigned dladdr_cache_next_free;

Dl_info dladdr_with_cache(const void *addr); // __attribute__((visibility("protected")));
Dl_info dladdr_with_cache(const void *addr)
{
	for (unsigned i = 0; i < DLADDR_CACHE_SIZE; ++i)
	{
		if (dladdr_cache[i].addr)
		{
			if (dladdr_cache[i].addr == addr)
			{
				/* This entry is useful, so maximise #misses before we recycle it. */
				dladdr_cache_next_free = (i + 1) % DLADDR_CACHE_SIZE;
				return dladdr_cache[i].info;
			}
		}
	}
	Dl_info info;
	int ret = dladdr(addr, &info);
	assert(ret != 0);

	/* always cache the dladdr result */
	dladdr_cache[dladdr_cache_next_free++] = (struct dladdr_cache_rec) { addr, info };
	if (dladdr_cache_next_free == DLADDR_CACHE_SIZE)
	{
		debug_printf(5, "dladdr cache wrapped around\n");
		dladdr_cache_next_free = 0;
	}
	return info;
}
