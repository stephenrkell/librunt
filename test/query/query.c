#define GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include "librunt.h"

extern int etext;
int main(void)
{
	void *entry = __runt_auxv_get_program_entry_point();
	assert((uintptr_t) entry < (uintptr_t) &etext);
	/* What other queries can we do?
	 * We can ask which file an address is part of -- like dladdr,
	 * but forgetting the symbol stuff.
	 * (Ideally we would be able to provide a fast implementation of
	 * the whole of dladdr. That means importing some form of the
	 * metavector stuff.)
	 */
	struct link_map *l = __runt_files_lookup_by_addr(main);
	assert(l);
	assert((uintptr_t) entry >= l->l_addr);
	return 0;
}
