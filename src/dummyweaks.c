#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>

#if 0 /* do we vendor a libunwind? hmm */
unw_addr_space_t unw_local_addr_space __asm__("__liballocs_unw_local_addr_space") __attribute__((visibility("protected")));
int unw_get_reg(unw_cursor_t *cursor, int reg, unw_word_t *dest) { return 0; }
int unw_init_local(unw_cursor_t *cursor, unw_context_t *context) { return 0; }
int unw_getcontext(unw_context_t *ucp) { return 0; }
int unw_step(unw_cursor_t *cp) { return 0; }
#endif

Dl_info dladdr_with_cache(const void *addr)
{
	Dl_info dummy;
	memset(&dummy, 0, sizeof dummy);
	return dummy;
}
void *__runt_auxv_get_program_entry_point(void)
{
	return NULL;
}
struct link_map *__runt_files_lookup_by_addr(void *addr)
{
	return NULL;
}
