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

void __runt_sections_init(void) __attribute__((constructor(102)));
void __runt_sections_init(void)
{
	/* Sections are created by the static file allocator,
	 * so there is nothing to do.  */
}
struct section_metadata
{
	const Elf64_Shdr *shdr; /* should *not* be null; we don't create dummy sections */
};

void __runt_sections_notify_define_section(
	struct file_metadata *meta,
	const ElfW(Shdr) *shdr
)
{
	if (shdr->sh_size > 0)
	{
		debug_printf(3, "notified of section at %p within %s\n",
			(void*) (meta->l->l_addr + shdr->sh_addr),
			dynobj_name_from_dlpi_name(meta->l->l_name, (void*) meta->l->l_addr));
	}
}
