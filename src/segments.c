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
#include "dso-meta.h"
#include "librunt_private.h"

/* static */ _Bool __runt_segments_trying_to_initialize __attribute__((visibility("hidden")));
#define trying_to_initialize __runt_segments_trying_to_initialize
static _Bool initialized;

void __runt_segments_init(void) __attribute__((constructor(102)));
void __runt_segments_init(void)
{
	if (!initialized && !trying_to_initialize)
	{
		/* Initialize what we depend on. This might do nothing if we
		 * are already in the middle of doing this init. How do we
		 * ensure that we always come back here to do *our* init?
		 * Firstly, the files code calls *us* when it's done.
		 * Secondly, we don't set our "trying" flag until *it's* inited,
		 * so that call will not give up saying "doing it". */
		__runt_files_init();
		trying_to_initialize = 1;
		/* That's all. */
		initialized = 1;
		trying_to_initialize = 0;
	}
}
/* In the most natural/direct model, children of the segment
 * may be sections or symbols, i.e. some symbols are not in
 * any section, and some ELF files do not have any section
 * headers at all. How common is this? How can we regularise
 * this? Rather than create dummy sections, we have only one
 * bitmap/metavector per segment. */
void __runt_segments_notify_define_segment(
	struct file_metadata *file,
	unsigned phndx,
	unsigned loadndx
)
{
	ElfW(Phdr) *phdr = &file->phdrs[phndx];
	const void *segment_start_addr = (char*) file->l->l_addr + phdr->p_vaddr;
	debug_printf(2, "notified of segment at %p within %s\n", segment_start_addr,
		dynobj_name_from_dlpi_name(file->l->l_name, (void*) file->l->l_addr));
	/* Fill in the per-segment info that is stored in the file metadata.
	 * We just fill in a metadataless dummy version; liballocs will do more. */
	file->segments[loadndx] = (struct segment_metadata) {
		.phdr_idx = phndx,
		.metavector = NULL,
		.metavector_size = 0
	};
}

void __runt_segments_notify_destroy_segment(
	ElfW(Phdr) *phdr
)
{
	/* Can segments go away without their containing file also going
	 * away? For now, we don't support this, so there is nothing to do. */
}
