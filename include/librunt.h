#ifndef LIBRUNT_H_
#define LIBRUNT_H_

#ifdef __cplusplus
extern "C" {
typedef bool _Bool;
#else
#endif

#include <sys/resource.h> /* for rlim_t */
#include <dlfcn.h>
#if !defined(_GNU_SOURCE) && !defined(HAVE_DL_INFO)
typedef struct {
	const char *dli_fname;
	void       *dli_fbase;
	const char *dli_sname;
	void       *dli_saddr;
} Dl_info;
#endif
#include <link.h>
#include <assert.h>

/* We define a dladdr that caches stuff. */
Dl_info dladdr_with_cache(const void *addr);
struct dl_phdr_info;
int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data);
const char *dynobj_name_from_dlpi_name(const char *dlpi_name,
	void *dlpi_addr);
struct link_map *__runt_files_lookup_by_addr(void *addr);

extern void *__top_of_initial_stack __attribute__((visibility("protected")));
extern rlim_t __stack_lim_cur __attribute__((visibility("protected")));

void __runt_auxv_init(void);
_Bool __runt_auxv_get_asciiz(const char **out_start, const char **out_end);
_Bool __runt_auxv_get_argv(const char ***out_start, const char ***out_terminator);
_Bool __runt_auxv_get_env(const char ***out_start, const char ***out_terminator);
_Bool __runt_auxv_get_auxv(const Elf64_auxv_t **out_start, Elf64_auxv_t **out_terminator);
void *__runt_auxv_get_program_entry_point(void);

void __runt_files_init(void);
void __runt_segments_init(void);
void __runt_sections_init(void);
void __runt_symbols_init(void);

#endif
