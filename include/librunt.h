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

/* If we're building something to go in the same DSO as librunt,
 * it's OK to give undefined syms (references) the protected visibility.
 * Note that this doesn't affect the visibiltiy that the *definition* gets.
 */
#ifdef IN_LIBRUNT_DSO
#define PROTECTED __attribute__((visibility("protected")))
#else
#define PROTECTED
#endif

extern const char __ldso_name[] PROTECTED;
/* We define a dladdr that caches stuff. */
Dl_info dladdr_with_cache(const void *addr) PROTECTED;
Dl_info fake_dladdr_with_cache(const void *addr) PROTECTED; /* does not malloc */
struct dl_phdr_info;
int dl_for_one_object_phdrs(void *handle,
	int (*callback) (struct dl_phdr_info *info, size_t size, void *data),
	void *data) PROTECTED;
const char *dynobj_name_from_dlpi_name(const char *dlpi_name,
	void *dlpi_addr) PROTECTED;
const char *__runt_get_exe_realpath(void) PROTECTED;
struct link_map *__runt_files_lookup_by_addr(void *addr) PROTECTED;
struct file_metadata;
struct file_metadata *__runt_files_metadata_by_addr(void *addr) PROTECTED;

extern rlim_t __stack_lim_cur PROTECTED;


void __runt_auxv_init(void) PROTECTED;
_Bool __runt_auxv_get_asciiz(const char **out_start, const char **out_end) PROTECTED;
_Bool __runt_auxv_get_argv(const char ***out_start, const char ***out_terminator) PROTECTED;
_Bool __runt_auxv_get_env(const char ***out_start, const char ***out_terminator) PROTECTED;
_Bool __runt_auxv_get_auxv(const ElfW(auxv_t) **out_start, ElfW(auxv_t) **out_terminator) PROTECTED;
void *__runt_auxv_get_program_entry_point(void) PROTECTED;

void *__runt_tls_block_base(void) PROTECTED;

void __runt_files_init(void) PROTECTED;
void __runt_segments_init(void) PROTECTED;
void __runt_sections_init(void) PROTECTED;
void __runt_symbols_init(void) PROTECTED;

extern const char *__auxv_asciiz_start PROTECTED;
extern const char *__auxv_asciiz_end PROTECTED;
extern const char **__env_vector_start PROTECTED;
extern const char **__env_vector_terminator PROTECTED;
extern const char **__argv_vector_start PROTECTED;
extern const char **__argv_vector_terminator PROTECTED;
extern ElfW(auxv_t) *__auxv_array_start PROTECTED;
extern ElfW(auxv_t) *__auxv_array_terminator PROTECTED;
extern intptr_t *__auxv_program_argcountp PROTECTED;
extern void *__program_entry_point PROTECTED;
extern void *__top_of_initial_stack PROTECTED;

/* Client code to be compiled in the same DSO as librunt can use our hidden stuff,
 * which is useful for debugging. relf.h conditionally uses this. To do so, check
 * that librunt.h is included before relf.h. */
#ifdef IN_LIBRUNT_DSO
char *get_exe_dynobj_fullname(void) __attribute__((visibility("hidden")));
char *get_exe_dynobj_basename(void) __attribute__((visibility("hidden")));
char *get_exe_command_basename(void) __attribute__((visibility("hidden")));
const char *fmt_hex_num(unsigned long n) __attribute__((visibility("hidden")));
#define write_string(s) raw_write(2, (s), sizeof (s) - 1)
#define write_chars(s, t)  raw_write(2, s, t - s)
#define write_ulong(a)   raw_write(2, fmt_hex_num((a)), 18)
#endif

#endif
