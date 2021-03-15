/* Utility functions for introspecting on TLS. */

void *__runt_tls_block_base(void)
{
	void *the_addr;
#if defined(__x86_64__)
	__asm__("mov %%fs:0, %0" : "=r"(the_addr)); // HACK: sysdep
#elif defined(__i386__)
	__asm__("mov %%gs:0, %0" : "=r"(the_addr)); // HACK: sysdep
#else
#error "Unknown architecture"
#endif
	return the_addr;
}
