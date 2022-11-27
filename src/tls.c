/* Utility functions for introspecting on TLS. */

void *__runt_tls_block_base(void)
{
	void *the_addr;
#if defined(__x86_64__)
	__asm__("mov %%fs:0, %0" : "=r"(the_addr)); // HACK: sysdep
#elif defined(__i386__)
	__asm__("mov %%gs:0, %0" : "=r"(the_addr)); // HACK: sysdep
#elif defined(__arm__)
	the_addr = __builtin_thread_pointer();
#else
#warning "Using a default method to get the thread pointer -- edit src/tls.c to check/silence."
	the_addr = __builtin_thread_pointer();
#endif
	return the_addr;
}
