/* Utility functions for introspecting on TLS. */

void *__runt_tls_block_base(void)
{
	void *the_addr;
	__asm__("mov %%fs:0, %0" : "=r"(the_addr)); // HACK: sysdep
	return the_addr;
}
