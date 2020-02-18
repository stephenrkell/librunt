#define GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

int main(void)
{
	/* How can we test librunt's support for dlopen() etc?
	 * Do we need to be a client of librunt ourselves?
	 * We could just do some dlopens etc and check nothing
	 * crashes... remembering that we preload our own dlopen.
	 */
}
