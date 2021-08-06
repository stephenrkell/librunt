#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <elf.h>
#include <link.h>
#include "relf.h"

extern struct r_debug _r_debug __attribute__((visibility("protected")));

int main(void)
{
	struct r_debug *r = find_r_debug();
	assert(r);
	return 0;
}
