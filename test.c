#include <stdio.h>

static void init(void) __attribute__((constructor));
static void init(void)
{
	printf("Hello world.\n");
}
