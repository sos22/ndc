#include <dlfcn.h>
#include <stdio.h>

int
main()
{
	printf("doing dlopen\n");
	dlopen("./test.so", RTLD_LAZY);
	printf("Done dlopen\n");
	return 0;
}
