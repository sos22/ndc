#include <pthread.h>

int global;

static void *
thrfunc(void *ign)
{
	while (1)
		global++;
}

int
main()
{
	pthread_t thr;

	pthread_create(&thr, NULL, thrfunc, NULL);

	while (1)
		global++;

}
