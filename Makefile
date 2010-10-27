CPPFLAGS+=-Wall -g

all: ndc.so test_dlopen test.so test_race1 ndc

clean:
	rm -f ndc.so test_dlopen test_race1 test.so ndc *.o *~ *.po

ndc.so: ndc.po
	gcc -shared -fPIC -g -o $@ $^

%.po: %.c
	gcc -shared -fPIC -Wall -g -c -o $@ $^

test_dlopen: test_dlopen.c
	gcc -Wall -ldl -g -o $@ $^

test.so: test.po
	gcc -shared -fPIC -g -o $@ $^

test_race1: test_race1.c
	gcc -Wall -g -pthread -o $@ $^

ndc: main.o ptrace.o decode.o util.o
	gcc -Wall -g $^ -o $@
