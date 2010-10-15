all: ndc.so test_dlopen test.so

ndc.so: ndc.po
	gcc -shared -fPIC -g -o $@ $^

%.po: %.c
	gcc -shared -fPIC -Wall -g -c -o $@ $^

test_dlopen: test_dlopen.c
	gcc -Wall -ldl -g -o $@ $^

test.so: test.po
	gcc -shared -fPIC -g -o $@ $^
