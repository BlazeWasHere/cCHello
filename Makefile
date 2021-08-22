CFLAGS ?= -O2 -Wall -Wextra -Wfloat-equal -Wundef -Wcast-align -Wwrite-strings -Wlogical-op -Wmissing-declarations -Wredundant-decls -Wshadow

all: test example

test: tests.c cCHello.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

example: example.c cCHello.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -rf example
	rm -rf test
