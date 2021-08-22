# cCHello

A minimal TLS client hello parser.

# Features
- compatible with C99
- no dependencies
- ~100 LOC
- simple API
- extensive overflow checks

# API
```c
client_hello_t *cchello_client_hello_init(void);
int cchello_parse(client_hello_t *ch, uint8_t *data, size_t data_len);
void cchello_client_hello_free(client_hello_t *ch);
```

# Usage

```c
#include "cCHello.h"
...
client_hello_t *ch == cchello_client_hello_init();
if (ch == NULL)
    // handle alloc failure.

int ret = cchello_parse(ch, data, data_len);
if (ret < 0)
    // handle cchello error.
else
    // you may want to check if cchello read all of the data
    assert(data_len == ret);

// remember to free!
cchello_client_hello_free(ch);
```

# Example

After running the example binary, visit the URL [https://localhost:1337](https://localhost:1337) in your browser.

```sh
$ make example
cc -O2 -Wall -Wextra -Wfloat-equal -Wundef -Wcast-align -Wwrite-strings -Wlogical-op -Wmissing-declarations -Wredundant-decls -Wshadow  -o test tests.c cCHello.c
$ ./example
[...]
```

# Tests
```sh
$ make test
cc -O2 -Wall -Wextra -Wfloat-equal -Wundef -Wcast-align -Wwrite-strings -Wlogical-op -Wmissing-declarations -Wredundant-decls -Wshadow  -o test tests.c cCHello.c
$ ./test
[...]
ALL TESTS PASSED.
```

# Thanks
[Michael Driscoll](https://github.com/syncsynchalt) for the [illustrated TLS connection](https://github.com/syncsynchalt/illustrated-tls)

# License
[BSL-1.0 License](https://github.com/BlazeWasHere/cCHello/blob/master/LICENSE)
