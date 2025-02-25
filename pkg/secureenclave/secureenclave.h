#include <string.h>
#include <stdbool.h>

// Wrapper is used to provide a common interface for calling c functions that return go like results of
// return value and error. The size is the size of the return value buffer.
typedef struct wrapper {
    // result
	unsigned char *buf;
    // size of returned value
	size_t size;
    // errors
	char *error;
} Wrapper;

Wrapper *wrapCreateKey(bool isPermanent);
Wrapper *wrapFindKey(void *hash);
Wrapper *wrapSign(void *hash, void *data, int dataSize);
