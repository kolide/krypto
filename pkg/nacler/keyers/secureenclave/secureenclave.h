#include <string.h>

typedef struct wrapper {
	unsigned char *buf;
	int status;
	size_t size;
	char *error;
} Wrapper;

Wrapper *wrapCreateKey();
Wrapper *wrapFindKey(void *hash);
Wrapper *wrapECDH(void *hash, void *counterParty, int counterPartySize);
