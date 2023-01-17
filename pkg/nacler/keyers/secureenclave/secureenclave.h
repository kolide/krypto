#include <string.h>

size_t createKey(unsigned char**, char**);
size_t findKey(unsigned char* hash, unsigned char** ret, char** retErr);
size_t ecdh(unsigned char* hash, unsigned char* counterParty, int counterPartySize, unsigned char** ret, char** retErr);
