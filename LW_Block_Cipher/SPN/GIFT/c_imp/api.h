#define CRYPTO_KEYBYTES     16
#define CRYPTO_NSECBYTES    0
#define CRYPTO_NPUBBYTES    16
#define CRYPTO_ABYTES       16
#define CRYPTO_NOOVERLAP    1

void string2hexString(unsigned char* input, int clen, char* output);
static unsigned char ascii2byte(char *hexstring, unsigned char *bytearray);