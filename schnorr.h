#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/sha.h>


#define L 1024
#define N 160
#define seedlen 160
#define outlen 256

struct PublicKey{
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* g;
    BIGNUM* y;
};

struct PrivateKey{
    BIGNUM* x;
};

struct Signature{
    BIGNUM* s;
    BIGNUM* e;
};

int generateKey(struct PublicKey* PK, struct PrivateKey* SK);
int sign(char* message, int message_len, struct PublicKey* PK, struct PrivateKey* SK, struct Signature* SG);
int verify(char* message, int message_len, struct PublicKey* PK, struct Signature* SG);
int printbignum(BIGNUM* a);