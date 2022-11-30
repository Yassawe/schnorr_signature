#include "schnorr.h"

int sha256(unsigned char* input, unsigned long length, unsigned char* md)
{
    // return 0 if error, 1 if ok. to be consistent with openssl

    SHA256_CTX context;
    if(!SHA256_Init(&context))
        return 0;

    if(!SHA256_Update(&context, input, length))
        return 0;

    if(!SHA256_Final(md, &context))
        return 0;

    return 1;
}

int concattwostrings(unsigned char* s1, unsigned char* s2, unsigned char* dest){
    int i = 0, j = 0;

    while (s1[i] != '\0') {
        dest[j] = s1[i];
        i++;
        j++;
    }

    i=0;
    while (s2[i] != '\0') {
        dest[j] = s2[i];
        i++;
        j++;
    }

    dest[j] = '\0';

    return 1;
}

int generateKey(struct PublicKey* PK, struct PrivateKey* SK){
    // return 0 if error, 1 if ok

    BIGNUM* q = BN_new();
    BIGNUM* p = BN_new();
    BIGNUM* k = BN_new();
    BIGNUM* h = BN_new();
    BIGNUM* g = BN_new();
    BIGNUM* y = BN_new();
    BIGNUM* x = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    
    int rc;

    genprimes:
    if(!BN_generate_prime_ex(q, N, 0, NULL, NULL, NULL))
    {
        printf("Failed to generate q. Retrying\n");
        goto genprimes;  
    }
    
    if(!BN_generate_prime_ex(p, L, 0, q, NULL, NULL)){ // function guarantees that p mod q = 1, therefore p = kq+1
        printf("Failed to generate p. Retrying\n");
        goto genprimes;
    }
    
    rc = BN_sub(temp1, p, BN_value_one()); // temp1 = p-1
    rc = BN_div(k, temp2, temp1, q, NULL); // k = (p-1)/q

    if (!rc){
        printf("Arithmetic error\n");
        return 0;
    }
     
    generator:

    rc = BN_rand_range(h, p); // 1<h<p
    rc = BN_mod_exp(g, h, k, p, NULL); // g = h^k mod p

    if (!rc){
        printf("Arithmetic error in generator\n");
        return 0;
    }

    if(BN_is_one(g)){
        goto generator;
    }

    // private key

    rc = BN_rand_range(x, q); // 1<x<q
    rc = BN_mod_exp(y, g, x, p, NULL); // y = g^x mod p

    if(!rc){
        printf("Error during private key generation\n");
        return 0;
    }


    PK->p = p;
    PK->q = q;
    PK->g = g;
    PK->y = y;
    SK->x = x;

    BN_free(temp1);
    BN_free(temp2);
    BN_free(k);
    BN_free(h);

    return 1;
}

int sign(char* message, int message_len, struct PublicKey* PK, struct PrivateKey* SK, struct Signature* SG){
    // return 0 if error, 1 if ok

    BIGNUM* k = BN_new();
    BIGNUM* r = BN_new();
    BIGNUM* e = BN_new();
    BIGNUM* s = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();

    int rc;


    rc = BN_rand_range(k, PK->q); // 1<k<q
    rc = BN_mod_exp(r, PK->g, k, PK->p, NULL); // r = g^k mod p

    int r_len = BN_num_bits(r);
    unsigned char* r_char = (unsigned char*)malloc(r_len*sizeof(char));
    unsigned char* concatenated = (unsigned char*)malloc((message_len+r_len)*sizeof(char));
    unsigned char* hash = (unsigned char*)malloc(outlen*sizeof(char));

    rc = BN_bn2bin(r, r_char);
    concattwostrings((unsigned char*)message, r_char, concatenated); // m||r
    sha256(concatenated, (message_len+r_len), hash); // h(m||r)
    BN_bin2bn(hash, (message_len+r_len), e); // e = h(m||r)

    rc = BN_mod_mul(temp1, SK->x, e, PK->q, NULL); // temp1 = xe mod q
    rc = BN_mod(temp2, k, PK->q, NULL); // temp2 = k mod q
    rc = BN_mod_add(s, temp1, temp2, PK->q, NULL); // s = xe + k mod q

    SG->s = s;
    SG->e = e;

    free(r_char);
    free(concatenated);
    free(hash);
    BN_free(k);
    BN_free(r);
    BN_free(temp1);
    BN_free(temp2);

    return rc;
}

int verify(char* message, int message_len, struct PublicKey* PK, struct Signature* SG){
    //return 1 if verified, return 0 if not verifyed

    BIGNUM* v = BN_new();
    BIGNUM* e_prime = BN_new();
    BIGNUM* temp1 = BN_new();
    BIGNUM* temp2 = BN_new();
    int rc;
    

    rc = BN_mod_exp(temp1, PK->g, SG->s, PK->p, NULL); // temp1 = g^s mod p
    
    temp2 = BN_dup(SG->e); // temp2 = e
    BN_set_negative(temp2, 1); // temp2 = -e
    rc = BN_mod_exp(temp2, PK->y, temp2, PK->p, NULL); // temp2 = y^-e mod p

    rc = BN_mod_mul(v, temp1, temp2, PK->p, NULL); // v = g^s y^-e mod p 

    int v_len = BN_num_bits(v);
    unsigned char* v_char = (unsigned char*)malloc(v_len*sizeof(char));
    unsigned char* concatenated = (unsigned char*)malloc((message_len+v_len)*sizeof(char));
    unsigned char* hash = (unsigned char*)malloc(outlen*sizeof(char));

    rc = BN_bn2bin(v, v_char);
    concattwostrings((unsigned char*)message, v_char, concatenated); // m||v
    sha256(concatenated, (message_len+v_len), hash); // h(m||v)
    BN_bin2bn(hash, (message_len+v_len), e_prime); // e_prime = h(m||v)

    if(!rc){
        printf("Unhandled error in verification \n"); 
        return -1;
    }

    int output = BN_cmp(SG->e, e_prime); // this function returns -1 if e<e', 0 if e==e', 1 if e>e'


    free(v_char);
    free(concatenated);
    free(hash);

    BN_free(v);
    BN_free(e_prime);
    BN_free(temp1);
    BN_free(temp2);

    
    return output == 0; 
}

int printbignum(BIGNUM* a){
    int rc;
    int len = BN_num_bits(a);
    unsigned char* a_char = (unsigned char*)malloc(len*sizeof(char));
    
    rc = BN_bn2bin(a, a_char);

    printf("%s\n", a_char);
    
    return rc;
}