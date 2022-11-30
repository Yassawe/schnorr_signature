#include "schnorr.h"


int main(int argc, char* argv[]){
    
    if (argc!=2){
        printf("Usage: ./test <message_without_spaces>\n");
        return 1;
    }

    char* message = argv[1];

    printf("Generating public and private key...\n");

    struct PublicKey PK;
    struct PrivateKey SK;

    generateKey(&PK, &SK);

    printf("Public key: \n");
    printf("p: ");
    printbignum(PK.p);
    printf("q: ");
    printbignum(PK.q);
    printf("g: ");
    printbignum(PK.g);
    printf("y: ");
    printbignum(PK.y);

    printf("\nPrivate key: \n");
    printf("x: ");
    printbignum(SK.x);

    printf("\n&&&&&&&&&&&&&&&&&&&&&&\n");

    printf("Signing...\n");
    
    struct Signature SG;

    sign(message, strlen(message), &PK, &SK, &SG);
    printf("Signature: \n");
    printf("s: ");
    printbignum(SG.s);
    printf("e: ");
    printbignum(SG.s);

    printf("\n&&&&&&&&&&&&&&&&&&&&&&\n");

    printf("Verifying... \n");

    int output = verify(message, strlen(message), &PK, &SG);

    if(output==1){
        printf("Message verified!\n");
    }
    else{
        printf("Message not verified! \n");
    }

}