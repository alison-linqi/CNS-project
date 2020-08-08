#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#define SALT "KCI"
#define ITRA 4096

//#include <function.h>

//The key generation algorithm, using PBKDF2
unsigned char *KeyGea(unsigned char* hex, int length){
char password[50];

unsigned char output[length];
memset(output,0,sizeof(output));

//memset(fnl, 0, sizeof(fnl));
printf("please enter password: \n");
scanf("%s", password);

if (PKCS5_PBKDF2_HMAC(password, strlen(password), SALT, strlen(SALT), ITRA, EVP_sha512(), length, output)==1){
 printf("this is the generated key by PBKDF2: \n");
// printf("%s \n",output);

 for(int i=0; i<sizeof(output);i++){
  //output[i]=Hex[output[i]];
 sprintf(hex+(i*2), "%02x",255 & output[i]);
  //printf("%02x", 255 & output[i]);

 }
printf("%s\n",hex);


}
else
 printf("some error happened the key is not generated");
return hex;
}

// handle errors
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}
//the encrypt algorithm

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();


    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

   
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

  
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}
//decryption

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

 
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

   
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


// IO operations

/* void InputCipher(unsigned char *cipher, int len){

FILE *f=fopen("./b/example.txt.uf","w");

if (f==NULL){
printf("Sorry, cannot open the specific file \n");
exit(1);

}

	//const char *text =cipher;
	//printf("6666666 %s \n",text);
	//fprintf(f, "%s", cipher);
        fwrite(cipher, sizeof(unsigned char), len, f);
	for(int i =0;i< len;i++) printf("%u",cipher[i]);
	printf("\n");
	fclose(f);
}  */

// put the decrypted plaintext to example.txt
void InputPlain(char *plain, int len){

FILE *f=fopen("example.txt","w");

if (f==NULL){
printf("Sorry, cannot open the specific file \n");
exit(1);

}

//BIO_dump_fp (stdout, (const char *)cipher, len);

   //const char *text =cipher;
	fprintf(f, "%s", plain);


	fclose(f);


}
// the same as encryption algorithm

int IOLen(char* name){

  FILE* fp = fopen(name, "r");
    
    int len;
     
    fseek(fp, 0, SEEK_END); 
    len = ftell(fp); 
    fseek(fp, 0, SEEK_SET);
     return len;
}

     
char * IOread(char* name, char* buf, int maxline)
{ 
 FILE *fp;          
 if((fp = fopen(name,"r")) == NULL)
 {
 perror("sorry, can not read the file");
 exit (1) ;
 }
 fread(buf, maxline,1,fp);
 // printf("%s \n",buf);
 fclose(fp);
 return buf;

}
// get HMAC
  char* Getmac(char* cipher, char* mdString)  
    {  
        // The key to hash  
        char key[] = "167349373";  
      
        unsigned char digest[EVP_MAX_MD_SIZE] = {'\0'};  
        unsigned int digest_len = 0;  
      
       
        HMAC(EVP_sha512(), key, strlen(key), (unsigned char*)cipher, strlen(cipher), digest, &digest_len);  
        printf("%s, len %u\n", digest, digest_len);  
      
      
      //  char mdString[129] = {'\0'};
        for(int i = 0; i < 64; i++)  
             sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);  
      
        printf("HMAC digest: %s\n", mdString);  
      
        return mdString;  
    }  


int file_exist(char * name){

FILE *fp;

    fp=fopen(name , "r");

    if ( fp != NULL ){
 printf("the output plaintext .txt file already exist! error 33! \n");
 fclose(fp);
    return 1;
}
 else
return 0;
  

}

int main (void)
{
    
 int flag=0;
flag=file_exist("example.txt");

//printf("exit \n");


if(flag==1)
{
	printf("exit \n");  
	return 0;
}

    /* A 256 bit key */
  int pair=32;

  unsigned char fnl[2*pair+1];
  memset(fnl,0,sizeof(fnl));

  unsigned char *Fkey = KeyGea(fnl, pair);

   /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"iut1k8w7g2he90he";


// decrypt

   unsigned char decryptedtext[1000*1000];
memset(decryptedtext,0,sizeof(decryptedtext));

	unsigned char decryptedtext2[1000*1000];
memset(decryptedtext2,0,sizeof(decryptedtext2));

    int decryptedtext_len;

	int lengthUF =IOLen("example.txt.uf");
	printf("length: %d\n",lengthUF);
	char buffercip[lengthUF];
    	char *ciphertext2 = IOread("example.txt.uf",buffercip,lengthUF);

    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext2, lengthUF);

char Hmac_space2[129];
char *newmac= Getmac(ciphertext2, Hmac_space2);
printf("***The new mac of the received document is: %s \n", newmac);

int macUF =IOLen("HMAC.txt.uf");
	char buffermac[macUF];
    	char *oldmac = IOread("HMAC.txt.uf",buffermac,macUF);
	oldmac[macUF] = '\0';
printf("***This is is old mac: %s \n", oldmac);
 
 if(strcmp(newmac,oldmac) ==0)
printf("Hmac matches! The file has been authenticated! \n");
else{
printf("Hmac do not match! error code 62 \n");
exit(1);
}

 



	decryptedtext_len = decrypt(ciphertext2, lengthUF, Fkey, iv, decryptedtext);

	for(int i =0;i<decryptedtext_len-3;i++)
        decryptedtext2[i] = decryptedtext[i];	
	decryptedtext_len -=3;
 /* int flag=file_exist("example.txt");

if(flag==1)
printf("exit \n");

 /* if (access("./d/example.txt",0) )
{
 printf("The file already exist! error code 33");
      // exit(1);
}  */

	InputPlain(decryptedtext2,decryptedtext_len);

        decryptedtext[decryptedtext_len] = '\0';


    // Show the decrypted text 
    printf("Decrypted text is:\n");
    printf("%s\n finish \n", decryptedtext2);
  
 



    return 0;  
    
}




