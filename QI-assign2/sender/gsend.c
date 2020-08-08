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



// IO operations, input ciphertext to exampe.txt.uf

void InputCipher(unsigned char *cipher, int len){

FILE *f=fopen("example.txt.uf","w");

if (f==NULL){
printf("Sorry, cannot open the specific file \n");
exit(1);

}

	//const char *text =cipher;
	//printf("6666666 %s \n",text);
	//fprintf(f, "%s", cipher);
	fwrite(cipher, sizeof(unsigned char), len, f);

	/* for(int i =0;i< len;i++) printf("%u",cipher[i]);
	printf("\n");  */
	fclose(f);
}

// put the calculated hmac to HMAC.txt.uf 
void InputMAC(unsigned char *hmac){

FILE *f=fopen("HMAC.txt.uf","w");

if (f==NULL){
printf("Sorry, cannot open the specific file \n");
exit(1);

}

	//const char *text =cipher;
	//printf("6666666 %s \n",text);
	fprintf(f, "%s", hmac);
     

	/* for(int i =0;i< len;i++) printf("%u",cipher[i]);
	printf("\n");  */
	fclose(f);

}
//get the length of a specific file

int IOLen(char* name){

  FILE* fp = fopen(name, "r");
    
    int len;
     
    fseek(fp, 0, SEEK_END); 
    len = ftell(fp); 
    fseek(fp, 0, SEEK_SET);
     return len;
}

// read a specific file according to its length    
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
//get HMAC
   
    char* Getmac(char* cipher, char* mdString)  
    {  
        // The key to hash  
        char key[] = "167349373";  
      
        // The data that we're going to hash using HMAC  
       // char data[] = cipher;  
      
        unsigned char digest[EVP_MAX_MD_SIZE] = {'\0'};  
        unsigned int digest_len = 0;  
      
      // getmac value
        HMAC(EVP_sha512(), key, strlen(key), (unsigned char*)cipher, strlen(cipher), digest, &digest_len);  
       // printf("%s, len %u\n", digest, digest_len);  
      
      //  char mdString[129] = {'\0'};
        for(int i = 0; i < 64; i++)  
             sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);  
      
        //printf("HMAC digest: %s\n", mdString);  
      
        return mdString;  
    }  

//check if the output already exist
int file_exist(char * name){

FILE *fp;

    fp=fopen(name , "r");

    if ( fp != NULL ){
 printf("the output ciphertext txt.uf file already exist! \n");
 fclose(fp);
    return 1;
}
 else
return 0;
  

}
//main func

int main (void)
{

int flag=0;
flag=file_exist("example.txt.uf");

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

   /* the random 128 bit iv*/
    unsigned char *iv = (unsigned char *)"iut1k8w7g2he90he";

    int length=IOLen("example.txt");
 //  printf("the real length is %d",length);

	printf("length: %d\n",length);

    char buffer[length];
    char *plaintext=IOread("example.txt",buffer,length);
   // unsigned char *plaintext =IOresult;

 BIO_dump_fp (stdout, (const char *)plaintext, length);

    unsigned char ciphertext[1000*1000];
memset(ciphertext,0,sizeof(ciphertext));
  
    int ciphertext_len;


    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), Fkey, iv,
                              ciphertext);

   
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
  
// hmac value
  char Hmac_space[129];
  char *Hmac_value;
  Hmac_value=Getmac(ciphertext, Hmac_space);
  printf("Value of the HMAC cipher file: %s FINISH\n", Hmac_value);

char Hmac_space2[129];
  char *Hmac_value2;
  Hmac_value2=Getmac(plaintext, Hmac_space2);
  printf("Value of the HMAC test file: %s FINISH\n", Hmac_value2);

 InputMAC(Hmac_value);

 
 
//check if the output already exist
/* int flag;
flag=file_exist("example.txt.uf");

if(flag==1)
printf("exit \n");  */
  
 /* if (access("./c/example.txt.uf",0))
{
 printf("The file already exist! error code 33");
      // exit(1);
}  */
        


    InputCipher(ciphertext, ciphertext_len);


  printf("This is ciphertext || HMAC: \n");
printf("%s", ciphertext);
printf("%s", Hmac_value);
printf("\n");
printf("Finish reading \n");  

    return 0;  
    
}




