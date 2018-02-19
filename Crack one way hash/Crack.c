/*
Cracking one way hash
Done By : Dhruv Verma (C) 2017 gothinski
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int getHash(char * hashname, char *msg, unsigned char *md_value) {
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int md_len, i;
	OpenSSL_add_all_digests();
	md = EVP_get_digestbyname(hashname);
	if(!md) {
		printf("Unknown message digest %s\n", hashname);
		exit(1);
	}
	mdctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, msg, strlen(msg));
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_destroy(mdctx);
	return md_len;
}

char* convert_hex(unsigned char *hash,int md_len)
{
	char *hash_hex=(char*)malloc(2*md_len + 1);
	char *hex_buff = hash_hex;
	int i=0;
	for(i=0;i<md_len;i++)
		hex_buff+=sprintf(hex_buff,"%02x",hash[i]);
	*(hex_buff+1)='\0';		
	return hash_hex;
}


static char *randstring(char *message, size_t length) 
{
    static const char charset[] ="0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    int i=0;
    for(i=0;i<length;i++)
    	message[i]=charset[rand() % (sizeof(charset)-1)];
    message[length]=0;	
    return message;
}



int crackOneWayHash(char * hashname) {
	char msg1[11], msg2[11];
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int x=0,y=0;
	char *hash1, *hash2;
	int count=0, i;
	randstring(msg1,11);
	x=getHash(hashname, msg1, digt1);
	hash1=convert_hex(digt1,x);
	
	// run the crack
	do {
		randstring(msg2,11);
		if(msg2!=msg1)
		{
		y=getHash(hashname, msg2, digt2);
		hash2=convert_hex(digt2,y);
		count++;
		}
	} while (strncmp(hash1, hash2, 6)!=0);
	
	printf("\nMessage  : %s",msg1);
	printf("\nHash  : %s",hash1);
	printf("\nMessage generated to crack : %s",msg2);
	printf("\nHash generated to crack : %s",hash2);
	printf("cracked after %d tries	! ", count);
	return count;
}

int crackCollisionHash(char * hashname) {
	char msg1[11], msg2[11];
	int x=0,y=0;
	char *hash1, *hash2;
	unsigned char digt1[EVP_MAX_MD_SIZE], digt2[EVP_MAX_MD_SIZE];
	int count=0, i;
	// run the crack
	do {
		randstring(msg1,11);
		x=getHash(hashname, msg1, digt1);
		hash1=convert_hex(digt1,x);

		randstring(msg2,11);
		y=getHash(hashname, msg2, digt2);
		hash2=convert_hex(digt2,y);

		count++;
	} while (strncmp(hash1, hash2, 6)!=0);

	printf("\nMessage 1 : %s \nHash1 is %s",msg1, hash1);	
	
	printf("\nMessage 2 : %s \nHash2 is %s",msg2, hash2);	
	printf("\nCracked after %d tries\n",count);
	EVP_cleanup();
	return count;
}

void main(int argc, char *argv[])
{
	char *hashname;
	if(!argv[1])
		// set to md5 by default
		hashname = "md5";
	else
		hashname = argv[1];
	int i,count;
	srand((int)time(0));
	/*for (i=0,count=0;i<3;i++)
		count+=crackCollisionHash(hashname);
	printf("average time cracking collision-free: %d \n", count/3);*/
	for (i=0,count=0;i<1;i++)
		count+=crackOneWayHash(hashname);
	printf("\naverage time cracking one-way: %d \n", count/3);
}

