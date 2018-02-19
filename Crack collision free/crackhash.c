/*
Cracking collision free property
Done By : Dhruv Verma (C) 2017 gothinski
*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/evp.h>

int crackcollision(char *hashname);
void rand_str(char *message, size_t length);
int getHash(char *message,char *hashname, unsigned char *hash);


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

int getHash(char *message,char *hashname, unsigned char *hex_buff)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int md_len;
	OpenSSL_add_all_digests();
	md =EVP_get_digestbyname(hashname);
	if (md == NULL) 
	{
        	printf("Unknown message digest %s\n", hashname);
        	exit(1);
 	}
	mdctx = EVP_MD_CTX_create();
 	EVP_DigestInit_ex(mdctx, md, NULL);
 	EVP_DigestUpdate(mdctx, message, strlen(message));
 	EVP_DigestFinal_ex(mdctx, hex_buff, &md_len);
 	EVP_MD_CTX_destroy(mdctx);
	return md_len;

}

void rand_str(char *message, size_t length) 
{
    static const char charset[] ="0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    int i=0;
    for(i=0;i<length;i++)
    	message[i]=charset[rand() % (sizeof(charset)-1)];
    message[length]=0;	
}


int crackcollision(char *hashname)
{
	char message1[10],message2[10];
	unsigned char hash1[EVP_MAX_MD_SIZE],hash2[EVP_MAX_MD_SIZE];
	int count=0,i=0;
	int md_len1=0,md_len2=0;
	char *hex_hash1,*hex_hash2;
	printf("Cracking Collision Resistance of Hash Function\n");
	do
	{
		printf("COUNT : %d\n",count);
		rand_str(message1,10);
		md_len1 = getHash(message1,hashname,hash1);
		hex_hash1=convert_hex(hash1,md_len1);		
	
		rand_str(message2,10);
		md_len2 = getHash(message2,hashname,hash2);
		hex_hash2=convert_hex(hash2,md_len2);
		
		count++;
		
	}while(strncmp(hex_hash1,hex_hash2,6)!=0);
	
	printf("\nMessage 1 : %s",message1);	
	printf("\nFirst Hash is : %s",hex_hash1);

	printf("\nMessage 2 : %s",message2);	
	printf("\nSecond Hash is : %s",hex_hash2);
	printf("\nCracked after %d tries\n",count);
	EVP_cleanup();
	return count;
	
}

int crackoneway(char *hashname)
{
	char message1[16],message2[16];
	unsigned char hash1[EVP_MAX_MD_SIZE],hash2[EVP_MAX_MD_SIZE];
	int count=0,i=0;
	char *hex_hash1,*hex_hash2;
	printf("\n\nCracking One-Way Property of Hash Function\n");
	
	rand_str(message1,16);
	int md_len1 = getHash(message1,hashname,hash1);
	hex_hash1=convert_hex(hash1,md_len1);
	do
	{
		rand_str(message2,16);
		int md_len2 = getHash(message2,hashname,hash2);
		hex_hash2=convert_hex(hash2,md_len2);
		count++;
	}while(strncmp(hex_hash1,hex_hash2,6)!=0);
	printf("Message1 : ");
	for(i=0;i<strlen(message1);i++)
		printf("%c",message1[i]);
	printf("\nhash 1 :\n%s",hex_hash1);
	
	printf("\nMessage 2 and hash 2 : \n %s \n %s",message2,hex_hash2);
	
	printf("\n");
	printf("\nCracked after %d tries\n",count);
	return count;

}


int main()
{
	char *md="md5";
	int i=0,count1=0,count2=0;
	srand((int)time(0));
	/*for(i=0;i<3;i++)
		count1 += crackcollision(md);
	printf("Average time cracking collision-free: %d \n", count1/3);*/
	for(i=0;i<1;i++)
		count2 += crackoneway(md);
	printf("Average time cracking collision-free: %d \n", count2/3);
	return 1;
}
