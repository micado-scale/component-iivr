/*
 * getHash.c
 *
 *  Created on: Jul 5, 2018
 *      Author: jorge
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>



void sha256_file(char *path, char *outputBuffer,size_t len)
{
    FILE *file = fopen(path, "rb");
    if(!file){
        printf("IIV-ERROR: The image cannot be read\n");
        exit(1);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer =(unsigned char *)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer){
        printf("IIV_ERROR: No memory allocation is possible\n");
        exit(1);
    }
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    int i = 0;
        for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
        }
    outputBuffer[len-1] = 0;

    fclose(file);
    free(buffer);

}

int main( int argc, char **argv){

		if( argc != 2){
			printf("Incorrect number of parameters: <Location of the Image>\n");
			exit(1);
                }		
		char calcHash[65];
		sha256_file(argv[1],calcHash,65);
		printf("The result is: %s\n",calcHash);
		return 0;

}
