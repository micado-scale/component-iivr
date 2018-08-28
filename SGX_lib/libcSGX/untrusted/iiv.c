#include "iiv.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <libgen.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/sha.h>

#include "IIV_u.h"
#include "lib/sgx_utils.h"
#include "sgx_tprotected_fs.h"

void hola(int a){
	printf("This is a test\n");
}


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Global Name of sealed hash file */
char hashList[]="hash_trusted_list.txt";

/////////////////////////////////////////////////////////////////////////////
/* ocall functions */
void ocall_IIV_sample(const char *str)
{
    /* Prox/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/* ocall to compute a 256Byte-hash for a particular image. */
void ocall_sha256_file(char *path, char *outputBuffer,size_t len)
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


/* Image Integrity Verifier Main Program  */

int SGX_init(char *file_path)
{

	/* Initialization of the protected Image Integrity Mechanism */
	int ecall_return;

	if(initialize_enclave(&global_eid) < 0){

	      return -1;
	    }


/* This block has to be part of the initialization process.
 * After the sealed file is created by the enclave, then the
 * information of the hashes in plain text needs to be transfered
 * to the sealed list. This block will be executed if and only if
 * the file_path is passed, however, if an encrypted version of
 * the trusted hash is provided(sealed with the same key) then this
 * block is skipped. None is equivalent to NULL*/

if(strcmp(file_path, "None") != 0){
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	uint64_t file_size = 0;
	SGX_FILE* fp;
	const char* mode = "w+";

	/* Request the creation of a sealed file. */
	ret = ecall_file_open(global_eid, &fp, hashList, mode);

	/* Load the hash list(plain text) to the sealed list(the one created above) */
	FILE *file = NULL; //For the plain-text file
	char buffer[1024];
	size_t bytesRead = 0;

	file = fopen(file_path, "r"); //Open the plain text file.

	/* if the plain text is not provided, the program must exit */
	if( !file || !fp ){
		printf("IIV-ERROR: The file %s could no be opened\n",file_path);
		exit(1);
	}

	while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0)
	{
			 size_t sizeOfWrite = 0;
			 ecall_file_write(global_eid,&sizeOfWrite,fp,buffer,bytesRead);
	}


	/* This optional block, removes the plain hash list once the information is loaded
	 * successfully to the sealed list.
	 *
		int status=remove("beto.txt");
		if(status ==0){
			  printf("%s file deleted successfully\n",argv[3]);
		 }
    */
	int32_t fileHandle;
	ret = ecall_file_close(global_eid, &fileHandle, fp);
}
	return 0;
}
/* ******************************************************************************************/

/* Image Integrity Mechanism. */
int SGX_IIM(char *image_name, char *image_path){
	enum IIV_status status;
	int result;
	ecall_ImagVerify(global_eid,&status,image_name, image_path);

	switch (status){

	case IMAGEOK :
		result=1;
		//printf("IIV-INFO: The image has been validated. The result is: OK\n");
		break;

	case IMAGENOK :
		result=0;
		//printf("IIV-INFO: The image has been validated. The result is: Not OK\n");
		break;
	default:
		result=-1;
		//printf("IIV-INFO: The image provided is not registered in the system\n");
	}

    return result ;
}
