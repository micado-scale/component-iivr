#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>
#include <string.h>
#include "IIV.h"
#include "IIV_t.h"  /* print_string */

#include <sgx_tcrypto.h>
#include <ctype.h>
#include <sgx_tseal.h>
#include "sgx_tprotected_fs.h"
#include <stdbool.h>

#define INITIAL_ALLOC 512 //Max number of characters per line.
uint64_t offset;

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_IIV_sample(buf);
}

/* TRUSTED FUNCTION DEFINITIONS */
int ecall_IIV_sample()
{
  printf("DEBUG-Info: Inside Integrity Verification Mechanism\n");
  return 0;
}

/* The untrusted section will make use of this function,
 * to create a file, that will be sealed in untrusted memory.*/

SGX_FILE* ecall_file_open(const char *filename, const char *mode){
	SGX_FILE *a;
	a=sgx_fopen_auto_key(filename,mode);
	return a;
}

/* The untrusted section will make use of this function,
 * to write the information in the plain well-known hashes in the
 *  sealed file kept in untrusted memory.*/

size_t ecall_file_write(SGX_FILE* fp, char *data, size_t size)
{
	size_t sizeofWrite;
	size_t len = size;
	sizeofWrite = sgx_fwrite(data, sizeof(char), size, fp);
	return sizeofWrite;
}

/* Once the untrusted component of the IIVR is done with moving the
 * information in the plain file to the seal file, it needs to close
 * the file, using this function.*/

int32_t ecall_file_close(SGX_FILE* fp)
{
	int32_t a;
	a = sgx_fclose(fp);
	return a;
}

/* This function is used to get one line at a time from the hash list file.
 * A file descriptor 'fp' is input as argument, and a line from the list is return at a time. */
char * read_line(SGX_FILE *fp) {

    size_t read_chars = 0;
    int bufsize = INITIAL_ALLOC;
    char *line = malloc(bufsize);
    char *tmp = malloc(bufsize);
    if ( !line || !tmp ) {
        return NULL;
    }


    while ( read_chars=sgx_fread(tmp,1,bufsize, fp) ) {

    	char *eol= strchr(tmp,'\n'); //Delimiter used to get just one line at a time.

    	line=strndup(tmp, (eol-tmp));

    	//Calculation of offset
    	uint64_t pre=(eol-tmp)+1;

    	offset=offset+pre;
    	//printf("Enclave-debug: Offset: %d pre-offset: %d\n",(int)offset, (int)pre);
    	sgx_fseek(fp,offset,SEEK_SET); //put the file descriptor in the next line
    	free(tmp);
    	return line;

    }
    free(tmp);
    return NULL;

}

/* This function returns a matching hash from 'image_name' in file provided as 'file_name' */
char *
find_hash(char * image_name, char *file_name) {

	SGX_FILE *fp;
    char *line;
    char *token1 = NULL;
    char *token2 = NULL;
    //const char *s = " \r\n";
    const char *s = ";"; //Parameter delimiter for a line in hash list: image_name;64Hex-hash
    char *hash;

    fp = sgx_fopen_auto_key(file_name, "r");

    if(!fp){
    	return NULL;
    }

    //Keeping track of line-to-line (initialize and reset)
    offset=0;


    /* Read file line by line until hash is found */
    while ( line = read_line(fp) ) {
    	//printf("%s  %s\n",image_name,line);
        if ( strstr(line, image_name) ){
            token1 = strtok(line, s);  // Get the name of the image from the saved file
            token2 = strtok(NULL, s); // Get the hash
            //printf("ENCLAVE-debug: line: %s and the file_name: %s...\n",token1, image_name);
            if(strcmp(token1,image_name)==0){
            	//if there is match, free the allocated line and return 'token' saved hash
                free(line);
                return token2;
            }
        }
            free(line);
   }


    sgx_fclose(fp);
    return NULL;
}

/* Compares two hashes and returns 'true' if equal, otherwise, 'false' is returned. */
bool hash_equal(char *hash1, char *hash2){
	if(!strstr(hash1, hash2)){
		return false;
	}

	return true;
}

/* Performs the Image Integrity Verifier Mechanism. First, a hash
 * is searched, using the name of the image that is about to be verified,
 * in the well-known hash list, store encrypted/sealed in
 * untrusted memory.Then, if there is a match, the hash is stored in 'getHash'
 * and the mechanism will calculate a new fresh hash using the image. The result
 * of the hash calculation is stored in 'calcHash'. Finally, both hashes 'getHash'
 * and 'calcHash' are compared and the result of the verification is return to the
 * requester.
 * This function takes as input arguments the image's name 'image_name' and the
 * location of it in untrusted memory. As a responds, it returns the status of
 * the verification process. see 'enum IIV_status' in edl for more information.
 * */

enum IIV_status ecall_ImagVerify(char * image_name, char * image_path){

	char *getHash;
	char calcHash[65];

/* Search for a matching hash for 'image_name' */

	getHash=find_hash(image_name, "hash_trusted_list.txt");
	//printf("%s The return hash is %s\n",image_name,getHash);

	if(!getHash){
		//printf("No hashing match for 'image_name' or hashing list is missing\n");
		return NOHASHFND;
	}

/* Calculate a new fresh hash for 'image_name' located in 'image_path' */

	//Calculate a 256-bit hash and save it as a 64 Hex representation.
	ocall_sha256_file(image_path, calcHash,65); //ocall to compute sha256 hash, populates digest with the result
	//printf("ENCLAVE-Debug: The calculated hash is %s\n",calcHash);

/* Verification Process */
	if(hash_equal(getHash,calcHash)){
		//printf("The image has been verified and the result is OK\n");
		return IMAGEOK;
	}
	return IMAGENOK;

}
















