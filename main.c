/*
 * main.c
 *
 *  Created on: Aug 6, 2013
 *      Author: rick
 */

#include<openssl/sha.h>
#include<openssl/err.h>
#include<openssl/ssl.h>
#include<openssl/rand.h>
#include<openssl/evp.h>
#include<openssl/aes.h>

#include<string.h>
#include<stdio.h>
#include<stdlib.h>

int main(){

	unsigned char *data;
	unsigned char *decrypted_data;

	EVP_CIPHER_CTX ctx;
	const EVP_CIPHER *cipher;

	unsigned char *encrypted_data;

	int size_encrypted_data = 0;
	int final_encrypted_size = 0;
	int size_decrypted_data = 0;
	int final_decrypted_size = 0;

	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_ciphers();
	OPENSSL_add_all_algorithms_conf();

	unsigned char *key;
	key = (unsigned char *)calloc(16 + 1, sizeof(unsigned char));
	unsigned char iv[] = {1,2,3,4,5,6,7,8,1,2,3,4,5,6,7,8};

	FILE * pFile;
	long lSize;
	unsigned char * buffer;
	size_t result;

	pFile = fopen("confirmacao.pdf", "rb");
	if (pFile == NULL) {
		fputs("File error", stderr);
		exit(1);
	}

	// obtain file size:
	fseek(pFile, 0, SEEK_END);
	lSize = ftell(pFile);
	rewind(pFile);

	// allocate memory to contain the whole file:
	buffer = (char*) malloc(sizeof(unsigned char) * lSize);
	if (buffer == NULL) {
		fputs("Memory error", stderr);
		exit(2);
	}

	// copy the file into the buffer:
	result = fread(buffer, 1, lSize, pFile);
	fclose(pFile);

	data = (unsigned char *)"Mensagem de texto. Quero que este texto tenha em torno de 80 caracteres 12345678 Agora aumentando o texto para ver se o meu programa realmente está cifrando textos de qualquer tamanho!!!";

	RAND_bytes(key, 16);

	cipher = EVP_get_cipherbynid(NID_aes_128_cbc);

	int tam_aloc2 = lSize;
	tam_aloc2 = tam_aloc2 + ( 16 - (tam_aloc2 % (cipher->block_size )));
	encrypted_data = malloc(tam_aloc2 );

	EVP_CIPHER_CTX_init(&ctx);
	EVP_CipherInit_ex(&ctx, cipher, NULL, key, iv, 1);
	EVP_CipherUpdate(&ctx, encrypted_data, &size_encrypted_data, buffer, lSize);
	EVP_CipherFinal_ex(&ctx, encrypted_data + size_encrypted_data, &final_encrypted_size);

	size_encrypted_data += final_encrypted_size;

	int tam_enc = size_encrypted_data;
	decrypted_data = malloc(tam_enc - 5);

	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, cipher, NULL, key, iv);
	EVP_DecryptUpdate(&ctx, decrypted_data, &size_decrypted_data, encrypted_data, size_encrypted_data);
	EVP_DecryptFinal_ex(&ctx, decrypted_data + size_decrypted_data, &final_decrypted_size);

	final_decrypted_size += size_decrypted_data;

	pFile = fopen ("confirmacao2.pdf", "wb");
	fwrite (decrypted_data , sizeof(unsigned char), final_decrypted_size, pFile);
	fclose (pFile);

	//printf("Dado decifrado: %s \n", decrypted_data);

	return 0;
}
