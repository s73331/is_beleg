#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>


#define BUF_SIZE 16384

/*
 * ORGANIZATIONAL FUNCTIONS
 */
void error()
{
	printf("An error occured.");
}

/*
 *
 */
int decrypt_aes_128_ecb(unsigned char *cipher, int cipher_bytes, unsigned char *key, unsigned char *buf_plain, int *bytes_out)
{
	EVP_CIPHER_CTX ctx;
	if (EVP_DecryptInit(&ctx, EVP_aes_128_ecb(), key, NULL) == 0)
		return -1;
	if (EVP_DecryptUpdate(&ctx, buf_plain, bytes_out, cipher, cipher_bytes) == 0)
		return -2;
	return 1;
}

/*
 * hashes message with sha1 into buf_hash
 * return:
 * 	       0: success
 *     non-0: failure
 */
int sha1(unsigned char *message, int message_bytes, unsigned char *buf_hash)
{
	// hash
	EVP_MD_CTX ctx;
	if (EVP_DigestInit(&ctx, EVP_sha1()) == 0) {
		return 1;
	}
	if (EVP_DigestUpdate(&ctx, message, message_bytes) == 0) {
		return 2;
	}
	if (EVP_DigestFinal(&ctx, buf_hash, NULL) == 0) {
		return 3;
	}
	return 0;
}

/*
 * FILE FUNCTIONS
 */
/*
 * return:
 *     value is number of bytes read
 */
int read_file(char *file_name, unsigned char *buf, int buf_size)
{
	FILE* file = fopen(file_name, "rb");
	if (file == NULL) {
		return 0;
	}
	int bytes = fread(buf, 1, buf_size, file);
	fclose(file);
	return bytes;
}
/*
 * return value is number of bytes read
 */
int write_file(char *file_name, unsigned char *buf, int bytes_to_write)
{
	FILE* file = fopen(file_name, "wb");
	if (file == NULL) {
		return 0;
	}
	int bytes = fwrite(buf, 1, bytes_to_write, file);
	fclose(file);
	return bytes;
}

int decrypt_aes_128_ecb_file(char *cipher_file_name, char *key_file_name, unsigned char *buf_plain, int *bytes_out)
{
	unsigned char buf_cipher[BUF_SIZE];
	int bytes = read_file(cipher_file_name, buf_cipher, sizeof(buf_cipher));
	if (bytes == 0) {
		return 0;
	}

	unsigned char buf_key[16];
	int bytes_key = read_file(key_file_name, buf_key, sizeof(buf_key));
	if (bytes_key == 0) {
		return 0;
	}

	return decrypt_aes_128_ecb(buf_cipher, bytes, buf_key, buf_plain, bytes_out);
}

/*
 * Reads the file located at ./file_name,
 * calculates the sha1 hash,
 * and writes the hash to ./file_name-sig.bin
 * Return value is 0 on failure, non-0 on success.
 */
int sha1_file(char *file_name)
{
	// read file
	unsigned char buf[BUF_SIZE];
	int bytes = read_file(file_name, buf, sizeof(buf));
	if(bytes == 0) {
		return 0;
	}

	unsigned char hash[SHA_DIGEST_LENGTH];
	if (sha1(buf, bytes, hash) == 0)
		return 0;

	// write to file
	char new_file_name[BUF_SIZE];
	strcpy(new_file_name, file_name);
	strcat(new_file_name, "-sig.bin");
	return write_file(new_file_name, hash, SHA_DIGEST_LENGTH);
}


/*
 * Verifies the digest file with the key file against the signature file
 *
 * return:
 * 1 Verification OK
 * 0 Verification Failure
 * negative value: error
 */
int rsa_verify_file(char *message_file_name, char *key_file_name, char *signature_file_name)
{
	FILE *key = fopen(key_file_name, "rb");
	if (key == NULL)
		return -1;
	RSA *rsa = RSA_new();
	rsa = PEM_read_RSA_PUBKEY(key, &rsa, NULL, NULL);

	unsigned char buf_signature[BUF_SIZE];
	int bytes_signature = read_file(signature_file_name, buf_signature, sizeof(buf_signature));
	if (bytes_signature == 0)
		return -2;

	unsigned char buf_message[BUF_SIZE];
	int bytes_message = read_file(message_file_name, buf_message, sizeof(buf_message));
	if (bytes_message == 0)
		return -3;

	unsigned char buf_digest[SHA_DIGEST_LENGTH];
	if (sha1(buf_message, bytes_message, buf_digest) != 0)
		return -4;

	int result = RSA_verify(NID_sha1, buf_digest, sizeof(buf_digest), buf_signature, bytes_signature, rsa);
	return result;
}

/*
 * solution for tasks
 */
void task1(char *cipher_file_name_template, char *pubkey_file_name, char *signature_file_name, char *right_cipher_file_name)
{
	printf("\nAufgabe 1:\n");
	int i;

	for (i = 1; i < 4; i++) {
		char cipher_file_name[BUF_SIZE];
		sprintf(cipher_file_name, cipher_file_name_template, i);
		int result = rsa_verify_file(cipher_file_name, pubkey_file_name, signature_file_name);
		char output[BUF_SIZE];
		if (result > 0) {
			strcpy(output, "\tSignature did match for file ");
			strcat(output, cipher_file_name);
			strcpy(right_cipher_file_name, cipher_file_name);
		} else if (result == 0) {
			strcpy(output, "\tSignature did not match for file ");
			strcat(output, cipher_file_name);
		} else {
			strcpy(output, "\tSignature check failed for file ");
			strcat(output, cipher_file_name);
		}
		strcat(output, "\n");
		printf(output);
	}
}

void task2(char *right_cipher_file_name, char *key_file_name, unsigned char *buf_plain, int *bytes_out)
{
	printf("\nAufgabe 2:\n");
	*bytes_out = 0;
	int result = decrypt_aes_128_ecb_file(right_cipher_file_name, key_file_name, buf_plain, bytes_out);
	char output[BUF_SIZE];
	if (result == 1) {
		strcpy(output, "\tSuccessfully decrypted cipher file ");
		strcat(output, right_cipher_file_name);
		strcat(output, "\n");
	} else {
		strcpy(output, "\tError when decrypting cipher file ");
		strcat(output, right_cipher_file_name);
		strcat(output, "\n");
	}
	printf(output);
}

int main(int argc, char *argv[])
{
	char *cipher_file_name_template = "s73331-cipher0%i.bin";
	char *key_file_name = "s73331-key.bin";
	char *pubkey_file_name = "pubkey.pem";
	char *signature_file_name = "s73331-sig.bin";

	char right_cipher_file_name[BUF_SIZE];
	right_cipher_file_name[0] = 0;

	task1(cipher_file_name_template, pubkey_file_name, signature_file_name, right_cipher_file_name);

	if (right_cipher_file_name[0] == 0) {
		printf("No signature matched.\nExiting.");
		return 1;
	}

	printf("\nProgressing with cipher file %s\n", right_cipher_file_name);

	unsigned char buf_plain[BUF_SIZE];
	int bytes_out;
	task2(right_cipher_file_name, key_file_name, buf_plain, &bytes_out);
	if (bytes_out > 0) {
		write_file("plain.pdf", buf_plain, bytes_out);
	}
	printf("\n");
	return 0;
}
