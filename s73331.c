#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#define BUF_SIZE 16384

/*
 * logic functions
 */

/*
 * decrypts the given cipher into buf_plain
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
 * hashes message with specified algorithm into buf_hash
 * return:
 * 	       0: success
 *     non-0: failure
 */
int hash(unsigned char *message, int message_bytes, unsigned char *buf_hash, const EVP_MD *algorithm)
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
 * return value is number of bytes written
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

/*
 * decrypts the cipher given in the cipher file into buf_plain
 */
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
 * Verifies the digest file with the key file against the signature file
 *
 * return:
 *     1 Verification OK
 *     0 Verification Failure
 *     negative value: error
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
	if (hash(buf_message, bytes_message, buf_digest, EVP_sha1()) != 0)
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
int task3(unsigned char *plain, int plain_bytes, char *file_name)
{
	printf("\nAufgabe 3:\n");

	unsigned char buf_digest[MD4_DIGEST_LENGTH];
	char output[BUF_SIZE];
	int ret = 0;

	if (MD4(plain, plain_bytes, buf_digest) == 0) {
		strcpy(output, "\tError when hashing plaintext\n");
	} else if (write_file(file_name, buf_digest, MD4_DIGEST_LENGTH)) {
		strcpy(output, "\tSuccessfully hashed plaintext to file ");
		strcat(output, file_name);
		strcat(output, "\n");
		ret = 1;
	} else {
		strcpy(output, "\tError when writing hash to file ");
		strcat(output, file_name);
		strcat(output, "\n");
	}
	printf(output);
	return ret;
}

int main()
{
	char *cipher_file_name_template = "s73331-cipher0%i.bin";
	char *key_file_name = "s73331-key.bin";
	char *pubkey_file_name = "pubkey.pem";
	char *signature_file_name = "s73331-sig.bin";
	char *hash_output_file_name = "s73331-hash.bin";

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

	if (bytes_out > 0)
		write_file("plain.pdf", buf_plain, bytes_out);
	else
		return 2;

	int result = task3(buf_plain, bytes_out, hash_output_file_name);
	printf("\n");

	if (result == 0)
		return 3;

	return 0;
}
