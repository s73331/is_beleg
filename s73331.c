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
void usage(char *call_name)
{
	printf("error\n");
	printf("usage: %s i\n", call_name);
	printf("Replace i with one of the following numbers.\n");
	printf("1. Prüfen Sie, zu welchem Chiffrat s73331-cipher01.bin, s73331-cipher02.bin oder s73331-cipher03.bin die Signatur s73331-sig.bin gehört. Nutzen Sie dazu den bereitgestellten öffentlichen Schlüssel pubkey.pem und das Hashverfahren SHA-1.\n");
	printf("2. Entschlüsseln Sie das identifizierte Chiffrat mit Hilfe des Schlüssels s73331-key.bin. Falls ein Initialisierungsvektor nötig ist, so ist dieser im Anschluss an den Schlüssel in dieser Datei abgelegt. Der Klartext wurde mittels des Verfahrens AES-128-ECB verschlüsselt. (Das Verfahren wird durch die Funktion EVP_aes_128_ecb() der OpenSSL-Bibliothek implementiert). Der Klartext ist ein Dokument im PDF.\n");
	printf("3. Bilden Sie einen kryptografischen Hash über dem korrekt entschlüsselten Klartext. Nutzen Sie das Verfahren EVP_md4(), das durch die Funktion der OpenSSL-Bibliothek implementiert wird. Speichern Sie den Hash in einer Datei s73331-hash.bin.\n");
}

/*
 * FILE FUNCTIONS
 */
/*
 * return value is number of bytes read
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

	// hash
	EVP_MD_CTX ctx;
	if (EVP_DigestInit(&ctx, EVP_sha1()) == 0) {
		return 0;
	}
	if (EVP_DigestUpdate(&ctx, buf, bytes) == 0) {
		return 0;
	}
	unsigned char hash[SHA_DIGEST_LENGTH];
	if (EVP_DigestFinal(&ctx, hash, NULL) == 0) {
		return 0;
	}

	// write to file
	char new_file_name[BUF_SIZE];
	strcpy(new_file_name, file_name);
	strcat(new_file_name, "-sig.bin");
	return write_file(new_file_name, hash, 20);
}

/*
 * Verifies the digest file with the key file against the signature file
 *
 * return:
 * 1 Verification OK
 * 0 Verification Failure
 * negative value: error
 */
int rsa_verify_file(char *digest_file_name, char *key_file_name, char *signature_file_name)
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
	unsigned char buf_digest[BUF_SIZE];
	int bytes_digest = read_file(digest_file_name, buf_digest, sizeof(buf_digest));
	if (bytes_digest == 0)
		return -3;
	int result = RSA_verify(NID_sha1, buf_digest, bytes_digest, buf_signature, bytes_signature, rsa);
	return result;
}


int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage(argv[0]);
		return 1;
	}
	//char buf[BUF_SIZE];

	//read_file("s73331.c", buf, sizeof(buf));

	if (sha1_file("s73331-cipher01.bin") == 0) {
		error();
		return 2;
	}
	if (sha1_file("s73331-cipher02.bin") == 0) {
		error();
		return 3;
	}
	if (sha1_file("s73331-cipher03.bin") == 0) {
		error();
		return 4;
	}
	int result1 = rsa_verify_file("s73331-cipher01.bin-sig.bin", "pubkey.pem", "s73331-sig.bin");
	if (result1 < 0) {
		error();
		return 5;
	}
	int result2 = rsa_verify_file("s73331-cipher02.bin-sig.bin", "pubkey.pem", "s73331-sig.bin");
	if (result2 < 0) {
		error();
		return 6;
	}
	int result3 = rsa_verify_file("s73331-cipher03.bin-sig.bin", "pubkey.pem", "s73331-sig.bin");
	if (result3 < 0) {
		error();
		return 7;
	}
	printf("Results for signature check:\n1: %i\n2: %i\n3: %i\n", result1, result2, result3);

	return 0;
}
