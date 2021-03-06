#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
//#include <openssl/rand.h>

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
	const unsigned char * p = (const unsigned char*)pv;
	if (NULL == pv)
		printf("NULL");
	else
	{
		size_t i = 0;
		for (; i<len;++i)
			printf("%02X ", *p++);
	}
	printf("\n");
}

#define KEYLENGTH 128
#define TEST_CASE 1
// main entrypoint
int main(int argc, char **argv)
{

#if 0

	/**
 * Test 1 of RFC3602
 */
	aes_cbc1 = {
		.alg = ENCR_AES_CBC, .key_size = 16, .len = 16,
		.key	= "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06",
		.iv		= "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41",
		.plain	= "Single block msg",
		.cipher	= "\xe3\x53\x77\x9c\x10\x79\xae\xb8\x27\x08\x94\x2d\xbe\x77\x18\x1a"
	};

	/**
 * Test 2 of RFC3602
 */
	aes_cbc2 = {
		.alg = ENCR_AES_CBC, .key_size = 16, .len = 32,
		.key	= "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a",
		.iv		= "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58",
		.plain	= "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
		"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
		.cipher	= "\xd2\x96\xcd\x94\xc2\xcc\xcf\x8a\x3a\x86\x30\x28\xb5\xe1\xdc\x0a"
		"\x75\x86\x60\x2d\x25\x3c\xff\xf9\x1b\x82\x66\xbe\xa6\xd6\x1a\xb1"
	};

	/**
 * Test 3 of RFC3602
 */
	aes_cbc3 = {
		.alg = ENCR_AES_CBC, .key_size = 16, .len = 64,
		.key	= "\x56\xe4\x7a\x38\xc5\x59\x89\x74\xbc\x46\x90\x3d\xba\x29\x03\x49",
		.iv		= "\x8c\xe8\x2e\xef\xbe\xa0\xda\x3c\x44\x69\x9e\xd7\xdb\x51\xb7\xd9",
		.plain	= "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf"
		"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
		"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf"
		"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf",
		.cipher	= "\xc3\x0e\x32\xff\xed\xc0\x77\x4e\x6a\xff\x6a\xf0\x86\x9f\x71\xaa"
		"\x0f\x3a\xf0\x7a\x9a\x31\xa9\xc6\x84\xdb\x20\x7e\xb0\xef\x8e\x4e"
		"\x35\x90\x7a\xa6\x32\xc3\xff\xdf\x86\x8b\xb7\xb2\x9d\x3d\x46\xad"
		"\x83\xce\x9f\x9a\x10\x2e\xe9\x9d\x49\xa5\x3e\x87\xf4\xc3\xda\x55"
	};

	/**
 * Test F.2.1 of NIST SP 800-38A 2001
 */
	aes_cbc4 = {
		.alg = ENCR_AES_CBC, .key_size = 16, .len = 64,
		.key	= "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
		.iv		= "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		.plain	= "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
		"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
		"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
		"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
		.cipher	= "\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d"
		"\x50\x86\xcb\x9b\x50\x72\x19\xee\x95\xdb\x11\x3a\x91\x76\x78\xb2"
		"\x73\xbe\xd6\xb8\xe3\xc1\x74\x3b\x71\x16\xe6\x9e\x22\x22\x95\x16"
		"\x3f\xf1\xca\xa1\x68\x1f\xac\x09\x12\x0e\xca\x30\x75\x86\xe1\xa7"
	};

	/**
 * Test F.2.3 of NIST SP 800-38A 2001
 */
	aes_cbc5 = {
		.alg = ENCR_AES_CBC, .key_size = 24, .len = 64,
		.key	= "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5"
		"\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
		.iv		= "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		.plain	= "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
		"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
		"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
		"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
		.cipher	= "\x4f\x02\x1d\xb2\x43\xbc\x63\x3d\x71\x78\x18\x3a\x9f\xa0\x71\xe8"
		"\xb4\xd9\xad\xa9\xad\x7d\xed\xf4\xe5\xe7\x38\x76\x3f\x69\x14\x5a"
		"\x57\x1b\x24\x20\x12\xfb\x7a\xe0\x7f\xa9\xba\xac\x3d\xf1\x02\xe0"
		"\x08\xb0\xe2\x79\x88\x59\x88\x81\xd9\x20\xa9\xe6\x4f\x56\x15\xcd"
	};

	/**
 * Test F.2.5 of NIST SP 800-38A 2001
 */
	aes_cbc6 = {
		.alg = ENCR_AES_CBC, .key_size = 32, .len = 64,
		.key	= "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
		"\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
		.iv		= "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
		.plain	= "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
		"\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51"
		"\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef"
		"\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
		.cipher	= "\xf5\x8c\x4c\x04\xd6\xe5\xf1\xba\x77\x9e\xab\xfb\x5f\x7b\xfb\xd6"
		"\x9c\xfc\x4e\x96\x7e\xdb\x80\x8d\x67\x9f\x77\x7b\xc6\x70\x2c\x7d"
		"\x39\xf2\x33\x69\xa9\xd9\xba\xcf\xa5\x30\xe2\x63\x04\x23\x14\x61"
		"\xb2\xeb\x05\xe2\xc3\x9b\xe9\xfc\xda\x6c\x19\x07\x8c\x6a\x9d\x1b"
	};

#endif



#ifndef TEST_CASE
	/* generate a key with a given length */
	unsigned char aes_key[KEYLENGTH/8] = "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a";

	/* generate input with a given length */

	unsigned char aes_input[32] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
								  "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";


	/* init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58",
			iv_dec[AES_BLOCK_SIZE] = "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58";

#else
	/* generate a key with a given length */
	unsigned char aes_key[256/8] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
									0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
									0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
									0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};


	/* generate input with a given length */
	unsigned char aes_input[64] =
	{
		/* inner IP header (20 bytes) */
		0x45, 0x00, 0x00, 0x3C,
		0x58, 0xDF, 0x40, 0x00,
		0x40, 0x06, 0x5E, 0x61,
		0xC0, 0xA8, 0x01, 0x28,
		0xC0, 0xA8, 0x01, 0x03,
		/* TCP header */
		0x80, 0x0A, 0x00, 0x50, 0x47, 0x67, 0xC8, 0xD1, 0x00, 0x00, 0x00, 0x00,
		0xA0, 0x02, 0x7E, 0xB8, 0xEB, 0x81, 0x00, 0x00, 0x02, 0x04, 0x3F, 0x5C, 0x04, 0x02, 0x08, 0x0A,
		0x00, 0x07, 0x90, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x00,
		/* padding */
		0x01, 0x02,
		/* padd len */
		0x02,
		/* next protocol*/
		0x04,
	} ;


	/* init vector */
	unsigned char iv_enc[AES_BLOCK_SIZE] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
											0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81},
	iv_dec[AES_BLOCK_SIZE] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
							  0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81};


#endif

	size_t inputslength = sizeof(aes_input) ;
	printf("inputslength: %d \n", inputslength);


	// buffers for encryption and decryption
	unsigned char enc_out[inputslength];
	unsigned char dec_out[inputslength];
	memset(enc_out, 0, sizeof(enc_out));
	memset(dec_out, 0, sizeof(dec_out));

	// so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, 256, &enc_key);
	AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);

	AES_set_decrypt_key(aes_key, 256, &dec_key);
	AES_cbc_encrypt(enc_out, dec_out, inputslength, &dec_key, iv_dec, AES_DECRYPT);

	printf("original:\t");
	hex_print(aes_input, sizeof(aes_input));
	printf("inputslength: %lu \n", inputslength);

	printf("encrypt:\t");
	hex_print(enc_out, sizeof(enc_out));

	printf("decrypt:\t");
	hex_print(dec_out, sizeof(dec_out));
	printf("dec_out: %s \n", dec_out);

	return 0;
}
