/*
 * embedded IPsec
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** @file esp_test.c
 *  @brief Testing ESP encapsulation and decapsulation
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 *  <B>OUTLINE:</B>
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  <B>NOTES:</B>
 *
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"

#include "ipsec/sa.h"
#include "ipsec/esp.h"

static unsigned char enc_esp_packet2[120] =
	/* IP header */
	"\x45\x00\x00\x78\xe8\x03\x00\x00\x40\x32\xb4\x2a\xac\x11\x43\x01\xac\x11\x43\x02"
	/* ESP header */
	"\x00\x00\x10\x06\x00\x00\x00\x01"
	/* IV */
	"\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81"
	/* encrypted payload */
	"\xbd\x89\x89\x95\x78\xaf\x22\xff\x93\xf2\x95\x93\x76\x29\x4e\x18\x80\x46\xc7\xc5\x25\x1e\x09\xe3\xb1\xb2\x24\x6e\x48\xb3\xb5\xd7\x46\x6d\x93\x1a\xdf\x6f\x36\xfe\x70\x3d\x61\x5b\xf9\x70\xff\xd2\x5c\xe3\x5e\x10\xd4\x9e\xae\x6b\x51\x9d\xf3\x67\x6e\x2a\x52\xeb"
	/* ICV */
	"\x56\xda\x4e\x77\x9a\x00\x84\x37\x49\xc4\x7d\x1c";


static unsigned char dec_esp_packet2_origin[60] =
{
	/* inner IP header (20 bytes) */
	0x45, 0x00, 0x00, 0x3C,
	0x58, 0xDF, 0x40, 0x00,
	0x40, 0x06, 0x5E, 0x61,
	0xC0, 0xA8, 0x01, 0x28, /* 192.168.1.40 */
	0xC0, 0xA8, 0x01, 0x03, /* 192.168.1.3 */
	/* TCP header */
	0x80, 0x0A, 0x00, 0x50, 0x47, 0x67, 0xC8, 0xD1, 0x00, 0x00, 0x00, 0x00,
	0xA0, 0x02, 0x7E, 0xB8, 0xEB, 0x81, 0x00, 0x00, 0x02, 0x04, 0x3F, 0x5C, 0x04, 0x02, 0x08, 0x0A,
	0x00, 0x07, 0x90, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x00,
} ;

static unsigned char dec_esp_packet2[64] =
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


static sad_entry packet2_sa = { 	SAD_ENTRY_NEW(	192,168,1,3, 255,255,255,255,
							0x00001006,
							IPSEC_PROTO_ESP, IPSEC_TUNNEL,
							IPSEC_AES_CBC,
							/* enckey */
							0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
							0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
							IPSEC_HMAC_SHA256,
							/* authkey */
							0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
							0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
							/* enc_key_len, auth_key_len */
							256, 256,
							/* icv_bytes_len, iv_bytes_len */
							12, 16,
							/* iv[16] */
							0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
							)
					   } ;



static unsigned char esp_packet_tmp [500] ;






/**
 * Checks if ESP encapsulation works (used for IPsec outbound processing)
 * 6 tests
 */
int test_esp_encapsulate(void)
{
	int			offset = 0, len = 0;
	sad_entry	*sa ;

	int start = 44;
	memset(esp_packet_tmp, 0, 500) ;
	memcpy(&esp_packet_tmp[start], dec_esp_packet2_origin, sizeof(dec_esp_packet2_origin)) ;
	sa = &packet2_sa ;

	printf("sa->iv_bytes_len: %d \n", sa->iv_bytes_len);
	printf("sa->enc_key_len: %d \n", sa->enc_key_len);
	printf("sa->auth_key_len: %d \n", sa->auth_key_len);
	printf("sa->icv_bytes_len: %d \n", sa->icv_bytes_len);


	ipsec_esp_encapsulate((ipsec_ip_header*)&esp_packet_tmp[start],
			&offset, &len, (void*)sa,
			ipsec_inet_addr("172.17.67.1") /*src*/, ipsec_inet_addr("172.17.67.2") /*dst*/) ;
	printf("offset: %d, len: %d \n", offset, len);

	return IPSEC_STATUS_SUCCESS ;
}





/**
 * Check if ESP decapsulation works (used for IPsec inbound processing).
 * 6 tests are performed here
 */
int test_esp_decapsulate(void)
{
	int			offset, len ;
	sad_entry	*sa ;

	/* test decryption of packet 1 */
	memcpy(esp_packet_tmp, enc_esp_packet2, 484) ;
	sa = &packet2_sa ;

	ipsec_esp_decapsulate((ipsec_ip_header*)esp_packet_tmp, &offset, &len, sa) ;
	

	return IPSEC_STATUS_SUCCESS ;
}

/**
 * Main test function for the ESP tests.
 * It does nothing but calling the subtests one after the other.
 */
void esp_test(test_result *global_results)
{
	test_result 	sub_results	= {
						 12, 		
						  2,			
						  0, 
						  0, 			
					};

	int retcode;

	retcode = test_esp_encapsulate() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "test_esp_encapsulate", (" "));

	retcode = test_esp_decapsulate() ;
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "test_esp_decapsulate", (" "));


	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}


