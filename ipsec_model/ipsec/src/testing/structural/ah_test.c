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

/** @file ah_test.c
 *  @brief Test functions for IP Authentication Header (AH)
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch>
 *
 *  <B>OUTLINE:</B>
 *
 *  This file contains test functions used to verify the AH code.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  There are no implementation hints to be mentioned.
 *
 *  <B>NOTES:</B>
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include <string.h>

#include "ipsec/util.h"
#include "ipsec/ah.h"
#include "ipsec/sa.h"
#include "ipsec/debug.h"
#include "testing/structural/structural_test.h"


static unsigned char enc_ah_packet1[104] =
		/* outter IP header (20 bytes) */
		"\x45\x00\x00\x68\xe8\x03\x00\x00\x40\x33\xb4\x39\xac\x11\x43\x01\xac\x11\x43\x02"

		/* ah header (12 bytes) */
		"\x04\x04\x00\x00\x00\x00\x10\x06\x00\x00\x00\x01"

		/* ICV (12 bytes) */
		"\x3d\x8b\x9f\x0f\xb3\x9d\xe1\x0e\xae\xe2\x08\xe6"

		/* inner IP header (20 bytes) */
		"\x45\x00\x00\x3c\x58\xdf\x40\x00\x40\x06\x5e\x61\xc0\xa8\x01\x28\xc0\xa8\x01\x03"
		"\x80\x0a\x00\x50\x47\x67\xc8\xd1\x00\x00\x00\x00\xa0\x02\x7e\xb8\xeb\x81\x00\x00"
		"\x02\x04\x3f\x5c\x04\x02\x08\x0a\x00\x07\x90\x0e\x00\x00\x00\x00\x01\x03\x03\x00";


static unsigned char dec_ah_packet1[60] =
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


static sad_entry packet1_sa = { 	SAD_ENTRY_NEW(	192,168,1,3, 255,255,255,255,
									0x00001006,
									IPSEC_PROTO_AH, IPSEC_TUNNEL,
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





/**
 * Test the ICV- and header-check of an AH-protected packet
 * @return int number of tests failed in this function
 */
int ah_test_ipsec_ah_decapsulate(void)
{

	int local_error_count	= 0;
	int payload_size 		= 0;
	int payload_offset		= 0;
	int ret_val;

	// feed valid AH packet
	ret_val = ipsec_ah_decapsulate((ipsec_ip_header *)&enc_ah_packet1, (int *)&payload_offset, (int *)&payload_size, (sad_entry *)&packet1_sa);
	if(ret_val != IPSEC_STATUS_SUCCESS) {
		local_error_count++;
		IPSEC_LOG_TST("ah_test_ipsec_ah_decapsulate 11 ", "FAILURE", ("ipsec_ah_decapsulate(ah_test_sample_ah_packet) failed")) ;
	}

	return local_error_count;
}

/**
 * Tests encapsulating an IP packet into an AH header
 * @return int number of tests failed in this function
 */
int ah_test_ipsec_ah_encapsulate(void) 
{


	int local_error_count 	= 0;
	int payload_size 		= 0;
	int payload_offset		= 0;

	int ret_val = 0;
	int _start = 100;
	unsigned char buffer[sizeof (dec_ah_packet1) /*60 inner ip packet*/ + _start];

	local_error_count = 0;


	/* copy packet in a buffer where space for the new headers is left */
	memcpy(buffer + _start, dec_ah_packet1, sizeof(dec_ah_packet1));

	ret_val = ipsec_ah_encapsulate((ipsec_ip_header *)(buffer + _start),
								   (int *)&payload_offset, (int *)&payload_size,
								   (void *)&packet1_sa,
								   ipsec_inet_addr("172.17.67.1"/*src*/) , ipsec_inet_addr("172.17.67.2"/*dst*/)
								   );
	if(ret_val != 0) {
		local_error_count++;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("ipsec_ah_encapsulate() failed (rev_val indicates no SUCCESS)")) ;
	}

	if(payload_offset != -44) /* 20 outer ip header + 12 ah header + 12 icv */
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("offset was not calculated properly")) ;
	}

	if(payload_size != 104) /* 20 outer ip header + 12 ah header + 12 icv + 60 inner ip packet  */
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("length was not calculated properly")) ;
	}

	payload_offset = -44;
	payload_size = 104;

	if(memcmp(((char*)(buffer + _start)) + payload_offset, enc_ah_packet1, payload_size) != 0)
	{
		local_error_count++ ;
		IPSEC_LOG_TST("ah_test_ipsec_ah_encapsulate", "FAILURE", ("packet was not properly encapsulated"));
	}

	return local_error_count;
}

/**
 * Main test function for the AH tests.
 * It does nothing but calling the subtests one after the other.
 */
void ah_test(test_result *global_results)
{
	test_result 	sub_results	= {
		6,
		2,
		0,
		0,
	};

	int retcode;


	retcode = ah_test_ipsec_ah_encapsulate();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ah_test_ipsec_ah_encapsulate()", (""));


	retcode = ah_test_ipsec_ah_decapsulate();
	IPSEC_TESTING_EVALUATE(retcode, sub_results, "ah_test_ipsec_ah_decapsulate()", (""));


	global_results->tests += sub_results.tests;
	global_results->functions += sub_results.functions;
	global_results->errors += sub_results.errors;
	global_results->notimplemented += sub_results.notimplemented;
}



