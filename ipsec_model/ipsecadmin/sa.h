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

/** @file sa.h
 *  @brief This module contains Security Association management code
 *
 *  @author Niklaus Schild <n.schild@gmx.ch>
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.<BR>
 * This file contains code from the OpenSSL Project<BR>
 * portions Copyright (c) 1998-2003 OpenSSL (www.openssl.org)
 *</EM><HR>
 */

#ifndef __SA_H__
#define __SA_H__

typedef unsigned char __u8 ;
typedef unsigned short __u16 ;
typedef unsigned long __u32 ;

/** \def IPSEC_MAX_SPD_ENTRIES 
 * Defines the size of SPD entires in the SPD table.
 */
#define IPSEC_MAX_SAD_ENTRIES	(10)

/** \def IPSEC_MAX_SAD_ENTRIES 
 * Defines the size of SAD entires in the SAD table.
 */
#define IPSEC_MAX_SPD_ENTRIES	(10)	//< Defines the number of SPD entries

/** \def IPSEC_FREE
 * Tells you that an SPD entry is used
 */
#define IPSEC_FREE	(0)				

/** \def IPSEC_USED
 * Tells you that an SPD entry is free
 */
#define IPSEC_USED	(1)				

/** \def POLICY_APPLY
 * Defines that the policy for this SPD entry means: apply IPsec
 */
#define POLICY_APPLY	(0)

/** \def POLICY_BYPASS
 * Defines that the policy for this SPD entry means: bypass IPsec
 */
#define POLICY_BYPASS	(1)

/** \def POLICY_DISCARD
 * Defines that the policy for this SPD entry means: the packet must be discared
 */
#define POLICY_DISCARD	(2)			

/** \def IPSEC_DES_KEY_LEN
 * Defines the size of a DES key in bytes.
 */
#define IPSEC_DES_KEY_LEN	(8)	

/** \def IPSEC_MAX_ENCKEY_LEN	
 * Defines the maximum encryption key length of our IPsec system.
 */
#define IPSEC_MAX_ENCKEY_LEN	(IPSEC_3DES_KEY_LEN)

/** \def IPSEC_3DES_KEY_LEN	
 * Defines the length of a 3DES key in bytes.
 */
#define IPSEC_3DES_KEY_LEN		(IPSEC_DES_KEY_LEN*3)

#define IPSEC_AUTH_ICV			(12)	/**< Defines the authentication key length in bytes (12 bytes for 96bit keys) */
#define IPSEC_AUTH_MD5_KEY_LEN	(16)	/**< Length of MD5 secret key  */
#define IPSEC_AUTH_SHA1_KEY_LEN	(20)	/**< Length of SHA1 secret key */
#define IPSEC_MAX_AUTHKEY_LEN  (IPSEC_AUTH_SHA1_KEY_LEN) /**< maximum length of authentication keys */

#define IPSEC_TUNNEL			(1)
#define IPSEC_TRANSPORT			(0)

#define IPSEC_DES				(1)
#define IPSEC_3DES				(2)
#define IPSEC_IDEA				(3)

#define IPSEC_HMAC_MD5			(1)
#define IPSEC_HMAC_SHA1			(2)

#define IPSEC_NR_NETIFS			(1)

typedef struct sa_entry_struct sad_entry ;

/** \struct sa_entry_struct
 * Holds all the values used by an SA entry
 */
struct sa_entry_struct
{
	__u32 		dest __attribute__ ((packed));
	__u32		dest_netaddr __attribute__ ((packed));
	__u32 		spi __attribute__ ((packed));	
	__u8		protocol __attribute__ ((packed));
	__u8		mode __attribute__ ((packed));	
	__u32		sequence_number __attribute__ ((packed));
	__u8		replay_win __attribute__ ((packed)) ;		
	__u32		lifetime __attribute__ ((packed));		
	__u16		path_mtu __attribute__ ((packed));
	__u8		enc_alg __attribute__ ((packed));
	__u8		enckey[IPSEC_MAX_ENCKEY_LEN] __attribute__ ((packed));
	__u8		auth_alg __attribute__ ((packed));
	__u8		authkey[IPSEC_MAX_AUTHKEY_LEN] __attribute__ ((packed)) ;
	sad_entry	*next __attribute__ ((packed));
	sad_entry	*prev __attribute__ ((packed));
	__u8		use_flag __attribute__ ((packed));
};

/** \var typedef spd_entry_struct spd_entry
 * This type hold all values used for an SAD entry.
 */
typedef struct spd_entry_struct spd_entry ;

struct spd_entry_struct
{
	__u32		src __attribute__ ((packed));		
	__u32  		src_netaddr __attribute__ ((packed));	
	__u32		dest __attribute__ ((packed));		
	__u32		dest_netaddr __attribute__ ((packed));	
	__u8		protocol __attribute__ ((packed));	
	__u16		src_port __attribute__ ((packed));	
	__u16		dest_port __attribute__ ((packed));	
	__u8		policy __attribute__ ((packed));	
	sad_entry 	*sa __attribute__ ((packed));		
	spd_entry	*next __attribute__ ((packed));		
	spd_entry	*prev __attribute__ ((packed));		
	__u8		use_flag __attribute__ ((packed)); 	
};


typedef struct spd_table_struct
{
	spd_entry	*table ;
	spd_entry	*first ;
	spd_entry	*last ;
	int			size ;
} spd_table;

typedef struct sad_table_struct
{
	sad_entry	*table ;
	sad_entry	*first ;
	sad_entry	*last ;
} sad_table ;

typedef struct db_set_netif_struct
{
	spd_table	inbound_spd ;
	spd_table	outbound_spd ;
	sad_table	inbound_sad ;
	sad_table	outbound_sad ;
	__u8		use_flag ;
} db_set_netif ;




#endif
