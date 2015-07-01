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

/** @file netconfig.c
 *  @brief Dynamic SAD/SPD configuration over UDP port 500 ("ISAKMP light")
 *
 *  @author Niklaus Schild <n.schild@gmx.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *
 *  <B>NOTES:</B>
 *
 * (Enumerate noteworthy items)
 *
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */

#include "lwip/udp.h"
#include <string.h>

#include "ipsec/debug.h"
#include "ipsec/ah.h"
#include "ipsec/esp.h"
#include "ipsec/sa.h"


/* *** GLOBAL DATA AND DEFINITIONS ***************************************** */
				
struct netconfig_state_struct {
  int bytes_left;						// bytes left in send buffer
  int page_offset;						// offset within page
  int page_size;						// total page size
} netconfig_state;


/* *** END OF GLOBAL DATA AND DEFINITIONS ********************************** */

#define IPSEC_CONFIG_ADD		(1)
#define IPSEC_CONFIG_FLUSH		(2)
#define IPSEC_CONFIG_GET		(3)

#define IPSEC_CONFIG_IV_LEN		(8)
#define IPSEC_CONFIG_ICV_LEN	(12)

#define IPSEC_DIR_INBOUND		(1)
#define IPSEC_DIR_OUTBOUND		(2)

typedef struct config_struct
{
	unsigned char 	iv[IPSEC_CONFIG_IV_LEN] ;
	unsigned char 	icv[IPSEC_CONFIG_ICV_LEN] ;
	unsigned char 	type ;
	unsigned char 	direction ;
	spd_entry		spd ;
	sad_entry		sad ;
} config_packet ;

#ifdef PHYCORE167HSE 
	spd_entry		default_spd_inbound_entry =  {SPD_ENTRY(  192,168,1,0,     255,255,255,0,   192,168,1,4,     255,255,255,255,   IPSEC_PROTO_UDP, 0,   500, POLICY_BYPASS, 0)} ;
	spd_entry		default_spd_outbound_entry = {SPD_ENTRY(  192,168,1,4,     255,255,255,255, 192,168,1,0,     255,255,255,0,     IPSEC_PROTO_UDP, 500, 0,   POLICY_BYPASS, 0)} ;
#else
	spd_entry		default_spd_inbound_entry =  {SPD_ENTRY(  192,168,1,0,     255,255,255,0,   192,168,1,3,     255,255,255,255,   IPSEC_PROTO_UDP, 0,   500, POLICY_BYPASS, 0)} ;
	spd_entry		default_spd_outbound_entry = {SPD_ENTRY(  192,168,1,3,     255,255,255,255, 192,168,1,0,     255,255,255,0,     IPSEC_PROTO_UDP, 500, 0,   POLICY_BYPASS, 0)} ;
#endif

extern db_set_netif	*databases ;

static void netconfig_get(config_packet *config)
{
	spd_table		*spd_table ;
	sad_table		*sad_table ;

	if(config->direction == IPSEC_DIR_INBOUND)
	{
		spd_table = &databases->inbound_spd ;
		sad_table = &databases->inbound_sad ;
	} 
	else if(config->direction == IPSEC_DIR_OUTBOUND)
	{
		spd_table = &databases->outbound_spd ;
		sad_table = &databases->outbound_sad ;
	}
	else
	{
		IPSEC_LOG_ERR("netconfig_flush", -99, ("invalid direction flag in config packet")) ;
		return ;
	}	

#ifdef IPSEC_TABLES
	ipsec_spd_print(spd_table) ;
	ipsec_sad_print(sad_table) ;
#endif

}

static void netconfig_flush(config_packet *config)
{
	spd_entry		*spd ;
	spd_table		*spd_table ;
	sad_table		*sad_table ;

	if(config->direction == IPSEC_DIR_INBOUND)
	{
		spd_table = &databases->inbound_spd ;
		sad_table = &databases->inbound_sad ;
		spd = &default_spd_inbound_entry ;
	} 
	else if(config->direction == IPSEC_DIR_OUTBOUND)
	{
		spd_table = &databases->outbound_spd ;
		sad_table = &databases->outbound_sad ;
		spd = &default_spd_outbound_entry ;
	}
	else
	{
		IPSEC_LOG_ERR("netconfig_flush", -99, ("invalid direction flag in config packet")) ;
		return ;
	}

	if(ipsec_spd_flush(spd_table, 	spd) != IPSEC_STATUS_SUCCESS)
	{
		IPSEC_LOG_ERR("netconfig_flush", -99, ("unable to flush SPD database properly")) ;
	}
	if(ipsec_sad_flush(sad_table) != IPSEC_STATUS_SUCCESS)
	{
		IPSEC_LOG_ERR("netconfig_flush", -99, ("unable to flush SAD database properly")) ;
	}

#ifdef IPSEC_TABLES
	ipsec_spd_print(spd_table) ;
	ipsec_sad_print(sad_table) ;
#endif

	return ;
}

static void netconfig_add(config_packet *config)
{
	ipsec_status	status ;
	spd_entry		*spd_retval ;
	spd_table		*spd_table ;
	sad_entry		*sad_retval ;
	sad_table		*sad_table ;

	if(config->direction == IPSEC_DIR_INBOUND)
	{
		spd_table = &databases->inbound_spd ;
		sad_table = &databases->inbound_sad ;
	} 
	else if(config->direction == IPSEC_DIR_OUTBOUND)
	{
		spd_table = &databases->outbound_spd ;
		sad_table = &databases->outbound_sad ;
	}
	else
	{
		IPSEC_LOG_ERR("netconfig_add", -99, ("invalid direction flag in config packet")) ;
		return ;
	}

	spd_retval = ipsec_spd_add(	config->spd.src,
					config->spd.src_netaddr,
					config->spd.dest,
					config->spd.dest_netaddr,
					config->spd.protocol,
					config->spd.src_port,
					config->spd.dest_port,
					config->spd.policy,
					spd_table) ;
	if(spd_retval == NULL)
	{
		IPSEC_LOG_ERR("netconfig_recv", -99, ("unable to set SP")) ;
		return ;
	}

	sad_retval = ipsec_sad_add(&config->sad, sad_table) ;
	if(sad_retval == NULL)
	{
		IPSEC_LOG_ERR("netconfig_recv", -99, ("unable to set SA"));
		return ;	
	 }

	status = ipsec_spd_add_sa(spd_retval, sad_retval) ;
	if(status != IPSEC_STATUS_SUCCESS)
	{
		IPSEC_LOG_ERR("netconfig_recv", -99, ("unable to add SA to SP")) ;
		return ;
	}

#ifdef IPSEC_TABLES
	ipsec_spd_print(spd_table) ;
	ipsec_sad_print(sad_table) ;
#endif

	return ;
}


/*****************************************************************************
 * netconfig_recv()                                                          *
 * This function is called to handle lwip events                             *
 *****************************************************************************/
void netconfig_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
	config_packet	*config ;
	unsigned char	icv[IPSEC_CONFIG_ICV_LEN] ;
	int				type ;

	/* to prevent compiler warnings */
	arg = arg ;
	upcb = upcb ;
	addr = addr ;
	port = port ;

	memset(icv, 0, IPSEC_CONFIG_ICV_LEN) ;

	if(p->len > 0) *((unsigned char *)p->payload + p->len) = 0x00;

	config = (config_packet*)p->payload	;

	/* check IV */
	if(strcmp(config->iv, "ipseccnf") != 0)
	{
		IPSEC_LOG_ERR("netconfig_recv", -99, ("configuration packet with invalid IV")) ;
		return ;
	}

	/* check ICV */
	if(memcmp(icv, config->icv, IPSEC_CONFIG_ICV_LEN) != 0)
	{
		IPSEC_LOG_ERR("netconfig_recv", -99, ("configuration packet with invalid ICV")) ;
		return ;
	}

	/* packet seems to be fine */
	type = config->type ;
	switch(type)
	{
		case IPSEC_CONFIG_ADD:
			netconfig_add(config) ;	
			ipsec_ah_bitmap  = 0;			/* reset AH anti-replay counter and bit fields */ 
			ipsec_ah_lastSeq = 0;
			ipsec_esp_bitmap  = 0;			/* reset ESP anti-replay counter and bit fields */ 
			ipsec_esp_lastSeq = 0;
			break ;
		case IPSEC_CONFIG_FLUSH:
			netconfig_flush(config) ;
			break ;
		case IPSEC_CONFIG_GET:
			netconfig_get(config) ;
			break ;
		default:
			IPSEC_LOG_ERR("netconfig_recv", -99, ("configuration type: %d invalid", (int)config->type)) ;
	}
	
	pbuf_free(p);
}

/*****************************************************************************
 * dumpwebpage_init()                                                        *
 * This function must be called on system startup to init "dumpwebpage"      *
 *****************************************************************************/
void netconfig_init(void)
{
  struct udp_pcb *pcb;

  pcb = udp_new();						// create a UDP control block
  udp_bind(pcb, IP_ADDR_ANY, 500);		// bind the new connection to port 500
  udp_recv(pcb, netconfig_recv, &netconfig_state);

}

