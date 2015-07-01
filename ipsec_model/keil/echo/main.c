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

/** @file main.c
 *  @brief Demonstrate the integration of embedded IPsec in lwIP
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  Sample program combining lwIP and embedded IPsec.
 *  The data flow between physical network and TCP/IP stack is intercepted
 *  by the IPsec device driver. All captured traffic will be routed through
 *  ipsecdev_input and forwarded to ip_input. All outbound traffic will 
 *  pass the IPsec driver's output function where IPsec specific processing
 *  can be applied. Afterwards, the packet will be sent out to the wire 
 *  using the physical device driver.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  The sample is made for the pyhCORE167-HS/E board and will setup an
 *  AH tunnel between 192.168.1.4 (the MCU board) and 192.168.1.5 (a remote 
 *  IPsec device).
 *
 *  It is possible to ping the system or 
 *  connect to UDP port 7 (RFC 862 Echo Protocol)
 *
 * This document is part of <EM>embedded IPsec<BR>
 * Copyright (c) 2003 Niklaus Schild and Christian Scheurer, HTI Biel/Bienne<BR>
 * All rights reserved.</EM><HR>
 */


#include "lwip/debug.h"					/* include lwIP						*/
#include "lwip/memp.h"
#include "lwip/mem.h"
#include "lwip/ip.h"
#include "lwip/udp.h"
#include "netif/etharp.h"

#include "netif/cs8900if.h"				/* include CS8900 driver			*/

#include "netif/ipsecdev.h"				/* include IPsec device driver		*/
#include "ipsec/ipsec.h"				/* include embedded IPsec			*/
#include "ipsec/sa.h"					/* include embedded IPsec			*/

#include <reg167.h>						/* include C166 specific stuff		*/
#include <intrins.h>
#include <ctype.h>


struct netif *ethif;					/* Ethernet network interface 		*/
struct netif *ipsecif;					/* IPsec network interface 			*/



/**************************/
/* inbound configurations */
/**************************/
	
/* SAD configuartion data */
sad_entry inbound_sad_config[IPSEC_MAX_SAD_ENTRIES] = {
	SAD_ENTRY(	192,168,1,4, 255,255,255,255, 
				0x1014, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				IPSEC_HMAC_MD5,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0
			  ),
			  EMPTY_SAD_ENTRY,
			  EMPTY_SAD_ENTRY,
			  EMPTY_SAD_ENTRY

} ;

/* SPD configuration data */
spd_entry inbound_spd_config[IPSEC_MAX_SAD_ENTRIES] = {
/*            source                            destination                    protocol  ports         policy          SA pointer *
 *            address          network          address       network                    src    dest                              */
	{ SPD_ENTRY(  192,168,1,5, 255,255,255,255, 192,168,1,4,  255,255,255,255, 0, 		 0,     0,     POLICY_APPLY,   &inbound_sad_config[0]) },
   	EMPTY_SPD_ENTRY,
	EMPTY_SPD_ENTRY
} ;


/***************************/
/* outbound configurations */
/***************************/

/* SAD configuartion data */
sad_entry outbound_sad_config[IPSEC_MAX_SAD_ENTRIES] = {
	SAD_ENTRY(	192,168,1,5, 255,255,255,255, 
				0x1014, 
				IPSEC_PROTO_AH, IPSEC_TUNNEL, 
				0, 
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				IPSEC_HMAC_MD5,  
				0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0
			  ),
	EMPTY_SAD_ENTRY,			  
	EMPTY_SAD_ENTRY,
	EMPTY_SAD_ENTRY
} ;

/* SPD configuration data */
spd_entry outbound_spd_config[IPSEC_MAX_SPD_ENTRIES] = {
/*            source                            destination                   protocol  ports         policy          SA pointer 
 *            address          network          address      network                    src    dest                              */
	{ SPD_ENTRY( 192,168,1,4,  255,255,255,255, 192,168,1,5, 255,255,255,255, 0, 		0,     0,     POLICY_APPLY,   &outbound_sad_config[0]) },
   	EMPTY_SPD_ENTRY,
	EMPTY_SPD_ENTRY
} ;





/****************************************************************************
 * udpecho_recv()                                                           *
 * This function is called to handle lwip events                            *
 ****************************************************************************/
void udpecho_recv(void *arg, struct udp_pcb *upcb, struct pbuf *p, struct ip_addr *addr, u16_t port)
{
	arg = NULL;
	if(p->len > 0) *((__u8 *)p->payload + p->len) = 0x00;

	printf("UDP port 7 received and echo: %s", p->payload);

	udp_connect(upcb, addr, port);
	udp_send(upcb, p);

	pbuf_free(p);
}



/****************************************************************************
 * udpecho_init()                                                        	*
 * This function must be called on system startup to init "udpecho"      	*
 * A RFC 862 Echo Protocol server is installed								*
 ****************************************************************************/
void udpecho_init(void)
{
  struct udp_pcb *pcb;

  pcb = udp_new();						/* create an UDP control block 		*/
  udp_bind(pcb, IP_ADDR_ANY, 7);		/* bind new connection to port 7    */
  udp_recv(pcb, udpecho_recv, NULL);
}
  


/********
 * MAIN *
 ********/
void main()
{
	struct ip_addr eth_ipaddr, eth_netmask, eth_gw;
	struct ip_addr ipsec_ipaddr, ipsec_netmask, ipsec_gw;
	unsigned int i;

#ifdef PHYCORE167HSE
#ifndef LWIP_DEBUG
	/* initialize serual port 0 */
	P3  |= 0x0400;                       /* set port 3.10 output latch (TXD)*/
	DP3 |= 0x0400;                       /* configure port 3.10 for output  */
	                                     /* operation. ( TXD output)        */
	DP3 &= 0xF7FF;                       /* configure port 3.11 for input   */
	                                     /* operation. ( RXD input)         */
	S0TIC = 0x80;                        /* set transmit interrupt flag     */
	S0RIC = 0x00;                        /* delete receive interrupt flag   */
	S0BG  = 0x80;                        /* set baudrate to 9600 baud @40Mhz*/
	S0CON = 0x8011;                      /* set serial mode                 */
#endif
#endif

	printf("lwIP - embedded IPsec UDP echo demo (compiled %s at %s)\n", __DATE__, __TIME__);
	printf("CVS ID: $Id: main.c,v 1.1 2003/12/12 13:58:04 schec2 Exp $\n\n");

	/* initialize lwIP */
	etharp_init();
	mem_init();							
	memp_init();
	pbuf_init(); 
	netif_init();
	ip_init();
	udp_init();
	printf("TCP/IP initialized.\n");

	/* configure Ethernet device */
	IP4_ADDR(&eth_ipaddr, 192,168,1,4);
	IP4_ADDR(&eth_netmask, 255,255,255,0);
	IP4_ADDR(&eth_gw, 192,168,1,1);

	/* configure IPsec device */
	IP4_ADDR(&ipsec_ipaddr, 192,168,1,4);
	IP4_ADDR(&ipsec_netmask, 255,255,255,0);
	IP4_ADDR(&ipsec_gw, 192,168,1,1);

	/* Initialize the physical device first (so that ethif->next will point *
	 * to ipsecif). The IPsec device will process the packets and pass them *
	 * upper to the IP layer (using ip_input)                               */
	printf("Setting up et0...");
	ethif = netif_add(&eth_ipaddr, &eth_netmask, &eth_gw, NULL,  cs8900if_init, ipsecdev_input);
	printf("OK\n");

	printf("Setting up is0...");
	ipsecif = netif_add(&ipsec_ipaddr, &ipsec_netmask, &ipsec_gw, NULL,  ipsecdev_init, ip_input);
	printf("OK\n");

	/* configure IPsec tunnel */
	ipsec_set_tunnel("192.168.1.4", "192.168.1.5");

	/* set the IPsec interface "is0" as default interface for lwIP */
	netif_set_default(ipsecif);

	/* start custom applications here */
	udpecho_init();

 	printf("Applications started.\n");

	DP2  = 0x00FF;						/* configure the status LED on Port2*/
	ODP2 = 0x0000;

	while(1)
	{
		P2 = ~P2;						/* blink LED 						*/

		for (i = 0; i < 50000; i++)  
		{       	
    		_nop_(); _nop_();			/* delay or use this time for the   */
			_nop_(); _nop_();			/* application						*/
			_nop_(); _nop_();
			if((i % 250) == 0) 
			{							/* periodically call to the     	*/
      			cs8900if_service(ethif);/* CS8900 driver (polling mode) 	*/
    		}
		}
  	}
}



