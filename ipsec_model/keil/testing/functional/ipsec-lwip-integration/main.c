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
 *  @brief Demonstrate data flow interception by the IPsec device
 *
 *  @author Christian Scheurer <http://www.christianscheurer.ch> <BR>
 *
 *  <B>OUTLINE:</B>
 *
 *  Sample program combining lwIP and embedded IPsec.
 *  The data flow between physical network and TCP/IP stack is intercepted by
 *  the IPsec device driver. All captured traffic will be routed trough ipsec_input
 *  and forwarded to ip_input. All outbound traffic will pass the IPsec driver's
 *  output function where IPsec specific processing can be applied. Afterwards,
 *  the packet will be sent out to the wire using the physical device driver.
 *
 *  <B>IMPLEMENTATION:</B>
 *
 *  The advantage of the current implementation is that no single line of lwIP code
 *  or the physical driver have to be changed. "ipsecdev" will automatically set hooks
 *  at the appropriate places inside the netif_list structrue of lwIP.
 *  
 *  Only minimal changes would be required to port this to different TCP/IP stacks.
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


#include "lwip/debug.h"						// include lwIP
#include "lwip/memp.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "netif/etharp.h"

#ifdef SIMULATOR
#include "netif/dumpdev.h"					// include dump driver (some kind of loopback driver)
#else
#include "netif/cs8900if.h"					// include CS8900 driver
#endif
#include "netif/ipsecdev.h"					// include IPsec device driver
#include "ipsec/util.h"						// include IPsec helper functions
#include "ipsec/ipsec.h"					// include embedded IPsec
#include "ipsec/sa.h"						// include SA

#include <reg167.h>							// include C166 register definitions
#include <intrins.h>		

extern void dumpwebpage_init(void);			// define dumpwebpage HTTP server


/* *** DEFAULT SAD/SPD CONFIGURATION ************************************** */
/* *** NOTE: only one configuration must be active at the same time		*** */

/* static configurations for Keil MCB167NET board (IP 192.168.1.3) */
#include "testing/config/keil_bypass.h"			/* Keil MCB167NET BYPASS all packets*/
//#include "testing/config/keil_1000_ah_md5.h"		/* Keil MCB167NET with AH MD5		*/
//#include "testing/config/keil_1001_ah_sha1.h"	 	/* Keil MCB167NET with AH SHA1		*/
//#include "testing/config/keil_1002_esp_3des.h"	/* Keil MCB167NET with ESP 3DES		*/
//#include "testing/config/keil_1003_esp_3des_md5.h"/* Keil MCB167NET with ESP 3DES MD5	*/
//#include "testing/config/keil_1004_esp_3des_sha1.h"/* Keil MCB167NET with ESP 3DES SHA1*/

/* static configurations for Phytec phyCORE167-HS/E board (IP 192.168.1.4) */
//#include "testing/config/phy_bypass.h"			/* phyCORE167-HS/E BYPASS all packets */
//#include "testing/config/phy_2000_ah_md5.h"		/* phyCORE167-HS/E with AH MD5		*/
//#include "testing/config/phy_2001_ah_sha1.h"		/* phyCORE167-HS/E with AH SHA1		*/
//#include "testing/config/phy_2002_esp_3des.h"		/* phyCORE167-HS/E with ESP 3DES	*/
//#include "testing/config/phy_2003_esp_3des_md5.h"	/* phyCORE167-HS/E with ESP 3DES MD5*/
//#include "testing/config/phy_2004_esp_3des_sha1.h"/* phyCORE167-HS/E with ESP 3DES SHA1*/
/* *** END OF DEFAULT SAD/SPD CONFIGURATION ******************************* */




extern void dumpwebpage_init(void);		/* define dumpwebpage HTTP server	*/
extern void netconfig_init(void);		/* define netconfig server (dynamic SA configuration) */
#ifdef SIMULATOR
extern void serinit(void);				/* initialize simulator serial port */
#endif


#ifdef PHYCORE167HSE
void serinit(void)
{
#ifndef LWIP_DEBUG
	/* initialize serual port 0 */
	P3  |= 0x0400;                   	/* set port 3.10 output latch (TXD)*/
	DP3 |= 0x0400;                      /* configure port 3.10 for output  */
	                                    /* operation. ( TXD output)        */
	DP3 &= 0xF7FF;                      /* configure port 3.11 for input   */
	                                    /* operation. ( RXD input)         */
	S0TIC = 0x80;                       /* set transmit interrupt flag     */
	S0RIC = 0x00;                       /* delete receive interrupt flag   */
	S0BG  = 0x80;                       /* set baudrate to 9600 baud @40Mhz*/
	S0CON = 0x8011;                     /* set serial mode                 */
#endif
}
#endif


#ifdef MCB167NET
void serinit(void) 
{
}
#endif




#ifdef SIMULATOR
struct netif *dumpif;					/* dummy network interface "dumpdev"*/
#else
struct netif *ethif;					/* Ethernet network interface 		*/
#endif
struct netif *ipsecif;					/* IPsec network interface 			*/



/********
 * MAIN *
 ********/
void main()
{
#ifdef SIMULATOR
	struct ip_addr dump_ipaddr, dump_netmask, dump_gw;
#else
	struct ip_addr eth_ipaddr, eth_netmask, eth_gw;
#endif
	struct ip_addr ipsec_ipaddr, ipsec_netmask, ipsec_gw;
	unsigned int i;


	serinit();							/* init serial port					*/

	printf("lwIP - IPsec integration demo (compiled %s at %s)\n", __DATE__, __TIME__);
	printf("CVS ID: $Id: main.c,v 1.10 2003/12/12 14:36:33 schec2 Exp $\n\n");


	/* initialize lwIP */
	etharp_init();
	mem_init();
	memp_init();
	pbuf_init(); 
	netif_init();
	ip_init();
	udp_init();
	tcp_init();
	printf("TCP/IP initialized.\n");

#ifdef SIMULATOR
	/* configure dummy device */
	IP4_ADDR(&dump_ipaddr, 192,168,1,3);
	IP4_ADDR(&dump_netmask, 255,255,255,0);
	IP4_ADDR(&dump_gw, 192,168,1,1);

	/* configure IPsec device */
	IP4_ADDR(&ipsec_ipaddr, 192,168,1,3);
	IP4_ADDR(&ipsec_netmask, 255,255,255,0);
	IP4_ADDR(&ipsec_gw, 192,168,1,1);
#endif

#ifdef MCB167NET
	/* configure Ethernet device */
	IP4_ADDR(&eth_ipaddr, 192,168,1,3);
	IP4_ADDR(&eth_netmask, 255,255,255,0);
	IP4_ADDR(&eth_gw, 192,168,1,1);

	/* configure IPsec device */
	IP4_ADDR(&ipsec_ipaddr, 192,168,1,3);
	IP4_ADDR(&ipsec_netmask, 255,255,255,0);
	IP4_ADDR(&ipsec_gw, 192,168,1,1);
#endif

#ifdef PHYCORE167HSE
	/* configure Ethernet device */
	IP4_ADDR(&eth_ipaddr, 192,168,1,4);
	IP4_ADDR(&eth_netmask, 255,255,255,0);
	IP4_ADDR(&eth_gw, 192,168,1,1);

	/* configure IPsec device */
	IP4_ADDR(&ipsec_ipaddr, 192,168,1,4);
	IP4_ADDR(&ipsec_netmask, 255,255,255,0);
	IP4_ADDR(&ipsec_gw, 192,168,1,1);
#endif


	/* Initialize the physical device first (so that ethif->next will point *
	 * to ipsecif). The IPsec device will process the packets and pass them *
	 * upper to the IP layer (using ip_input)                               *
	 * If the simulator is used, dumpdev will replace cs8900.               */
#ifdef SIMULATOR
	printf("Setting up dp0...");
	dumpif = netif_add(&dump_ipaddr, &dump_netmask, &dump_gw, NULL,  dumpdev_init, ipsecdev_input);
	printf("OK\n");

	printf("Setting up is0...");
	ipsecif = netif_add(&ipsec_ipaddr, &ipsec_netmask, &ipsec_gw, NULL,  ipsecdev_init, ip_input);
	printf("OK\n");
#else
	printf("Setting up et0...");
	ethif = netif_add(&eth_ipaddr, &eth_netmask, &eth_gw, NULL,  cs8900if_init, ipsecdev_input);
	printf("OK\n");

	printf("Setting up is0...");
	ipsecif = netif_add(&ipsec_ipaddr, &ipsec_netmask, &ipsec_gw, NULL,  ipsecdev_init, ip_input);
	printf("OK\n");
#endif

	/* configure IPsec tunnel */
#ifdef PHYCORE167HSE
	ipsec_set_tunnel("192.168.1.4", "192.168.1.5");
#else
	ipsec_set_tunnel("192.168.1.3", "192.168.1.5");
#endif

	/* set the IPsec interface "is0" as default interface for lwIP */
	netif_set_default(ipsecif);			/* use ipsec interface by default	*/


	/* start custom applications here */
	dumpwebpage_init();					/* start dumpwebpage 				*/

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
#ifdef SIMULATOR
      			dumpdev_service(dumpif);/* dump device driver (polling mode)*/
#else
      			cs8900if_service(ethif);/* CS8900 driver (polling mode) 	*/
#endif
				tcp_tmr();				/* poll TCP timer					*/
    		}


		}
  	}

}



