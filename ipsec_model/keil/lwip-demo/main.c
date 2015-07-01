/*
 * Copyright (c) 2003 Christian Scheurer (www.christianscheurer.ch).
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
 * This file is part of the Keil C166 port of lwIP TCP/IP stack.
 * 
 */

#include "lwip/debug.h"						// include lwIP
#include "lwip/memp.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "netif/cs8900if.h"					// include CS8900 driver
#include <reg167.h>							// include C166 register definitions
#include <intrins.h>		

extern void dumpwebpage_init(void);			// define dumpwebpage HTTP server

struct netif *ethif;						// network interface



void main()
{
  struct ip_addr ipaddr, netmask, gw;
  unsigned int i;
  unsigned int j;

  printf("lwIP demo (compiled %s at %s)\n\n", __DATE__, __TIME__);

#ifdef STATS
  stats_init();
#endif

  mem_init();								// init lwIP
  memp_init();
  pbuf_init(); 
  netif_init();
  ip_init();
  udp_init();
  tcp_init();
  printf("TCP/IP initialized.\n");
  
  IP4_ADDR(&gw, 192,168,1,1);
#ifdef MCB167NET
  IP4_ADDR(&ipaddr, 192,168,1,3);
#endif
#ifdef PHYCORE167HSE
  IP4_ADDR(&ipaddr, 192,168,1,4);
#endif
  IP4_ADDR(&netmask, 255,255,255,0);

  ethif = netif_add(&ipaddr, &netmask, &gw, NULL,  cs8900if_init, ip_input);

  netif_set_default(ethif);					// bring up ethernet interface

  dumpwebpage_init();						// start dumpwebpage
  
  printf("Applications started.\n");
  DP2  = 0x00FF;
  ODP2 = 0x0000;

  while(1) {

    for (j=0x0001; j != 0x0100; j<<=1){    
      P2 = ~j & 0x00FF;                  	// blink LED
      for (i = 0; i < 10000; i++)  {       	// delay
        _nop_(); _nop_();
        _nop_(); _nop_();
        _nop_();
        if((i % 250) == 0) {				// periodically call to the
	      cs8900if_service(ethif);		    // CS8900 driver (polling mode)
          tcp_tmr();						// and TCP/IP timer
        }
      }
    }

    for (j=0x0080; j != 0; j>>=1){         
      P2 = ~j & 0x00FF;						// blink LED
      for (i = 0; i < 10000; i++)  {       	// delay
        _nop_(); _nop_();
        _nop_(); _nop_();
        _nop_();
        if((i % 250) == 0) {				// periodically call to the
	      cs8900if_service(ethif);		    // CS8900 driver (polling mode)
          tcp_tmr();						// and TCP/IP timer
        }
      }
    }
  }

}









