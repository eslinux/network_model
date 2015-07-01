/***************************************************************************
 **                                                                       **
 **    Simple HTTP server which will dump a HTML page at each request     **
 **                                                                       **
 **    It is based on lwIP (CVS version 06.03.2003) by Adam Dunkels of    **
 **    Swedish Institute of Computer Science. See www.sics.se/~adam/lwip/ **
 **                                                                       **
 **    Ported 03/2003 by Christian Scheurer (www.ChristianScheurer.ch)    **
 **                                                                       **
 *************************************************************************** */

#include "webpage.h"
#include "lwip/tcp.h"

/* *** GLOBAL DATA AND DEFINITIONS ***************************************** */
				
struct dumpwebpage_state {
  int bytes_left;						// bytes left in send buffer
  int page_offset;						// offset within page
  int page_size;						// total page size
};

const unsigned char http_get_response[] = {
 "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"
}; 

/* *** END OF GLOBAL DATA AND DEFINITIONS ********************************** */


/*****************************************************************************
 * dumpwebpage_init()                                                        *
 * This function must be called on system startup to init "dumpwebpage"      *
 *****************************************************************************/
void dumpwebpage_init(void)
{
  struct tcp_pcb *pcb;

  pcb = tcp_new();						// create a TCP control block
  tcp_bind(pcb, IP_ADDR_ANY, 80);		// bind the new connection to port 80
  pcb = tcp_listen(pcb);				// start listening
}


/*****************************************************************************
 * send_buf()                                                                *
 * This function is called to send a block of the web page                   *
 *****************************************************************************/
static void send_buf(struct tcp_pcb *pcb, struct dumpwebpage_state *es) 
{
  int len; 							

  // send HTTP response if this is the first call of send_buf
  if(es->page_offset == -1){
    printf("  Starting transmission of %d bytes by sending HTTP response (%d bytes)...", 
           es->page_size + sizeof(http_get_response)-1, sizeof(http_get_response)-1);

    // abort if there is not enough memory for the HTTP response in the send buffer
    len = tcp_sndbuf(pcb); 					// get availabe space in send buffer
    if(len < sizeof(http_get_response)-1){
      printf("ERROR! (not enough memory to buffer HTTP response)\n");
	  return;
    }
    tcp_write(pcb, (unsigned char *)http_get_response, sizeof(http_get_response)-1, 1);
	es->bytes_left+=sizeof(http_get_response)-1;
    es->page_offset=0;
    printf("OK\n");
  }

  len = tcp_sndbuf(pcb); 				// get availabe space in send buffer
  
  if(es->page_offset >= es->page_size){ // abort if the whole page has been sent
    return;
  }

  if(len == 0){							// abort if the whole page has been sent
    return;
  }

  if(len > (es->page_size - es->page_offset)){ // send rest of the page
    len = es->page_size - es->page_offset;
  }

  tcp_write(pcb, (unsigned char *)WebPage+es->page_offset, len, 1);
  es->bytes_left+=len;
  es->page_offset+=len;

  tcp_output(pcb);						// flush buffer
}


/*****************************************************************************
 * close_conn()                                                              *
 * This function is called to close an active connection                     *
 *****************************************************************************/
static void close_conn(struct tcp_pcb *pcb, struct dumpwebpage_state *es) 
{
  tcp_arg(pcb, NULL);

  if(es != NULL){
    mem_free(es);
  }

  printf("  Closing connection...");
  if(tcp_close(pcb) == ERR_OK){
    printf("OK\n");
  } 
  else {
    printf("ERROR!\n");
  }	
}


/*****************************************************************************
 * dumpwebpage_poll()                                                        *
 * This callback function is called periodically to continue sending data or *
 * to close the connection                                                   *
 *****************************************************************************/
static err_t dumpwebpage_poll(void *arg, struct tcp_pcb *pcb)
{
  struct dumpwebpage_state *es;
  es = arg;

  if(es == NULL){
    return ERR_CONN;
  }

  send_buf(pcb, es);					// try to send more data

  if(es->page_offset >= es->page_size){ // everything sent => close connection 
    printf("  Ending transmission (page size == %d, page offset == %d), calling close_conn()\n",
           es->page_size, es->page_offset);
    close_conn(pcb, es);
    return ERR_CLSD;
  }

  return ERR_OK;
}


/*****************************************************************************
 * dumpwebpage_sent()                                                        *
 * This callback function is called when data has been physically transmitted*
 *****************************************************************************/
static err_t dumpwebpage_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
  struct dumpwebpage_state *es;
  void *dummy;
  dummy = pcb + 0;						// dummy to avoid compiler warning

  es = arg;

  if(es != NULL){
	if(len > 1){
		es->bytes_left-=len;			// adjust send buffer
	}
  }

  return ERR_OK;
}


/*****************************************************************************
 * dumpwebpage_recv()                                                        *
 * This callback function is called when new data has been received          *
 *****************************************************************************/
static err_t dumpwebpage_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
  struct dumpwebpage_state *es;
  void *dummy;
  dummy = pcb + 0;						// dummy to avoid compiler warning
  dummy = (void *)err;					// dummy to avoid compiler warning

  es = arg;
  
  pbuf_free(p); 						// do not process received data, just
										// free the allocated memory
  
  return ERR_OK;
}


/*****************************************************************************
 * dumpwebpage_accept()                                                      *
 * This callback function is called when a new connection is opened          *
 *****************************************************************************/
static err_t dumpwebpage_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
  struct dumpwebpage_state *es;
  void *dummy;
  dummy = arg;							// dummy to avoid compiler warning
  dummy = (void *)err;					// dummy to avoid compiler warning

  tcp_setprio(pcb, TCP_PRIO_MIN);

  printf("  Accepting new connection (assuming a HTTP GET request)...");

  // alloc memory to hold the connection state  
  es = mem_malloc(sizeof(struct dumpwebpage_state));
  if(es == NULL){
    printf("ERROR! (out of memory)\n");
    return ERR_MEM;
  }
  
  // initialize state information
  es->bytes_left = 0;					// no buffered bytes in queue yet
  es->page_offset = -1;					// use "-1" to signal the the HTTP response is not sent
  es->page_size = sizeof(WebPage) - 1;	// set the size of the web page

  tcp_arg(pcb, es);						// TCP shall pass the structure "es" with 
  printf("OK\n");						// the state information to all callbacks
  
  tcp_poll(pcb, dumpwebpage_poll, 0); 	// TCP shall call dumpwebpage_poll() when 
									  	// incoming data is detected
  return ERR_OK;
}


/*****************************************************************************
 * dumpwebpage_err()                                                         *
 * This callback function is called in case of errors                        *
 *****************************************************************************/
static void dumpwebpage_err(void *arg, err_t err) 
{
  printf("  Error occurred: err == %d\n", err);
  if(arg != NULL){
    mem_free(arg);
  }
}


/*****************************************************************************
 * lwip_tcp_event()                                                          *
 * This function is called to handle lwip events                             *
 *****************************************************************************/
err_t lwip_tcp_event(void *arg, struct tcp_pcb *pcb, enum lwip_event ev, struct pbuf *p, u16_t size, err_t err)
{
  int retvalue = ERR_OK;

  switch(ev){
    case LWIP_EVENT_ACCEPT:
      retvalue = dumpwebpage_accept(arg, pcb, err);
      break;
    case LWIP_EVENT_SENT:
      retvalue = dumpwebpage_sent(arg, pcb, size);
      break;
    case LWIP_EVENT_RECV:
      retvalue = dumpwebpage_recv(arg, pcb, p, err);
      break; 
    case LWIP_EVENT_ERR:
      dumpwebpage_err(arg, err);
      break;
    case LWIP_EVENT_POLL:
      retvalue = dumpwebpage_poll(arg, pcb);
      break;
    default:
      break;
  }  
  return retvalue;
}


