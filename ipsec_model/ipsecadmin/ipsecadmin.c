#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "sa.h"

extern int errno ;

#define DEBUG_MSG

#define CONFIG_FILE 	"ipsec.conf"
#define MAX_LINE_SIZE	(128)

#define CONFIG_TAG	"config"
#define COMMENT_TAG	"#"


#define IKE_PORT		(500)

#define IPSEC_PROTO_ICMP 	(0x01)
#define IPSEC_PROTO_TCP 	(0x06)
#define IPSEC_PROTO_UDP 	(0x11)
#define IPSEC_PROTO_ESP 	(0x32)
#define IPSEC_PROTO_AH 		(0x33)

#define IPSEC_CONFIG_IV_LEN	(8)
#define IPSEC_CONFIG_ICV_LEN	(12)

#define IPSEC_CONFIG_ADD	(1)
#define IPSEC_CONFIG_FLUSH	(2)
#define IPSEC_CONFIG_GET	(3)

#define IPSEC_DIR_INBOUND	(1)
#define IPSEC_DIR_OUTBOUND	(2)


typedef struct config_struct
{
  unsigned char iv[IPSEC_CONFIG_IV_LEN] __attribute__ ((packed));
  unsigned char icv[IPSEC_CONFIG_ICV_LEN] __attribute__ ((packed));
  unsigned char type __attribute__ ((packed));
  unsigned char direction  __attribute__ ((packed));
  spd_entry 	spd __attribute__ ((packed));
  sad_entry	sad __attribute__ ((packed));
} config_packet;

void get_key(char *line, char *key)
{
  char *line_pos ;
  char *key_pos ;
  int test ;
  
  char tmp_str[2+1] ;

  printf("key is: %s\n", line) ;
  
  /* go till '=' */
  for(line_pos=line; *line_pos != '=';line_pos++)
    {
      printf("line_pos: %c", *line_pos) ;
    }
  /* jump over '=0x' string */
  line_pos+=3 ;
  
  /* go through the whole key and copy bytewise */
  for(key_pos = key;line_pos != NULL; line_pos+=2, key_pos++)
    {
      strncpy(tmp_str, line_pos, 2) ;
      tmp_str[2] = '\0' ;
      printf("pos: %s\n", tmp_str) ;
      *key_pos = (unsigned char) atoi(tmp_str) ;
      test = atoi(tmp_str) ;
    }
  
  return ;
}

int send_config(char *buffer, int buffer_len, char* dest_addr, int port) 
{
  int 			sock, status ;
  struct sockaddr_in   client_addr, server_addr ;

  sock = socket(AF_INET, SOCK_DGRAM, 0) ;
  if(sock < 0)
    {
      perror("unable to create a socket") ;
      return -1 ;
    }
  
  server_addr.sin_port = htons(port) ;
  server_addr.sin_addr.s_addr = inet_addr(dest_addr) ;
  server_addr.sin_family = AF_INET ;

  client_addr.sin_family = AF_INET ;
  client_addr.sin_addr.s_addr = htonl(INADDR_ANY) ;
  client_addr.sin_port = htons(0) ;
  
  status = bind(sock, (struct sockaddr*) &client_addr, sizeof(client_addr)) ;
  if(status < 0)
    {
      perror("unable to bind socket") ;
      return -2 ;
    }
  
  status = sendto(sock, buffer, buffer_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) ;
  if(status < 0)
    {
      perror("unable to send UDP data") ;
      return -3 ;
    }

  close(sock) ;
  
  return 0 ;
}

void print_usage(void)
{
  printf("bad usage: admin <ADD>   <config file> <IP address of device>\n") ;
  printf("           admin <FLUSH> <direction>   <IP address of device>\n") ;
  printf("           admin <GET>   <direction>   <IP address of device>\n") ;
  printf("\n NOTE: all commands are case sensitive!\n\n");
}

char* trimm_line(char *line)
{
  char *tmp ;

  /* skip till '=' */
  while(*line++ != '=') ;

  tmp = line ;
  
  /* trimm spaces */
  while((*line != 0x0a) && (*line != 0x0d)) *line++;
  *line = '\0' ;

  return tmp;
}


/**
 * Convert hex string into a byte buffer
 *
 * @param hexstring  pointer to a '0'-terminated string (i.g. "0x12AB0000")
 * @param bytebuffer pointer where the output should be written (i.g. 12 AB 00 00)
 * @return int number of bytes written to the bytebuffer, 0 in case of error
 */
int hex2byte(unsigned char *hexstring, unsigned char* bytebuffer)
{
	int i;
	int len;
	unsigned char tmp_byte;

	len = strlen(hexstring);
	
	if(len < 2) return 0;			/* string length must be at least 2 */
	if((len % 2) != 0) return 0;	/* length must be even				*/

	// skip "0x"
	if(*(hexstring + 1) != 'x')
	{
		return 0;
	}
        hexstring += 2;
	len -= 2;

	for(i = 0; i < len/2; i++)
	{
		tmp_byte = 0x00;
	   	if (*hexstring >= '0' && *hexstring <= '9') tmp_byte = *hexstring - '0';
	   	if (*hexstring >= 'a' && *hexstring <= 'f') tmp_byte = *hexstring - 'a' + 10;
	   	if (*hexstring >= 'A' && *hexstring <= 'F') tmp_byte = *hexstring - 'A' + 10;

		*bytebuffer = tmp_byte << 4;
		hexstring++;

		tmp_byte = 0x00;
	   	if (*hexstring >= '0' && *hexstring <= '9') tmp_byte = *hexstring - '0';
	   	if (*hexstring >= 'a' && *hexstring <= 'f') tmp_byte = *hexstring - 'a' + 10;
	   	if (*hexstring >= 'A' && *hexstring <= 'F') tmp_byte = *hexstring - 'A' + 10;

		*bytebuffer = *bytebuffer | (tmp_byte & 0x0F);
		hexstring++;

		bytebuffer++;
	}

	return i;
}


int get_sa(FILE *fd, sad_entry *sad)
{
  char	line[MAX_LINE_SIZE+1] ;
  char	*new_line ;
  int  	nr_items = 0 ;
  char  tmp_char ;
  unsigned long  tmp_long ;
  unsigned short tmp_short ;
  
  memset(line, 0, MAX_LINE_SIZE+1) ;
  
  #ifdef DEBUG_MSG
  printf(" *** SA: ***\n");
  #endif
  
  /* loop over all configuration entries */
  while(nr_items < 9 && fgets(line, MAX_LINE_SIZE, fd))
    {
      if(strncmp(line, "dest", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" dest  : %s\n", new_line);
	  #endif
	  sad->dest = inet_addr(new_line) ;
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "dnet", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" dnet  : %s\n", new_line);
	  #endif
	  sad->dest_netaddr = inet_addr(new_line) ;
	  nr_items++ ;
	  continue ;
	}
      
      if(strncmp(line, "spi", 3) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" spi   : %s\n", new_line);
	  #endif

	  // handle hex (0x...) and decimal configuration
	  if(hex2byte(new_line, (unsigned char *)&sad->spi) == 0)
	  {
	  tmp_long = atol(new_line) ;
	  sad->spi = htonl(tmp_long) ;
      }

      printf(" spi = %08x\n", ntohl(sad->spi));

	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "protocol", 8) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" protocol: %s\n", new_line);
	  #endif
	  
	  if(strncmp(new_line, "ESP", 3) == 0)
	    sad->protocol = (__u8)IPSEC_PROTO_ESP ;
	  else if(strncmp(new_line, "AH", 2) == 0)
	    sad->protocol = (__u8)IPSEC_PROTO_AH ;
	  	  
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "mode", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" mode  : %s\n", new_line);
	  #endif

	  if(strncmp(new_line, "TUNNEL", 6) == 0)
	    sad->mode = IPSEC_TUNNEL ;
	  if(strncmp(new_line, "TRANSPORT", 9) == 0)
	    sad->mode = IPSEC_TRANSPORT ;

	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "mtu", 3) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" mtu   : %s\n", new_line);
	  #endif
	  
	  tmp_short = (unsigned short)atoi(new_line) ;
	  sad->path_mtu = tmp_short ;

	  continue ;
	}
      
      if(strncmp(line, "enc", 3) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" enc   : %s\n", new_line);
	  #endif

	  if(strncmp(new_line, "DES", 3) == 0)
	    sad->enc_alg = (__u8)IPSEC_DES ;
	  else if(strncmp(new_line, "3DES", 4) == 0)
	    sad->enc_alg = (__u8)IPSEC_3DES ;
	  else 
	    sad->enc_alg = 0 ;
	  
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "ekey", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" ekey  : %s\n", new_line);
	  #endif

	  if((tmp_short = hex2byte(new_line, (unsigned char *)&sad->enckey[0])) > IPSEC_MAX_ENCKEY_LEN)
	  {
	  		printf(" error: ekey length == %d (must not be longer than %d bytes for 3DES)!\n", tmp_short, IPSEC_MAX_ENCKEY_LEN);
      }
      else {
          printf(" ekey = ");
          for(tmp_short = 0; tmp_short < (strlen(new_line)-2)/2; tmp_short++) printf("%02x ", sad->enckey[tmp_short]);
          printf("\n");
      }
	  
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "auth", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" auth  : %s\n", new_line);
	  #endif

	  
	  if(strncmp(new_line, "HMAC-MD5", 8) == 0)
	    sad->auth_alg = (__u8)IPSEC_HMAC_MD5 ;
	  else if(strncmp(new_line, "HMAC-SHA1", 9) == 0)
	    sad->auth_alg = (__u8)IPSEC_HMAC_SHA1 ;
	  else
	    sad->auth_alg = 0 ;
	  
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "akey", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" akey  : %s\n", new_line);
	  #endif

	  if((tmp_short = hex2byte(new_line, (unsigned char *)&sad->authkey)) > IPSEC_MAX_AUTHKEY_LEN)
	  {
	  		printf(" error: akey length == %d (must not be longer than %d bytes!)\n", tmp_short, IPSEC_MAX_AUTHKEY_LEN);
      }
      else {
          printf(" akey = ");
          for(tmp_short = 0; tmp_short < (strlen(new_line)-2)/2; tmp_short++) printf("%02x ", sad->authkey[tmp_short]);
          printf("\n");
      }

	  
	  nr_items++ ;
	  continue ;
	}
      memset(line, 0, MAX_LINE_SIZE+1) ;
    }
  
  return nr_items ;
}

int get_sp(FILE *fd, spd_entry *spd)
{
  char	line[MAX_LINE_SIZE+1] ;
  char	*new_line ;
  int  	nr_items = 0 ;
  char  tmp_char ;
  unsigned short tmp_short ;

  memset(line, 0, MAX_LINE_SIZE+1) ;

  #ifdef DEBUG_MSG
  printf(" *** SP: ***\n");
  #endif


  /* loop over all configuration entries */
  while(nr_items < 8 && fgets(line, MAX_LINE_SIZE, fd))
    {
      if(strncmp(line, "src", 3) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" src   : %s\n", new_line);
	  #endif
	  spd->src = inet_addr(new_line) ;
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "snet", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" snet  : %s\n", new_line);
	  #endif
	  spd->src_netaddr = inet_addr(new_line) ;

	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "dest", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" dest  : %s\n", new_line);
	  #endif
	  spd->dest = inet_addr(new_line) ;
	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "dnet", 4) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" dnet  : %s\n", new_line);
	  #endif
	  spd->dest_netaddr = inet_addr(new_line) ;

	  nr_items++ ;
	  continue ;
	}
      
      if(strncmp(line, "proto", 5) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" proto : %s\n", new_line);
	  #endif

	  if(strncmp(new_line, "TCP", 3) == 0)
	    spd->protocol = (__u8)IPSEC_PROTO_TCP ;
	  if(strncmp(new_line, "UDP", 3) == 0)
	    spd->protocol = (__u8)IPSEC_PROTO_UDP ;
	  if(strncmp(new_line, "ICMP", 4) == 0)
	    spd->protocol = (__u8)IPSEC_PROTO_ICMP ;
	  
	  nr_items++ ;
	  continue ;
	}
      
      if(strncmp(line, "sport", 5) == 0)
	{
 	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" sport : %s\n", new_line);
	  #endif

	  tmp_short = (unsigned short) atoi(new_line) ;
	  spd->src_port = htons(tmp_short) ;

	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "dport", 5) == 0)
	{
	  new_line = trimm_line(line) ;
	  
	  #ifdef DEBUG_MSG
	  printf(" dport : %s\n", new_line);
	  #endif

	  tmp_short = (unsigned short) atoi(new_line) ;
	  spd->dest_port = htons(tmp_short) ;

	  nr_items++ ;
	  continue ;
	}

      if(strncmp(line, "policy", 6) == 0)
	{
	  new_line = trimm_line(line) ;
	  #ifdef DEBUG_MSG
	  printf(" policy: %s\n", new_line);
	  #endif

	  if(strncmp(new_line, "APPLY", 5) == 0)
	    spd->policy = POLICY_APPLY ;
	  if(strncmp(new_line, "DISCARD", 7) == 0)
	    spd->policy = POLICY_APPLY ;
	  if(strncmp(new_line, "BYPASS", 6) == 0)
	    spd->policy = POLICY_APPLY ;
	  
	  nr_items++ ;
	  continue ;
	}
    }

  return nr_items ;
}

int get_config(FILE *fd, config_packet *config)
{
  char	line[MAX_LINE_SIZE+1] ;
  char	*new_line ;
  int  	nr_items = 0;

  memset(line, 0, MAX_LINE_SIZE+1) ;
  fgets(line, MAX_LINE_SIZE, fd) ;
  new_line = trimm_line(line) ;

  if(strncmp(new_line, "OUTBOUND", 8) == 0)
    config->direction = IPSEC_DIR_OUTBOUND ;
  if(strncmp(new_line, "INBOUND", 7) == 0)
    config->direction = IPSEC_DIR_INBOUND ;

  #ifdef DEBUG_MSG
  printf("\n #### %s configuration: ####\n", new_line);
  #endif

  memset(line, 0, MAX_LINE_SIZE+1) ;
  fgets(line, MAX_LINE_SIZE, fd) ;

  if(strncmp(line, "db=SP", strlen("db=SP")) == 0)
    nr_items = get_sp(fd, &config->spd) ;
      
  memset(line, 0, MAX_LINE_SIZE+1) ;
  fgets(line, MAX_LINE_SIZE, fd) ;

  if(strncmp(line, "db=SA", strlen("db=SA")) == 0)
    nr_items += get_sa(fd, &config->sad) ;
        
  return nr_items ;
}

int send_config_flush(char *direction, char *remote_addr)
{
  config_packet config ;

  /* setup static packet fields */
  memset(&config, 0, sizeof(config_packet)) ;
  strncpy(config.iv, "ipseccnf", 8) ;
  memset(&config.icv, 0, IPSEC_CONFIG_ICV_LEN) ;
  config.type = IPSEC_CONFIG_FLUSH ; 

  if(strncmp(direction, "OUTBOUND", 8) == 0)
    config.direction = IPSEC_DIR_OUTBOUND ;
  if(strncmp(direction, "INBOUND", 7) == 0)
    config.direction = IPSEC_DIR_INBOUND ;

  if(send_config((char *)&config, sizeof(config_packet), 
		 remote_addr, IKE_PORT ) != 0)
    printf("error on sending flush\n") ;
  
  return 0 ;
}


int send_config_get(char *direction, char *remote_addr)
{
  config_packet config ;

  /* setup static packet fields */
  memset(&config, 0, sizeof(config_packet)) ;
  strncpy(config.iv, "ipseccnf", 8) ;
  memset(&config.icv, 0, IPSEC_CONFIG_ICV_LEN) ;
  config.type = IPSEC_CONFIG_GET ; 

  if(strncmp(direction, "OUTBOUND", 8) == 0)
    config.direction = IPSEC_DIR_OUTBOUND ;
  if(strncmp(direction, "INBOUND", 7) == 0)
    config.direction = IPSEC_DIR_INBOUND ;

  if(send_config((char *)&config, sizeof(config_packet), 
		 remote_addr, IKE_PORT ) != 0)
    printf("error on sending get\n") ;
  
  return 0 ;
}

int send_config_file(char *config_file, char *remote_addr)
{
  FILE *fd ;
  char	line[MAX_LINE_SIZE+1] ;
  int	line_nr = 1 ;
  int	conn_found = 0 ;
  char	*ret_char ;
  config_packet config ;

  fd = fopen(config_file, "r") ;
  if(!fd)
    {
      perror("error on opening config file\n") ;
      return -1 ;
    }
  
  /* read line,if a "config" tag starts, we read in and send the config */
  memset(line, 0, MAX_LINE_SIZE) ;
  while(fgets(line, MAX_LINE_SIZE, fd))
    {
      if(strncmp(line, CONFIG_TAG, strlen(CONFIG_TAG)) == 0)
	{
	  /* setup static packet fields */
	  memset(&config, 0, sizeof(config_packet)) ;
	  strncpy(config.iv, "ipseccnf", 8) ;
	  memset(&config.icv, 0, IPSEC_CONFIG_ICV_LEN) ;
	  config.type = IPSEC_CONFIG_ADD ;
	  
	  if (get_config(fd, &config) == 0)
	    {
	      printf("did not get all config items\n") ;
	      return -2 ;
	    }
	  else
	    {
	      if(send_config((char *)&config, 
			     sizeof(config_packet), 
			     remote_addr, IKE_PORT ) != 0)
		printf("error on sending config\n") ;
	    }
	}
      memset(line, 0, MAX_LINE_SIZE) ;
    }
  
  if(fclose(fd))
    {
      perror("error on closing ipsec.conf\n") ;
      return -2 ;
    }

  return 0 ;
}

int main (int argc, char **argv)
{
  FILE *fd ;
  char	line[MAX_LINE_SIZE+1] ;
  int	line_nr = 1 ;
  int	conn_found = 0 ;
  char	*ret_char ;
  config_packet config ;
  
	printf("IPsec admin tool (compiled %s at %s)\n", __DATE__, __TIME__);
	printf("CVS ID: $Id: ipsecadmin.c,v 1.5 2004/02/11 00:48:33 schec2 Exp $\n\n");

  if(argc != 4)
    {
      print_usage() ;
      return -1 ;
    }

  if(strncmp(argv[1], "ADD", 3) == 0)
    {
      send_config_file(argv[2], argv[3]) ;
    }
  else if (strcmp(argv[1], "FLUSH") == 0)
    {
      send_config_flush(argv[2], argv[3]) ;
    }
  else if (strcmp(argv[1], "GET") == 0)
    {
      send_config_get(argv[2], argv[3]) ;
    }
  else
    {
      print_usage() ;
      return -1 ;
    }
  
  return 0 ;
}
