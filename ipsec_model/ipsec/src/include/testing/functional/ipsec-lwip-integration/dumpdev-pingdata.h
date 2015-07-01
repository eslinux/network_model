/** @file dumpdev-pingdata.h
 *  @brief This file contains a ICMP ping reference session to feed the dumpdev device (used for tests)
 */

/**
  * Sequence of dumped reference packets 
  **/

typedef enum dumpdev_packet_type_list {
	INBOUND  = 0,
	OUTBOUND = 1
} dumpdev_packet_type;


/** structure of a single packet */
typedef struct dumpdev_packet_struct
{
	dumpdev_packet_type packet_type;	/** define if packet is INBOUND or OUTBOUND */
	unsigned int size; 					/** packet size in bytes */
	unsigned char *payload;				/** packet payload */
} dumpdev_packet;



/** 
 * Recorded data of a ping sequence from host 192.168.1.2 (PC) to
 * 192.168.1.3 (MCB 167-NET board)
 */
//  Source File: 01 - PC ARP broadcast.bin
unsigned char ping_ARP_broadcast[42] =
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x06, 0x00, 0x01, 
    0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0xC0, 0xA8, 0x01, 0x02, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x03, 
} ;

//  Source File: 02 - uC ARP broadcast reply.bin
unsigned char ping_ARP_reply[60] =
{
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 
    0x08, 0x00, 0x06, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x03, 
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0xC0, 0xA8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
} ;


//  Source File: 03 - PC ping.bin
unsigned char ping_request_01[74] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7B, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xF0, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8, 
    0x01, 0x03, 0x08, 0x00, 0x49, 0x5C, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 04 - uC ping reply.bin
unsigned char ping_reply_01[74] =
{
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7B, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xF0, 0xC0, 0xA8, 0x01, 0x03, 0xC0, 0xA8, 
    0x01, 0x02, 0x00, 0x00, 0x51, 0x5C, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 05 - PC ping.bin
unsigned char ping_request_02[74] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7C, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xEF, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8, 
    0x01, 0x03, 0x08, 0x00, 0x48, 0x5C, 0x03, 0x00, 0x02, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 06 - uC ping reply.bin
unsigned char ping_reply_02[74] =
{
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7C, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xEF, 0xC0, 0xA8, 0x01, 0x03, 0xC0, 0xA8, 
    0x01, 0x02, 0x00, 0x00, 0x50, 0x5C, 0x03, 0x00, 0x02, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 07 - PC ping.bin
unsigned char ping_request_03[74] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7D, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xEE, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8, 
    0x01, 0x03, 0x08, 0x00, 0x47, 0x5C, 0x03, 0x00, 0x03, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 08 - uC ping reply.bin
unsigned char ping_reply_03[74] =
{
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7D, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xEE, 0xC0, 0xA8, 0x01, 0x03, 0xC0, 0xA8, 
    0x01, 0x02, 0x00, 0x00, 0x4F, 0x5C, 0x03, 0x00, 0x03, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 09 - PC ping.bin
unsigned char ping_request_04[74] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7E, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xED, 0xC0, 0xA8, 0x01, 0x02, 0xC0, 0xA8, 
    0x01, 0x03, 0x08, 0x00, 0x46, 0x5C, 0x03, 0x00, 0x04, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;

//  Source File: 10 - uC ping reply.bin
unsigned char ping_reply_04[74] =
{
    0x00, 0xE0, 0x29, 0x15, 0x1C, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 
    0x00, 0x3C, 0x00, 0x7E, 0x00, 0x00, 0x80, 0x01, 0xB6, 0xED, 0xC0, 0xA8, 0x01, 0x03, 0xC0, 0xA8, 
    0x01, 0x02, 0x00, 0x00, 0x4E, 0x5C, 0x03, 0x00, 0x04, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
    0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
    0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 
} ;



dumpdev_packet ping_sequence[] = {
	{ INBOUND,  sizeof(ping_ARP_broadcast),	ping_ARP_broadcast},
	{ OUTBOUND, sizeof(ping_ARP_reply),		ping_ARP_reply},
	{ INBOUND,  sizeof(ping_request_01), 	ping_request_01},
	{ OUTBOUND, sizeof(ping_reply_01), 		ping_reply_01},
	{ INBOUND,  sizeof(ping_request_02), 	ping_request_02},
	{ OUTBOUND, sizeof(ping_reply_02), 		ping_reply_02},
	{ INBOUND,  sizeof(ping_request_03), 	ping_request_03},
	{ OUTBOUND, sizeof(ping_reply_03), 		ping_reply_03},
	{ INBOUND,  sizeof(ping_request_04), 	ping_request_04},
	{ OUTBOUND, sizeof(ping_reply_04), 		ping_reply_04},
};


#define PING_SEQUENCE_LENGTH (sizeof(ping_sequence) / sizeof(dumpdev_packet))
int ping_sequence_pos = 0;

