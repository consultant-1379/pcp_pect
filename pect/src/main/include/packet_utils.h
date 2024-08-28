#ifndef _PACKET_UTILS_H
#define _PACKET_UTILS_H

#include <netinet/ip.h>
#include <pcap.h>
#include <net/ethernet.h>


// Ethernet definitions
#define TAG_ETHER_802_1_Q_LENGTH 4  // The length of a 802.1Q tag in octets

typedef struct ether {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short int type;
} ether_t;

// GTP-C and GTP-U ports
#define GTP_C_UDP_PORT	2123
#define GTP_U_UDP_PORT	2152

// GTP versions
#define GTP_V1_TYPEVER 3      // GTP V1 is the version and GTP is the type
// Mandatory part of the GTP header
struct gtpv1hdr {
    u_char flag_options : 3,  // Extension, Sequence Number, and N-PDU flags
           flag_reserved : 1, // Reserved for future use
           flag_typever : 4;  // The GTP message type and version
    u_char message_type;     // The GTP message type
    u_short length;           // Total length excluding initial mandatory header (length includes optional fields)
    u_int teid;             // The TEID (Tunnel End Point Identifier)
};

// Macros to get GTP Type and Version
#define GTP_TYPE(flag_typever)		((flag_typever) >> 1)
#define GTP_VER(flag_typever)		((flag_typever) & 0x01)

// Macros to get GTP option flags
#define GTP_EXT_FLAG(flag_options)		(((flag_options) & 0x04) >> 2)
#define GTP_SEQ_FLAG(flag_options)		(((flag_options) & 0x02) >> 1)
#define GTP_NPDU_FLAG(flag_options)		(((flag_options) & 0x01))

// Optional part of the GTP-U header
// This field follows the gtpv1 struct if any of the extension header, sequence number, or N-PDU bits are set,
// if any of those bits are set, all the optional field must appear. The values only make sense if the respective
// bit is set
struct gtpv1hdropt {
    u_short sequence_no;     // The sequence number of the GTP packet
    u_char npdu_no;         // The N-PDU number
    u_char next_exthdrtype; // The next extension header type
};

typedef enum {
    NOT_YET_DEFINED = -1,
    HEADING_TO_INTERNET = 0,
    HEADING_TO_USER_EQUIPMENT = 1
} PacketDirection_t ;

// This function returns a pointer to a GTPv1 header in a packet in a data buffer.  It also populates the PectPacketHeader.teid_d.addr field with the GTP tunnel destination IP.
//
// Parameters:
//  const unsigned int length: The amount of data present in the data buffer
//  const unsigned char* data: A pointer to the packet data
//
// Return:
//  gtpv1hdr*: A pointer to a GTP V1 header if a GTP V1 packet is present, NULL otherwise
struct gtpv1hdr *gtpv1_get_header(const unsigned int length, const unsigned char *data, unsigned int *ethernetAndgtpv1Length, unsigned int *gtpOffset, struct PectPacketHeader *pectHeader);

// This function returns a pointer to the inner IP header of a GTP tunneled packet
//iphdr *get_ip_header(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned int *userPacketSize, unsigned int *ip2Offset, unsigned int *ip2HeaderSize, unsigned int *ip2TotalLength);
// efitleo: Returns 0 for success and 1 for error
int get_ip_header(struct PectPacketHeader *pectHeader, const unsigned char *packet);

// This function returns the UE IP from a GTP tunneled GTP-U packet
int parseLayer3Info(iphdr *ipHeader, unsigned long theSourceMacAddress, unsigned long theDestinationMacAddress,
                    struct PectPacketHeader *pectHeader);


int parseLayer4Info(const PacketDirection_t packetDirection, const iphdr *ipHeader, struct PectPacketHeader *pectHeader, unsigned int userPacketSize);
/*
 *
 * A number of functions that Prints a packet in hexadecimal format, aids in debugging packets
 *
 */
 // This one prints to console
void helper_print_packet_details(const struct iphdr *iph, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, int print_packet);
// This one print to log;
void helper_print_packet_details_to_log(const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, int print_packet, char* returnMessage);
#endif
