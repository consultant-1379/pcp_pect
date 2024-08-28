/*************************************************************************
 * COPYRIGHT (C) Ericsson 2012                                           *
 * The copyright to the computer program(s) herein is the property       *
 * of Telefonaktiebolaget LM Ericsson.                                   *
 * The program(s) may be used and/or copied only with the written        *
 * permission from Telefonaktiebolaget LM Ericsson or in accordance with *
 * the terms and conditions stipulated in the agreement/contract         *
 * under which the program(s) have been supplied.                        *
 *************************************************************************
 *************************************************************************
 * File: packet_utils.cc
 * Date: Feburary 21, 2013
 * Author: LMI/LXR/PE Richard Kerr
 ************************************************************************/

/*************************************************************************
 * This file contains functions for the manipulation of packets to       *
 * obtain specific pieces of information.                                *
 *************************************************************************/
#include "flow.h"
#include "gtpv1_utils.h"
#include "logger.hpp"
#include "packet_utils.h"
#include "packetbuffer.h"


#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <iostream>
#include <list>

using namespace log4cxx;
using namespace std;
// TODO: All configuration (ie: EArgs type and variable) should be moved to config.cc, at that time remove this include
extern EArgs evaluatedArguments;

// TODO: When logging/monitoring is implemented, these should belong there (not in classify.cc)

/**
 * Get determines the Ip to search from by comaring mac address of packet with known list of mac addreses.
 *
 * Logic here is that each packet will have just one mac address associated with it.
 *
 * input   1. ipheader
 * input   2. sourceMacAddress
 * input   3. destinationMAcAddress
 * input   4. mac lookuptable
 *
 * output
 *       1. layer 3 info will be output to pectHeader
 * Also there are 3 options for each loop
 *      - It mactech the source mac address
 *      - it matches the destination mac address
 *      - this mac address does not match either source or destination address..So try the next mac address
 *
 * Also once the matching mac adress is found, we don't need to search for other mac addresses.
 *
 * Also Have decided that if no matching mac addreses found we should print a warning.
 */
int parseLayer3Info(iphdr *ipHeader, unsigned long theSourceMacAddress, unsigned long theDestinationMacAddress, struct PectPacketHeader *pectHeader) {
    unsigned int ipPacketLength =  pectHeader->userPacketSize;

    //check can access current ipHeader
    if(ipPacketLength < sizeof(iphdr)) {
        return 1;
    }

    bool macAddressFound = false;
    list<unsigned long>::iterator mac_Itr;
    
    // Ensure fourTuple is being set.
    pectHeader->fourTuple.ueIP = 0;
    pectHeader->fourTuple.uePort = 0;
    pectHeader->fourTuple.serverIP = 0;
    pectHeader->fourTuple.serverPort = 0;
    int parseLayer4_bad=1;
						  
    for(mac_Itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
            mac_Itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++mac_Itr) {
        if(*mac_Itr == theSourceMacAddress) {
            pectHeader->packetDirection = HEADING_TO_USER_EQUIPMENT;
            pectHeader->fourTuple.ueIP = ntohl(ipHeader->daddr);
            pectHeader->fourTuple.serverIP = ntohl(ipHeader->saddr);
            parseLayer4_bad = parseLayer4Info(HEADING_TO_USER_EQUIPMENT, ipHeader, pectHeader, ipPacketLength);
            macAddressFound = true;
            break;
        }

        if(*mac_Itr == theDestinationMacAddress) {
            pectHeader->packetDirection = HEADING_TO_INTERNET;
            pectHeader->fourTuple.ueIP = ntohl(ipHeader->saddr);
            pectHeader->fourTuple.serverIP = ntohl(ipHeader->daddr);
            parseLayer4_bad = parseLayer4Info(HEADING_TO_INTERNET, ipHeader, pectHeader, ipPacketLength);
            macAddressFound = true;
            break;
        }
    }
					  
    if(!macAddressFound) {
        std::string macAddr("");

        for(mac_Itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
                mac_Itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++mac_Itr) {
            LOG4CXX_WARN(loggerPect, "MAC ADDRESSES Known Mac Address = 0x" << std::hex << *mac_Itr);
        }

        LOG4CXX_WARN(loggerPect,
                     "MAC ADDRESSES Source Mac Address = 0x" << std::hex << theSourceMacAddress);
        LOG4CXX_WARN(loggerPect,
                     "MAC ADDRESSES Destination Mac Address = 0x" << std::hex << theDestinationMacAddress << " ");
        return (1); // If mac address is not found, no point in continuing.
    }

	if(parseLayer4_bad) return 2;
	
    return 0;
}

/**
 * Function to get port number for a IP packet, Thread safe.
 *
 * Input:
 *   1. packetDirection
 *   2. ip header
 *
 * Output:
 *   1. all the layer4 info will be output to pectHeader
 */
inline int parseLayer4Info(const PacketDirection_t packetDirection, const iphdr *ipHeader, PectPacketHeader *pectHeader, unsigned int userPacketSize) {
    pectHeader->isTcpPacket = false;
    pectHeader->windowsSize = 0;

		
	if(ipHeader->protocol == 0x06) { // check if it's TCP protocol
        unsigned char *p = (unsigned char *)ipHeader;
        int tcpUserPacketSize = userPacketSize - ipHeader->ihl * 4;
        const struct tcphdr *tcpHeader = (tcphdr *)(p + (ipHeader->ihl * 4)); 
		
        //check can access current tcpHeader
        if(tcpUserPacketSize < (int)sizeof(tcphdr)) {
			if(loggerPect->isDebugEnabled()) {
				LOG4CXX_DEBUG(loggerClassify, "PACKET INTEGRITY SIZE CHECK parseLayer4Info(): TCP Header size too small (Fragment at IP1 layer?) "
							  << ": (pectHeader) UE IP = " << pectHeader->fourTuple.ueIP
							  << ": (pectHeader) UE PORT (zero?) = " << pectHeader->fourTuple.uePort
							  << ": (pectHeader) SERVER IP = " << pectHeader->fourTuple.serverIP
							  << ": (pectHeader) SERVER PORT (zero?) = " << pectHeader->fourTuple.serverPort
							  << ": TCP User Packet Size = " << tcpUserPacketSize
							  << ": sizeof(tcphdr) = " << (int)sizeof(tcphdr)
							  );
			}
            return 1;
        }

        // Ensure that it is specifically a TCP Packet.
        pectHeader->isTcpPacket = true;
        pectHeader->windowsSize = ntohs(tcpHeader->window);

        if(packetDirection == HEADING_TO_USER_EQUIPMENT) {
            pectHeader->fourTuple.serverPort = ntohs(tcpHeader->source);
            pectHeader->fourTuple.uePort = ntohs(tcpHeader->dest);
        } else {
            pectHeader->fourTuple.uePort = ntohs(tcpHeader->source);
            pectHeader->fourTuple.serverPort = ntohs(tcpHeader->dest);
        }
    }
	if(ipHeader->protocol == 0x11) { // check if it's UDP protocol
        unsigned char *p = (unsigned char *)ipHeader;
        int udpUserPacketSize = userPacketSize - ipHeader->ihl * 4;
		const struct udphdr *udpHeader = (struct udphdr *)(p + (ipHeader->ihl * 4));
        //check can access current tcpHeader
        if(udpUserPacketSize < (int)sizeof(udphdr)) { 
			if(loggerPect->isDebugEnabled()) {
				LOG4CXX_DEBUG(loggerClassify, "PACKET INTEGRITY SIZE CHECK parseLayer4Info(): UDP Header size too small (Fragment at IP1 layer?) "
							  << ": (pectHeader) UE IP = " << pectHeader->fourTuple.ueIP
							  << ": (pectHeader) UE PORT (zero?) = " << pectHeader->fourTuple.uePort
							  << ": (pectHeader) SERVER IP = " << pectHeader->fourTuple.serverIP
							  << ": (pectHeader) SERVER PORT(zero?) = " << pectHeader->fourTuple.serverPort
							  << ": UDP User Packet Size = " << udpUserPacketSize
							  << ": sizeof (udphdr) = " << (int)sizeof(udphdr)
							  );
			}
            return 1;
        }

        if(packetDirection == HEADING_TO_USER_EQUIPMENT) {
            pectHeader->fourTuple.serverPort = ntohs(udpHeader->source);
            pectHeader->fourTuple.uePort = ntohs(udpHeader->dest);
        } else {
            pectHeader->fourTuple.uePort = ntohs(udpHeader->source);
            pectHeader->fourTuple.serverPort = ntohs(udpHeader->dest);
        }
    }
    // GTP carries IGMP, ICMP, DNS and other such protocols also. No ports with these by definition: So ports will be zero
    return 0;
}

/**
 * This function returns a pointer to a GTPv1 header in a packet in a data buffer
 *
 * Parameters:
 *  const unsigned int length: The amount of data present in the data buffer
 *  const unsigned char* data: A pointer to the packet data
 *
 * Return:
 *  gtpv1hdr*: A pointer to a GTP V1 header if a GTP V1 packet is present, NULL otherwise
 *  *ethernetAndgtpv1HeaderSize size of ether + gtpv1 header
 */
struct gtpv1hdr *
gtpv1_get_header(const unsigned int length, const unsigned char *data, unsigned int *bytesLeftFromReturnedPtr, unsigned int *gtpOffset, struct PectPacketHeader *pectHeader) {
    // Keep track of the current position to avoid complex casts
    unsigned int offset = 0;

    // Check if there is enough data for the Ethernet header
    if(length - offset < sizeof(struct ether_header)) {
		LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Invalid Ethernet header size: Packet will be dropped ");
        return NULL;
    }

    // Set the Ethernet header pointer
    struct ether_header *ether_header = (struct ether_header *)(data + offset);

    // Check if there is a VLAN specified in the Ethernet header
    int ether_type = ntohs(ether_header->ether_type);

    if(ether_type == ETHERTYPE_VLAN) {
        if(length - offset < sizeof(struct ether_header) + TAG_ETHER_802_1_Q_LENGTH) {
			LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Invalid VLAN header size: Packet will be dropped ");
            return NULL;
        }

        // In this case, we must skip past the 802.1Q tag and find the Ethernet type in the next 2 octets
        u_short *ether_typep = (u_short *)(((char *) &ether_header->ether_type) + TAG_ETHER_802_1_Q_LENGTH);
        ether_type = ntohs(*ether_typep);
        // Set the IP header pointer to the end of the Ethernet header, this is the outer IP header
        offset += (unsigned int) sizeof(struct ether_header) + TAG_ETHER_802_1_Q_LENGTH;
    } else {
        // Set the IP header pointer to the end of the Ethernet header, this is the outer IP header
        offset += (unsigned int) sizeof(struct ether_header);
    }

    // Check if this is an IPv4 packet, if not, return because for now we only support IPV4
    // TODO: Implement IPv6
    if(ether_type != ETHERTYPE_IP) {
		LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Packet is not IP over Ethernet: Packet will be dropped ");
        return NULL;
    }

    // Check if there is enough data for the IP header
    if(length - offset < sizeof(struct ip)) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Invalid IP Header size: Packet will be dropped ");
        return NULL;
    }

    // Set the IP header pointer
    struct ip *ip_header = (struct ip *)(data + offset);

    // Check if the IP header version is IPv4, for now we only support IPv4
    // TODO: Implement IPv6
    if(ip_header->ip_v != IPVERSION) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : NOT IPV4 PACKET: Packet will be dropped ");
        return NULL;
    }
    
    // Check if the enclosing protocol is UDP, GTP is carried in UDP
    if(ip_header->ip_p != IPPROTO_UDP) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : NON UDP PACKET: Packet will be dropped ");
        return NULL;
    }
    
    // Check if the packet is fragmented
    pectHeader->ip1_fragmented = 0;
    uint16_t ipFragmented_bytes = ntohs(ip_header->ip_off);
    if(ipFragmented_bytes & (IP_MF | IP_OFFMASK)) {
        // Fragmented
         pectHeader->ip1_fragmented = 1;
         LOG4CXX_TRACE(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : FRAGMENTED at L1: Packet will be dropped ");
         return NULL; // PACE will not decode beyond first fragmented layer i.e. ports get set to 2152 and IPs == GGSN and SGSN
    }
    
    
    // Set the UDP header pointer to the end of the IP header, The IP header length is in units of 4 octets
    offset += ip_header->ip_hl * 4;

    // Store the addr of the teid
    pectHeader->teid_d.addr = ntohl(ip_header->ip_dst.s_addr);

    // Check if there is enough data for the UDP header
    if(length - offset < sizeof(struct udphdr)) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Invalid UDP header size at layer 1: Packet will be dropped ");
        return NULL;
    }

    //Set the UDP header pointer
    struct udphdr* udp_header = (struct udphdr*) (data + offset);
    pectHeader->udp1_srcPort = ntohs(udp_header->source);
    pectHeader->udp1_dstPort = ntohs(udp_header->dest);
    
    // Check for GTP-U or GTP-C
    if (pectHeader->udp1_srcPort != GTP_U_UDP_PORT && pectHeader->udp1_dstPort != GTP_U_UDP_PORT &&
        pectHeader->udp1_srcPort != GTP_C_UDP_PORT && pectHeader->udp1_dstPort != GTP_C_UDP_PORT) {
      LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : UDP PORT Number is not GTP-U or GTP-C: Packet will be dropped ");
      return NULL;
    }
	
    // Set the GTP V1 header pointer to the end of the UDP header
    offset += (unsigned int) sizeof(struct udphdr);

    // Check if there is enough data for the GTP v1 header
    if(length - offset < sizeof(struct gtpv1hdr)) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Invalid GTP v1 header size : Packet will be dropped ");
        return NULL;
    }

    // Set the UDP header pointer
    struct gtpv1hdr *gtpv1_header = (struct gtpv1hdr *)(data + offset);



    // Check for GTP Version 1
    if(gtpv1_header->flag_typever != GTP_V1_TYPEVER) {
         LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : gtpv1_get_header() : Packet is not GTP Version 1: Packet will be dropped ");
        return NULL;
    }


    *bytesLeftFromReturnedPtr = length - offset;
    *gtpOffset = offset;
    
    // OK, we have now got to the GTP v1 header
    return gtpv1_header;
}

int get_ip_header(struct PectPacketHeader *pectHeader, const unsigned char *packet) {
    //iphdr *get_ip_header(const struct pcap_pkthdr *header, const unsigned char *packet, unsigned int *userPacketSize, unsigned int *ip2Offset, unsigned int *ip2HeaderSize, unsigned int *ip2TotalLength) {
    //get the GTP header this allows us to ignore VLANs
    unsigned int lengthFromGtpv1hdr = 0;
    unsigned int offsetToGtp = 0;

    if(&pectHeader->pcapHeader == NULL) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : get_ip_header():The pcap header is NULL this packet will be dropped");
        return 1;
    }

    struct gtpv1hdr *gtpv1hdr = gtpv1_get_header(pectHeader->pcapHeader.caplen, (const unsigned char *) packet, &lengthFromGtpv1hdr, &offsetToGtp, pectHeader);

    if(gtpv1hdr == NULL) {
        LOG4CXX_TRACE(loggerPcpGlue, "GTP-U PACKET : get_ip_header(): A valid GTPv1 header was not created this packet will be dropped");
        return 1;
    }

    int GTPFlags = gtpv1hdr->flag_options;
    unsigned int IPLocation = 0;

    //account for the two sizes of GTP header
    if(GTPFlags > 0) {
        IPLocation = 0x0c;
    } else {
        IPLocation = 0x08;
    }

    //If we don't have enough length in gtp header
    if(lengthFromGtpv1hdr < IPLocation) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : get_ip_header(): Packet too small,GTPC header size: " << IPLocation << ", lengthFromGtpv1hdr:" << lengthFromGtpv1hdr);
        return 1;
    }

    pectHeader->teid_d.teid = ntohl(gtpv1hdr->teid);
    pectHeader->teid_d.time = (double) pectHeader->pcapHeader.ts.tv_sec; // + (double) pectHeader->pcapHeader.ts.tv_usec / 1e6;
    pectHeader->userPacketSize = lengthFromGtpv1hdr - IPLocation; // this is userIpPacket Size
    pectHeader->userPacketOffset = offsetToGtp + IPLocation;
    unsigned char *theGTPHeaderIndex = (unsigned char *) gtpv1hdr;
    iphdr *ipPacket = (iphdr *)(&theGTPHeaderIndex[IPLocation]);
    
   
    pectHeader->ip2_fragmented = 0;
    pectHeader->ip2_fragmented_dropped = 0;
	
    uint16_t ipFragmented_bytes = ntohs(ipPacket->frag_off);
    if(ipFragmented_bytes & (IP_MF | IP_OFFMASK)) {
		
		// Fragmented
		pectHeader->ip2_fragmented = 1;
		
		// fragment zero has offset of zero and more fragments bit set.
		// So if frag offset is non zero then drop the packet
		if((ipFragmented_bytes & IP_OFFMASK) > 0 ) {
			LOG4CXX_TRACE(loggerPcpGlue, "GTP-U PACKET : get_ip_header(): Fragmented Packet (not fragment 0) at IP Layer 2: Packet will be dropped ");
			pectHeader->ip2_fragmented_dropped = 1;
			return 1;
		}
	}
	
	
    pectHeader->userHeaderSize = ipPacket->ihl * 4;
    pectHeader->userTotalLength = ntohs(ipPacket->tot_len);
    pectHeader->userPacketIPHeader = ipPacket;
    
    return 0;
}


/*
 * This function prints the RAW packet bytes
 * Call it from pcpGlue
 */ 

// NOTE: This prints to console.
void helper_print_packet_details(const struct iphdr *iph, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, int print_packet) {
    unsigned int sip = ntohl(iph->saddr);
    unsigned int dip = ntohl(iph->daddr);
    int start = 0; // starting offset
    int end = header->caplen; // ending offset
    int i;
    
		
	if(print_packet) {
		for(i = start; i < end; i++) {
			if((i % 15) == 0) {
				printf("\n%d: ",i);
			}
			printf(" %.2x", packet[i]);
			
		}
	}

	printf("\n");    
	printf("headerlength: %u\n", header->caplen);
	printf("source address:  0x%x (%u)\n", ntohl(iph->saddr), ntohl(iph->saddr));
	printf("dest address:  0x%x (%u)\n",  ntohl(iph->daddr), ntohl(iph->daddr));
	printf("source address:  0x%x (%u)\n",  sip, sip);
	printf("dest address:  0x%x (%u)\n", dip, dip);
	printf("Protocol:  0x%x (%u)\n", iph->protocol, iph->protocol);
	//printf("tot_len:  0x%x (%u)\n", iph->tot_len, iph->tot_len);  // Depend on if packet is large enough (may be fragmented at IP level 1)
	//printf("frag_off:  0x%x (%u)\n", iph->frag_off, iph->frag_off); //Depend on if packet is large enough (may be fragmented at IP level 1)
	
	printf("PCAP caplen:  0x%x (%u)\n",  header->caplen,  header->caplen);
	printf("PCAP len:  0x%x (%u)\n",  header->len,  header->len);
	

	printf("(pectHeader) UE IP = 0x%x (%u)\n", pectHeader->fourTuple.ueIP, pectHeader->fourTuple.ueIP);
	printf("(pectHeader) UE PORT = 0x%x (%u)\n", pectHeader->fourTuple.uePort, pectHeader->fourTuple.uePort);
	printf("(pectHeader) SERVER IP = 0x%x (%u)\n", pectHeader->fourTuple.serverIP, pectHeader->fourTuple.serverIP);
	printf("(pectHeader) SERVER PORT = 0x%x  (%u) \n", pectHeader->fourTuple.serverPort, pectHeader->fourTuple.serverPort);
	printf("\n");

}


/*
 * This function prints the RAW packet bytes
 * Call it from pcpGlue
 */ 
void helper_print_packet_details_to_log(const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, int print_packet, char* returnMessage) {
    
    if(packet == NULL) return;
    const struct ether *ethernet = (struct ether *) packet;
    u16 type = ethernet->type;
    struct iphdr *iph_L1 = (struct iphdr *)(&packet[sizeof(struct ether)]);

    // If the packet is VLAN tagged
    if(type == htons(ETH_P_8021Q)) {
        iph_L1 = (struct iphdr *)(&packet[sizeof(struct ether) + 4]);
    }

    unsigned int sip = ntohl(iph_L1->saddr);
    unsigned int dip = ntohl(iph_L1->daddr);
    unsigned int protocol_L1 = (unsigned int ) iph_L1->protocol;
    
    
    const struct iphdr *iph_L2 = pectHeader->userPacketIPHeader;
    
    int start = 0; // starting offset
    int end = header->caplen; // ending offset
    int i;
    LOG4CXX_TRACE(loggerPect, "GTP PACKET: RAW PACKET");    
    int BUF_SIZE;
    int MINI_BUF_SIZE=200;
    int PACKET_SIZE = 2000;
    int TRAILING_INFO_LEN = 2000;
    BUF_SIZE = (PACKET_SIZE*3)+TRAILING_INFO_LEN;
    
	char msgOut[BUF_SIZE];
	char tmp[MINI_BUF_SIZE];
	for(int j=0; j< BUF_SIZE; j++) msgOut[j] ='\0';
	
	if(end > PACKET_SIZE ) {
		end = PACKET_SIZE-1;
	}
	
	
	if(print_packet) {
		for(i = start; i < end; i++) {
			for(int j=0; j< MINI_BUF_SIZE; j++) tmp[j] ='\0';
			if((i % 16) == 0) {
				snprintf(tmp,  MINI_BUF_SIZE-1, "\n%d: ",i);
				strcat(msgOut,tmp);
			}
			snprintf(tmp, MINI_BUF_SIZE-1, " %.2x", packet[i]);
			
			tmp[MINI_BUF_SIZE-1] = '\0';
			strcat(msgOut,tmp);
		}
	}
	
	strcat(msgOut,"\n\0");    

	snprintf(tmp, MINI_BUF_SIZE-1, "L1 source address:  0x%x (%u)\n", sip, sip);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "L1 dest address:  0x%x (%u)\n", dip, dip);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "L1 Protocol:  0x%x (%u)\n",protocol_L1, protocol_L1);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "L1 Fragmentation:  %u \n",pectHeader->ip1_fragmented);
	strcat(msgOut,tmp);
	
	if(iph_L2 != NULL ) {
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 source address:  0x%x (%u)\n",  ntohl(iph_L2->saddr),  ntohl(iph_L2->saddr));
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 dest address:  0x%x (%u)\n", ntohl(iph_L2->daddr), ntohl(iph_L2->daddr));
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 Protocol:  0x%x (%u)\n",iph_L2->protocol, iph_L2->protocol);
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 Fragmentation:  %u \n",pectHeader->ip2_fragmented);
		strcat(msgOut,tmp);
	}
	else {
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 source address:  NULL\n");
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 dest address:  NULL\n");
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 Protocol: NULL\n");
		strcat(msgOut,tmp);
		
		snprintf(tmp, MINI_BUF_SIZE-1, "L2 Fragmentation: NULL \n");
		strcat(msgOut,tmp);
	}

	snprintf(tmp, MINI_BUF_SIZE-1, "PCAP caplen / header length: %u\n", header->caplen);
	strcat(msgOut,tmp);
			
	snprintf(tmp, MINI_BUF_SIZE-1, "PCAP len / header length: %u\n", header->len);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "(pectHeader) UE IP = 0x%x (%u)\n", pectHeader->fourTuple.ueIP, pectHeader->fourTuple.ueIP);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "(pectHeader) UE PORT = 0x%x (%u)\n", pectHeader->fourTuple.uePort, pectHeader->fourTuple.uePort);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "(pectHeader) SERVER IP = 0x%x (%u)\n", pectHeader->fourTuple.serverIP, pectHeader->fourTuple.serverIP);
	strcat(msgOut,tmp);
	
	snprintf(tmp, MINI_BUF_SIZE-1, "(pectHeader) SERVER PORT = 0x%x (%u)\n", pectHeader->fourTuple.serverPort, pectHeader->fourTuple.serverPort);
	strcat(msgOut,tmp);
	
	msgOut[BUF_SIZE-1] = '\0';
	if(returnMessage == NULL) {
		LOG4CXX_TRACE(loggerPect, msgOut);
	}
	else {
		strcpy(returnMessage,msgOut);
	}
	
}



