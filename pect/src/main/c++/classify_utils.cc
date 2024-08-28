#include "classify.h"


#include <arpa/inet.h>
#include <algorithm>
#include <arpa/inet.h>
#include <boost/foreach.hpp>
#include <cstring>
#include <iomanip>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <stdint.h>
#include <sys/types.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <time.h>

using std::stringstream;
using std::string;
using std::hex;
using namespace log4cxx;


void test_flowID_intergity_header(){
		LOG4CXX_DEBUG(loggerFlowIntegrity, "FLOW INTEGRITY CHECK: classify(): FLOW ID (four tuple) IS NOT EQUAL TO PECT (four tuple) ID"
						  << "| new_element" 
						  << "| (flow_data) Pkts Up / Down"
						  << "| (flow_data) UE IP "   << "| (pectHeader) UE IP " 
						  << "| (flow_data) UE PORT " << "| (pectHeader) UE PORT " 
						  << "| (flow_data) SERVER IP " << "| (pectHeader) SERVER IP " 
						  << "| (flow_data) SERVER PORT " << "| (pectHeader) SERVER PORT " 
						  << "| application "
						  << "| group "
						  << "| sub_protocol "
						  << "| protocol "
						  << "| IP L1 Fragmented Packet "
						  << "| IP L2 Fragmented Packet "
						  << "| IP L1 Protocol "
						  << "| IP L2 Protocol "
						  << "| ID "
						  << "| (Ipoque) Lower IP "
						  << "| (Ipoque) Lower Port "
						  << "| (Ipoque) Higher IP "
						  << "| (Ipoque) Higher Port "
						  << "| (Ipoque) protocol Number "
						  );
}

void getIP_dotDecimal_from_host_format_ip_u32(u32 host_ip, char* ip_str, int len) {
    struct in_addr ip_in;
    ip_in.s_addr = htonl((host_ip));
    inet_ntop(AF_INET, &ip_in, ip_str, len);
}
void getIP_dotDecimal_from_netwok_format_ip_long(u32 ip_long, char* ip_str, int len) {
    struct in_addr ip_in;
    ip_in.s_addr = ip_long ;
    inet_ntop(AF_INET, &ip_in, ip_str, len);
}
void printUniqueFlow(struct ipoque_unique_flow_struct *unique_flow, const char* msg, char* outBuf, int outBufSize) {
	
		if (unique_flow != NULL) {

		    char lowIPBuf[40];
		    char upIPBuf[40];
		    
			getIP_dotDecimal_from_netwok_format_ip_long(unique_flow->lower_ip, lowIPBuf, 40);
			getIP_dotDecimal_from_netwok_format_ip_long(unique_flow->upper_ip, upIPBuf, 40);
			
			/* printf("%s :Flow between IP %u (%u)(%s) port %u and IP %u (%u)(%s) port %u, protocol %u\n",msg, unique_flow->lower_ip, ntohl(unique_flow->lower_ip), lowIPBuf, ntohs(unique_flow->lower_port), \
			                                                                                                unique_flow->upper_ip, ntohl(unique_flow->upper_ip), upIPBuf, ntohs(unique_flow->upper_port), \
			                                                                                                unique_flow->protocol );
			*/
			snprintf(outBuf,outBufSize -2, "| %s | %u (%u)(%s)| %u | %u (%u)(%s)| %u, | %u\n",msg, unique_flow->lower_ip, ntohl(unique_flow->lower_ip), lowIPBuf, ntohs(unique_flow->lower_port), \
			                                                                                                unique_flow->upper_ip, ntohl(unique_flow->upper_ip), upIPBuf, ntohs(unique_flow->upper_port), \
			                                                                                                unique_flow->protocol );
		   outBuf[outBufSize -1] = '\0';
		}
		else{
		   // printf("FLOW INTEGRITY CHECK: printUniqueFlow():  %s UNIQUE FLOW ID is NULL\n", msg);
		   snprintf(outBuf,outBufSize -1, "| %s | UNIQUE FLOW ID is NULL\n", msg);
		   outBuf[outBufSize -1] = '\0';
		}

}
void printHashFiveTuple(classify_data cd, uint32_t ip, const char* msg, char* outBuf, int outBufSize,  struct ipoque_flow_struct *flow, struct ipoque_unique_flow_struct *unique_flow){
		
	
	const void *rr;
	if((cd->connection_toh != NULL) && (cd->subscriber_toh != NULL)) { 
		rr = ipoque_to_hash_get_unique_key_from_user_data(cd->connection_toh, flow);
		unique_flow = (struct ipoque_unique_flow_struct *) rr;
		printUniqueFlow(unique_flow, msg,  outBuf, outBufSize);
	}
	else{
		LOG4CXX_WARN(loggerClassify, "Hash table is NULL when trying to get the ID.");
		snprintf(outBuf,outBufSize -1, "| %s | Hash table is NULL when trying to get the ID.\n", msg);
		outBuf[outBufSize -1] = '\0';
		
	} 

}

u8 dump_hash_table_callback(u8 * unique_buffer, u8 * user_buffer, u32 last_timestamp, void *user_data)
{
	int BUF_SIZE=300;
	char ueBUF[BUF_SIZE];
	snprintf(ueBUF,BUF_SIZE -1, "| IPQ flow | No Value Set");
	ueBUF[BUF_SIZE -1] = '\0';
	struct ipoque_unique_flow_struct *unique_flow = (struct ipoque_unique_flow_struct *) unique_buffer;
	printUniqueFlow(unique_flow,"DUMPING TABLE",ueBUF,BUF_SIZE);
	return 0;
}

void dump_hash_table(classify_data cd)
{
	
	/* write flow entries */
	ipoque_to_hash_foreach(cd->connection_toh, dump_hash_table_callback, NULL);

	fprintf(stderr, "Dumping end\n");
}
/*
 * This function prints the RAW packet bytes if flow_data four Tuple (previous port values) and pectHeader four tuple (current port values) are zero or not equal
 * Call it from classify
 */ 
// NOTE: This prints to console.
void helper_print_packet_details_and_flow_details (const struct iphdr *iph_L1, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, struct flow_data *flow_data, struct ipoque_flow_struct *flow, classify_data cd, int print_packet) {
    unsigned int sip = ntohl(iph_L1->saddr);
    unsigned int dip = ntohl(iph_L1->daddr);
    int start = 0; // starting offset
    int end = header->caplen; // ending offset
    int i;
    const struct iphdr *iph_L2 = pectHeader->userPacketIPHeader;
    
    if (flow_data->packetsUp < 5) return;
	if (flow_data->packetsDown < 5) return;
	// NOTE : iph_L1->protocol == 01 = ICMP & iph_L1->protocol == 47 = GRE Generic Routing Encapsulation + No PORT Numbers 
	if(((iph_L2->protocol == 0x06) || (iph_L2->protocol ==0x11)) && (iph_L1->protocol == 0x11)) {  // L1 = UDP & L2 = UDP or TCP
		if((flow_data->fourTuple.ueIP != pectHeader->fourTuple.ueIP) || 
			   (flow_data->fourTuple.serverIP != pectHeader->fourTuple.serverIP) || 
			   (flow_data->fourTuple.uePort != pectHeader->fourTuple.uePort) || 
			   (flow_data->fourTuple.serverPort != pectHeader->fourTuple.serverPort) || 		   
			   (flow_data->fourTuple.ueIP == 0) || 
			   (flow_data->fourTuple.serverIP == 0) || 
			   (flow_data->fourTuple.uePort == 0) || 
			   (flow_data->fourTuple.serverPort == 0)
			   ) {
			
				if(print_packet) {
					for(i = start; i < end; i++) {
						if((i % 16) == 0) {
							printf("\n%d: ",i);
						}
						printf(" %.2x", packet[i]);
						
					}
				}
				

				printf("\n");    
				printf("headerlength: %u\n", header->caplen);

				printf("source address  (Layer 1):  0x%x (%u)\n",  sip, sip);
				printf("dest address (Layer 1):  0x%x (%u)\n", dip, dip);
				
				printf("source address (Layer 2):  0x%x (%u)\n", ntohl(iph_L2->saddr), ntohl(iph_L2->saddr));
				printf("dest address  (Layer 2):  0x%x (%u)\n",  ntohl(iph_L2->daddr), ntohl(iph_L2->daddr));
				
				printf("L1 Protocol:  0x%x (%u)\n", iph_L1->protocol, iph_L1->protocol);
				printf("L2 Protocol:  0x%x (%u)\n", iph_L2->protocol, iph_L2->protocol);
				
				printf("IP L1 Fragmented: %u\n", pectHeader->ip1_fragmented);
				printf("IP L2 Fragmented: %u\n", pectHeader->ip2_fragmented);
				
				
				printf("(pectHeader) UE IP = 0x%x (%u)\n", pectHeader->fourTuple.ueIP, pectHeader->fourTuple.ueIP);
				printf("(pectHeader) UE PORT = 0x%x (%u)\n", pectHeader->fourTuple.uePort, pectHeader->fourTuple.uePort);
				printf("(pectHeader) SERVER IP = 0x%x (%u)\n", pectHeader->fourTuple.serverIP, pectHeader->fourTuple.serverIP);
				printf("(pectHeader) SERVER PORT = 0x%x  (%u) \n", flow_data->fourTuple.serverPort, flow_data->fourTuple.serverPort);

				printf("(flow_data) UE IP = 0x%x (%u)\n", flow_data->fourTuple.ueIP, flow_data->fourTuple.ueIP);
				printf("(flow_data) UE PORT = 0x%x (%u) \n", flow_data->fourTuple.uePort, flow_data->fourTuple.uePort);
				printf("(flow_data) SERVER IP = 0x%x (%u)\n", flow_data->fourTuple.serverIP, flow_data->fourTuple.serverIP);
				printf("(flow_data) SERVER PORT = 0x%x (%u) \n", pectHeader->fourTuple.serverPort, pectHeader->fourTuple.serverPort);
				
				int BUF_SIZE=300;
				char ueBUF[BUF_SIZE];
				snprintf(ueBUF,BUF_SIZE -1, "| IPQ flow | No Value Set");
				ueBUF[BUF_SIZE -1] = '\0';
					
				uint32_t ueip_network = htonl(flow_data->hashKey);
				struct ipoque_unique_flow_struct *unique_flow = NULL;
				printHashFiveTuple(cd, ueip_network,(const char *) "IPQ flow", ueBUF, BUF_SIZE, flow, unique_flow);
				printf("%s", ueBUF);
					

				printf("\n");
		}
	}

}




/*
 * This function prints the RAW packet bytes if flow_data four Tuple (previous port values) and pectHeader four tuple (current port values) are zero or not equal
 * Call it from classify
 */ 
// NOTE: This prints to log
void helper_print_packet_details_and_flow_details_to_log (const struct iphdr *iph_L1, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, struct flow_data *flow_data, struct ipoque_flow_struct *flow, classify_data cd, int print_packet) {

	if(packet == NULL) return;
    const struct iphdr *iph_L2 = pectHeader->userPacketIPHeader;
    
    int BUF_SIZE;
    int MINI_BUF_SIZE=200;
    int PACKET_SIZE = 2000;
    int TRAILING_INFO_LEN = 3000;
    BUF_SIZE = (PACKET_SIZE*3)+TRAILING_INFO_LEN;
    
	char msgOut[BUF_SIZE];
	char tmp[MINI_BUF_SIZE];
	for(int j=0; j< BUF_SIZE; j++) msgOut[j] ='\0';
	for(int j=0; j< MINI_BUF_SIZE; j++) tmp[j] ='\0';
    
    if (flow_data->packetsUp < 5) return;
	if (flow_data->packetsDown < 5) return;
	// NOTE : iph_L1->protocol == 01 = ICMP & iph_L1->protocol == 47 = GRE Generic Routing Encapsulation + No PORT Numbers 
	if(((iph_L2->protocol == 0x06) || (iph_L2->protocol ==0x11)) && (iph_L1->protocol == 0x11)) {  // L1 = UDP & L2 = UDP or TCP
		if((flow_data->fourTuple.ueIP != pectHeader->fourTuple.ueIP) || 
				(flow_data->fourTuple.serverIP != pectHeader->fourTuple.serverIP) || 
				(flow_data->fourTuple.uePort != pectHeader->fourTuple.uePort) || 
				(flow_data->fourTuple.serverPort != pectHeader->fourTuple.serverPort) || 		   
				(flow_data->fourTuple.ueIP == 0) || 
				(flow_data->fourTuple.serverIP == 0) || 
				(flow_data->fourTuple.uePort == 0) || 
				(flow_data->fourTuple.serverPort == 0)
				) {
				LOG4CXX_TRACE(loggerFlowIntegrity, "FLOW INTEGRITY CHECK: GTP PACKET: RAW PACKET"); 
				helper_print_packet_details_to_log(&(pectHeader->pcapHeader), packet, pectHeader, 1,msgOut);
				snprintf(tmp, MINI_BUF_SIZE-1, "(flow_data) UE IP = 0x%x (%u)\n", flow_data->fourTuple.ueIP, flow_data->fourTuple.ueIP);
				strcat(msgOut,tmp);


				snprintf(tmp, MINI_BUF_SIZE-1, "(flow_data) UE PORT = 0x%x (%u)\n", flow_data->fourTuple.uePort, flow_data->fourTuple.uePort);
				strcat(msgOut,tmp);

				snprintf(tmp, MINI_BUF_SIZE-1, "(flow_data) SERVER IP = 0x%x (%u)\n", flow_data->fourTuple.serverIP, flow_data->fourTuple.serverIP);
				strcat(msgOut,tmp);

				snprintf(tmp, MINI_BUF_SIZE-1, "(flow_data) SERVER PORT = 0x%x (%u)\n", flow_data->fourTuple.serverPort, flow_data->fourTuple.serverPort);
				strcat(msgOut,tmp);
				
				int BUF_SIZE=300;
				char ueBUF[BUF_SIZE];
				snprintf(ueBUF,BUF_SIZE -1, "| IPQ flow | No Value Set");
				ueBUF[BUF_SIZE -1] = '\0';
					
				uint32_t ueip_network = htonl(flow_data->hashKey);
				struct ipoque_unique_flow_struct *unique_flow = NULL;
				printHashFiveTuple(cd, ueip_network,(const char *) "IPQ flow", ueBUF, BUF_SIZE, flow, unique_flow);
				ueBUF[BUF_SIZE -1] = '\0';
				strcat(msgOut,ueBUF);
				LOG4CXX_TRACE(loggerFlowIntegrity, msgOut);
		}
	}

}





void test_flowID_intergity(classify_data cd, struct iphdr *iph_L1, u16 theSize, flow_data *flow_data, const struct PectPacketHeader *pectHeader,  u8 *new_flow, struct ipoque_flow_struct *flow) {
	
	if(*new_flow == 0) {
		// check established flows only
		if (flow_data->packetsUp < 5) return;
		if (flow_data->packetsDown < 5) return;
		const struct iphdr *iph_L2 = pectHeader->userPacketIPHeader;

		
	    // NOTE : iph_L1->protocol == 01 = ICMP & iph_L1->protocol == 47 = GRE Generic Routing Encapsulation + No PORT Numbers 
	    if(((iph_L2->protocol == 0x06) || (iph_L2->protocol ==0x11)) && (iph_L1->protocol == 0x11)) {  // L1 = UDP & L2 = UDP or TCP

			int BUF_SIZE=300;
			char ueBUF[BUF_SIZE];
			snprintf(ueBUF,BUF_SIZE -1, "| IPQ flow | No Value Set");
			ueBUF[BUF_SIZE -1] = '\0';
				
		    uint32_t ueip_network = htonl(flow_data->hashKey);
		    struct ipoque_unique_flow_struct *unique_flow = NULL;
			printHashFiveTuple(cd, ueip_network,(const char *) "IPQ flow", ueBUF, BUF_SIZE, flow, unique_flow);
			char applicationBuf[MAX_APPLICATION_STRING_LENGTH];
			getApplicationValueAsString(flow_data->application, applicationBuf);
			char sub_protocol_strBuf[MAX_SUB_PROTOCOL_STRING_LENGTH];
			getSubProtocolValueAsString(flow_data->sub_protocol, flow_data->sub_protocol_str, sub_protocol_strBuf);
			char protocolBuf[MAX_IPOQUE_PROTOCOL_STRING_LENGTH];
			getProtocolValueAsString(flow_data->protocol, protocolBuf);
			char protocolGroupBuf[MAX_IPOQUE_GROUP_STRING_LENGTH];
			getProtocolGroupValueAsString(flow_data->group, protocolGroupBuf);  
			
			char msg[150];
			uint16_t printMessage=0;
			if (unique_flow != NULL) {
				if ((ntohs(unique_flow->lower_port) == 2152) &&  (ntohs(unique_flow->upper_port) == 2152)) {
					snprintf(msg, sizeof(msg), "FLOW INTEGRITY CHECK: test_flowID_intergity(): IPOQUE FLOW ID (Ports) IS 2152 for BOTH upper and lower ports");
					printMessage=1;
				}
			}
			if((flow_data->fourTuple.ueIP == 0) || (flow_data->fourTuple.serverIP == 0) || (flow_data->fourTuple.uePort == 0) || (flow_data->fourTuple.serverPort == 0)) {
				snprintf(msg, sizeof(msg), "FLOW INTEGRITY CHECK: test_flowID_intergity(): FLOW ID (four tuple) IS ZERO");
				printMessage=1;
			}
			else if((flow_data->fourTuple.ueIP != pectHeader->fourTuple.ueIP) || 
			   (flow_data->fourTuple.serverIP != pectHeader->fourTuple.serverIP) || 
			   (flow_data->fourTuple.uePort != pectHeader->fourTuple.uePort) || 
			   (flow_data->fourTuple.serverPort != pectHeader->fourTuple.serverPort)) {
				snprintf(msg, sizeof(msg), "FLOW INTEGRITY CHECK: test_flowID_intergity(): FLOW ID (four tuple) IS NOT EQUAL TO PECT (four tuple) ID");
				printMessage=1;	
			}
			else {
				printMessage=0;	
			}
			if(printMessage) {
					LOG4CXX_DEBUG(loggerFlowIntegrity, msg
					  << "| " <<  (int) *new_flow
					  << "| " << flow_data->packetsUp << "/" << flow_data->packetsDown
					  << "| " << flow_data->fourTuple.ueIP   << "| " << pectHeader->fourTuple.ueIP 
					  << "| " << flow_data->fourTuple.uePort   << "| " << pectHeader->fourTuple.uePort
					  << "| " << flow_data->fourTuple.serverIP   << "| " << pectHeader->fourTuple.serverIP
					  << "| " << flow_data->fourTuple.serverPort   << "| " << pectHeader->fourTuple.serverPort
					  << "| " << applicationBuf << "(" << flow_data->application << ")"
					  << "| " << protocolGroupBuf << "(" << flow_data->group << ")"
					  << "| " << sub_protocol_strBuf << "(" << flow_data->sub_protocol << ")"
					  << "| " << protocolBuf <<"(" << flow_data->protocol << ")"
					  << "| " << pectHeader->ip1_fragmented
					  << "| " << pectHeader->ip2_fragmented
					  << "| " << (int) iph_L1->protocol
					  << "| " << (int) iph_L2->protocol
					  << ueBUF
					  );
		  }		
		}
	}

}
