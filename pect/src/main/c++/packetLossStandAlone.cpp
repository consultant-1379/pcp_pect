#include <arpa/inet.h>
#include <getopt.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <iostream>
#include <list>

#include "flow.h"
#include "logger.hpp"
#include "classify.h"
#include "packetLossStandAlone.hpp"



#define APP_NAME	"PacketLoss"
#define APP_DESC	"Packet Loss Ratio"
#define APP_COPYRIGHT	"Copyright (c) 2014 Leo Fitzpatrick"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."


struct gtp_v1_hdr {
    u_int8_t flags;
    u_int8_t msgtype;
    u_int16_t length;
    u_int32_t teid;
};


using namespace std;

using std::ostream;
using std::cout;
using std::endl;

static unsigned long pkt_count = 0; /* packet counter */
time_t rop_now, rop_then;

std::list<flow_data *> flowData;
pcap_t *handle;
struct bpf_program fp;

#define SNAP_LEN 		1518
#define SIZE_ETHERNET 	14
//#define ETHER_ADDR_LEN	6
#define SIZE_UDP        8
#define SIZE_VLAN       4

struct parameters {
    char device[100];
    char input_file[200];
    char filter[200];
    char defaultFilter[200];
    char defaultPort[200];
    unsigned long filterIP;
    unsigned long printInterval;
    unsigned long ueIP;
} params;


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_app_usage(void);

void print_app_usage(void) {
    LOG4CXX_INFO(loggerPacketLoss,
                 "Usage: " << APP_NAME << "[options]\n"
                 << "\n"
                 << "Options:\n"
                 << "\t-i eth0 [Listen on interface for packets.]\n"
                 << "\t-r input_file [read pcap file for captured packet instead of interface.]\n"
                 << "\t-f \"111.222.333.444\" [IP of server acting as INTERNET in INTERNET -> UE or UE -> INTERNET tests]\n"
                 << "\t-p xx {number of seonds between print out of packet loss statistics to file writer\n"
                 << "\t-h [show app usage.]\n");
    LOG4CXX_INFO(loggerConsole,
                 "Usage: " << APP_NAME << "[options]\n"
                 << "\n"
                 << "Options:\n"
                 << "\t-i eth0 [Listen on interface for packets.]\n"
                 << "\t-r input_file [read pcap file for captured packet instead of interface.]\n"
                 << "\t-f \"111.222.333.444\" [IP of server acting as INTERNET in INTERNET -> UE or UE -> INTERNET tests]\n"
                 << "\t-p xx {number of seonds between print out of packet loss statistics to file writer\n"
                 << "\t-h [show app usage.]\n");
    return;
}


std::list<flow_data *>::iterator ifTuplePresent(PectIP4Tuple tuple) {
    std::list<flow_data *>::iterator itemIter;
    pktLossInfo *tcp_flow;

    for(itemIter = flowData.begin(); itemIter != flowData.end(); itemIter++) {
        tcp_flow = &((*itemIter)->tcpPktLossInfo);

        if(tcp_flow->fourTuple.serverIP == tuple.serverIP &&
                tcp_flow->fourTuple.ueIP == tuple.ueIP &&
                tcp_flow->fourTuple.serverPort == tuple.serverPort &&
                tcp_flow->fourTuple.uePort == tuple.uePort) {
            break;
        }
    }

    return itemIter;
}

void printPacketLossSAInfo() {
    std::list<flow_data *>::iterator itemIter;
    flow_data *fd = NULL;

    if(loggerPacketLoss->isTraceEnabled()) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: printPacketLossSAInfo: Printing Packet Loss for " << flowData.size() << " flows : See FileWriter.log");
    }
	
	int16_t matchUEIP_Found =0;
	
	if(params.ueIP > 0) {
		//for(itemIter = flowData.begin(); itemIter != flowData.end(); itemIter++) {
		itemIter = flowData.end();
		itemIter--;
		while(itemIter != flowData.begin()) {	 
			fd = (*itemIter);
			if(fd->fourTuple.ueIP == params.ueIP){
				matchUEIP_Found =1;
				break;
			}
			itemIter--;
		}
	}
	if(!matchUEIP_Found) {
		//Only need to print the last flow in the list, as this is the currently affected flow.
		itemIter = flowData.end();
		itemIter--;
		fd = (*itemIter);
	}
    if(fd != NULL) {
		printPktLossRateInfo(fd);
    }
}


void ipToDecimal(char *ip, unsigned long *base10IP) {
    unsigned long int ulipBit[4];
    std::stringstream ipDotStr;
    std::string ipSegment;
    ipDotStr << ip;
    int i = 0;

    while(std::getline(ipDotStr, ipSegment, '.')) {
        ulipBit[i++] = strtoul(ipSegment.c_str(), NULL, 0);
    }

    //LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: ipToDecimal ip segs = " << ulipBit[0] << ", " << ulipBit[1] << ", " << ulipBit[2] << ", " << ulipBit[3] );
    // Do calculations to convert IP to base 10
    ulipBit[0] *= 16777216;
    ulipBit[1] *= 65536;
    ulipBit[2] *= 256;
    //LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: ipToDecimal ip segs = " << ulipBit[0] << ", " << ulipBit[1] << ", " << ulipBit[2] << ", " << ulipBit[3] );
    *base10IP = ulipBit[0] + ulipBit[1] + ulipBit[2] + ulipBit[3];
    LOG4CXX_TRACE(loggerPacketLoss, "PACKET LOSS STAND ALONE: ipToDecimal IP = " << ip << ": Decmal IP = " << *base10IP);
}

void printNewFlowInfo(PectIP4Tuple tuple, int pkt_loss_direction) {
    struct in_addr ueIPIn;
    struct in_addr serverIPIn;
    ueIPIn.s_addr = htonl((tuple.ueIP));
    serverIPIn.s_addr = htonl((tuple.serverIP));
    char ueIPBuf[40];
    char serverIPBuf[40];
    inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
    inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);

    if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: printFlowInfo: PROCESSING FLOW : PKT_LOSS_HEADING_TO_USER_EQUIPMENT "
                     << ": ueIP:port = " << tuple.ueIP << "[" << ueIPBuf << "]" << ":" << tuple.uePort
                     << ": Server:port = " << tuple.serverIP << "[ " << serverIPBuf << "]" << ":" << tuple.serverPort);
    } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: printFlowInfo: PROCESSING FLOW : PKT_LOSS_HEADING_TO_INTERNET "
                     << ": ueIP:port = " << tuple.ueIP << "[" << ueIPBuf << "]" << ":" << tuple.uePort
                     << ": Server:port = " << tuple.serverIP << "[" << serverIPBuf << "]" << ":" << tuple.serverPort);
    }
}

void handleTCPPacket(const struct pcap_pkthdr *header, const struct tcphdr *tcp, const struct iphdr *ip) {
    int pkt_loss_direction = 0;
    uint16_t src_port, dst_port;
    u_int32_t src_ip, dst_ip;
    PectIP4Tuple tuple;
    uint32_t tcpHeaderSize, tcpPayloadSize;
    pktLossInfo *tcp_flow;
    flow_data *fd;
    tcpHeaderSize = tcp->doff;
    tcpPayloadSize = ntohs(ip->tot_len) - 20 - (tcpHeaderSize * 4);

    if(loggerPacketLoss->isTraceEnabled()) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: --------------------------------------------------------------------------------------- ");
    }

    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);
    src_ip = ntohl(ip->saddr);
    dst_ip = ntohl(ip->daddr);
    //cout << "tcpPayloadSize = " << tcpPayloadSize << ": tcpHeaderSize = " << tcpHeaderSize*4 << endl;
    struct in_addr srcIPIn;
    struct in_addr destIPIn;
    srcIPIn.s_addr = htonl((ntohl(ip->saddr)));
    destIPIn.s_addr = htonl((ntohl(ip->daddr)));
    char srcIPBuf[40];
    char dstIPBuf[40];
    inet_ntop(AF_INET, &srcIPIn, srcIPBuf, 40);
    inet_ntop(AF_INET, &destIPIn, dstIPBuf, 40);

    if(loggerPacketLoss->isTraceEnabled())
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: DETERMINE FLOW DIRECTION "
                     << ": src_ip = " << src_ip << "[" << srcIPBuf << "] : src_port =" << src_port
                     << ": dst_ip = " << dst_ip << "[" << dstIPBuf << "] : dst_port =" << dst_port);

    if(strcmp(params.filter, params.defaultFilter) == 0) {
        if(src_ip == 170770845) { // 10.45.193.157 atsfsx160
            pkt_loss_direction = PKT_LOSS_HEADING_TO_USER_EQUIPMENT;
        } else if(dst_ip == 170770845) {
            pkt_loss_direction = PKT_LOSS_HEADING_TO_INTERNET;
        } else {
            LOG4CXX_ERROR(loggerPacketLoss, "Error in filter expression");
            LOG4CXX_ERROR(loggerConsole, "Error in filter expression");
            return;
        }
    } else {
        if(src_ip == params.filterIP) {
            pkt_loss_direction = PKT_LOSS_HEADING_TO_USER_EQUIPMENT;
        } else if(dst_ip == params.filterIP) {
            pkt_loss_direction = PKT_LOSS_HEADING_TO_INTERNET;
        } else {
            LOG4CXX_ERROR(loggerPacketLoss, "Error in SPECIFIED filter expression");
            LOG4CXX_ERROR(loggerConsole, "Error in SPECIFIED filter expression");
            return;
        }
    }

    if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        tuple.serverIP = src_ip;
        tuple.ueIP = dst_ip;
        tuple.serverPort = src_port;
        tuple.uePort = dst_port;
    } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
        tuple.serverIP = dst_ip;
        tuple.ueIP = src_ip;
        tuple.serverPort = dst_port;
        tuple.uePort = src_port;
    } else {
        LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: UNABLE TO PROCESS FLOW : UNKNOWN DIRECTION"
                     << ": SRC IP:port = " << src_ip << ":" << src_port
                     << ": DEST:port = " << dst_ip << ":" << dst_port);
        return;
    }

    if(loggerPacketLoss->isTraceEnabled()) {
        if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: PROCESSING FLOW : PKT_LOSS_HEADING_TO_USER_EQUIPMENT "
                         << ": ueIP:port = " << tuple.ueIP << ":" << tuple.uePort
                         << ": Server:port = " << tuple.serverIP << ":" << tuple.serverPort
                         << ": tcpPayloadSize = " << tcpPayloadSize << ": tcpHeaderSize = " << tcpHeaderSize*4 
                         );
        } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: PROCESSING FLOW : PKT_LOSS_HEADING_TO_INTERNET "
                         << ": ueIP:port = " << tuple.ueIP << ":" << tuple.uePort
                         << ": Server:port = " << tuple.serverIP << ":" << tuple.serverPort
                         << ": tcpPayloadSize = " << tcpPayloadSize << ": tcpHeaderSize = " << tcpHeaderSize*4 
                         );
        } else {
            LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: UNABLE TO PROCESS FLOW : UNKNOWN DIRECTION"
                         << ": SRC IP:port = " << src_ip << ":" << src_port
                         << ": DEST:port = " << dst_ip << ":" << dst_port);
            return;
        }
    }

    std::list<flow_data *>::iterator itemIter = ifTuplePresent(tuple);
    unsigned long long packetTime_uS = ((unsigned long long) header->ts.tv_sec) * PKTLOSS_RESOLUTION  + (unsigned long long)header->ts.tv_usec;

    if(itemIter == flowData.end()) {
		// new flow; print stats for previous flow first
		// START: PRINT LAST FLOW SECTION
		if(flowData.size() > 0) {
			itemIter = flowData.end();
			itemIter--;
			flow_data *previous_fd; 
			previous_fd = (*itemIter);
			printPktLossRateInfo(previous_fd);
			LOG4CXX_INFO(loggerFileWriter, "PACKET LOSS: printPktLossRateInfo : LAST PACKET flow data size = " << flowData.size());
		}
        // END: PRINT LAST FLOW SECTION
        
        // not found	// handle new flow
        fd = new flow_data();
        flowData.push_back(fd);
        tcp_flow = &(fd->tcpPktLossInfo);
        initCounters(tcp_flow);
        tcp_flow->fourTuple = tuple;
        fd->fourTuple = tuple;
        printNewFlowInfo(tuple, pkt_loss_direction);
        tcp_flow->queueNumber = (int16_t) fd->queueNumber; //always Zero for this Standalone version
        fd->isTcpFlow = true;
        pktLossInitialiseMaps(fd, tuple);
        handleNewFlow(tcp, tcpPayloadSize, pkt_loss_direction, tcp_flow, &(packetTime_uS));

        if(loggerPacketLoss->isTraceEnabled())
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: NEW FLOW "
                         << ": ueIP: port " << tcp_flow->fourTuple.ueIP << ": " << tcp_flow->fourTuple.uePort
                         << ": Server: port " << tcp_flow->fourTuple.serverIP << ": " << tcp_flow->fourTuple.serverPort);
    } else {
        // found
        // handle old flow
        fd = (*itemIter);
        tcp_flow = &(fd->tcpPktLossInfo);

        // handle traffic PKT_LOSS_HEADING_TO_USER_EQUIPMENT direction
        if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
            if(tcp_flow->resetPerRop) {
                resetPerROPCounters(tcp_flow);
                tcp_flow->fourTuple = tuple;
                tcp_flow->queueNumber = (int16_t) fd->queueNumber;
                tcp_flow->resetPerRop = 0;
            }

            handleTCPPacketHeadingToUE(tcp, tcpPayloadSize, tcp_flow, &(packetTime_uS));
            // handle traffic PKT_LOSS_HEADING_TO_INTERNET direction
        } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
            if(tcp_flow->resetPerRop) {
                resetPerROPCounters(tcp_flow);
                tcp_flow->fourTuple = tuple;
                tcp_flow->queueNumber = (int16_t) fd->queueNumber;
                tcp_flow->resetPerRop = 0;
            }

            handleTCPPacketHeadingToInternet(tcp, tcpPayloadSize, tcp_flow, &(packetTime_uS));
        }

        if(loggerPacketLoss->isTraceEnabled())
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: EXISTING FLOW "
                         << ": ueIP: port " << tcp_flow->fourTuple.ueIP << ": " << tcp_flow->fourTuple.uePort
                         << ": Server: port " << tcp_flow->fourTuple.serverIP << ": " << tcp_flow->fourTuple.serverPort);
    }

    // Packet Loss Rate is multiplied by PKTLOSS_RATE_RESOLUTION to keep from having to operate in floats

    if(tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
        //fd->internetToUeLossRate = ((tcp_flow->retxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
        uint32_t uniqueReTx_count = tcp_flow->retxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - (tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
        tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = pktLossCheckDataIntegrity(tcp_flow, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
        if(tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] ) {
			fd->internetToUeLossRate = (uniqueReTx_count * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
		}
    }

    if(tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET]) {
        // fd->ueToInternetLossRate = ((tcp_flow->retxCount[PKT_LOSS_HEADING_TO_INTERNET] - tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_INTERNET]) * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET];
        uint32_t uniqueReTx_count = tcp_flow->retxCount[PKT_LOSS_HEADING_TO_INTERNET] - (tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_INTERNET] + tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_INTERNET]);
        tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET] = pktLossCheckDataIntegrity(tcp_flow, PKT_LOSS_HEADING_TO_INTERNET);
        if(tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET] ) {
			fd->internetToUeLossRate = (uniqueReTx_count * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET];
		}
    }

    //print results every minute
    time(&rop_then);

    if(loggerPacketLoss->isTraceEnabled()) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: rop_then = " << rop_then << ": rop_now = " << rop_now << ": diff = " <<  difftime(rop_then, rop_now));
    }

    if((difftime(rop_then, rop_now) + 1) > params.printInterval) {
        rop_now = rop_then;
        printPacketLossSAInfo();
    }

    if(loggerPacketLoss->isTraceEnabled()) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: handleTCPPacket: --------------------------------------------------------------------------------------- ");
    }
}
void cleanupPacketLossStandAlone() {
    flow_data *fd;
    LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Closing Pcap.");
    LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Closing Pcap.");
    pcap_breakloop(handle);
    sleep(5);
    pcap_freecode(&fp);
    pcap_close(handle);
    sleep(5);
    LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: cleanupPacketLossStandAlone: Flow List Size Before Cleanup " <<  flowData.size());
    size_t length = flowData.size();

    // Erase the contents of the hashmap via a deep deallocation of memory.
    for(size_t i = 0; i < length; ++i) {
        std::list<flow_data *>::iterator itemIter = flowData.begin();

        if(itemIter != flowData.end()) {
            fd = (*itemIter);

            if(fd->isTcpFlow == true) {
                pktLossCleanupMaps(fd); // FREE does not call destructors
            }

            delete fd;
            flowData.erase(itemIter);
        }
    }

    LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: cleanupPacketLossStandAlone: Flow List Size After Cleanup " <<  flowData.size());
    flowData.clear();
    LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: All Done.\n ");
    LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: All DOne.\n");
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ethhdr *ethernet;
    const struct iphdr *ip1, *ip2;
    const struct udphdr *udp;
    const struct tcphdr *tcp;
    const struct gtp_v1_hdr *gtp;
    int size_ip;
    int size_tcp;
    int len = 0;
    int isGtpuSeqPresent = 0;
    uint16_t src_port1, dst_port1;
    int version, type;
    pkt_count++;
    ethernet = (struct ethhdr *)(packet);
    type = ethernet->h_proto;

    if(type == htons(ETH_P_8021Q)) {
        ip1 = (struct iphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN);
    } else {
        ip1 = (struct iphdr *)(packet + SIZE_ETHERNET);
    }

    version = ip1->version;

    if(version == 6) {
        return;
    }

    size_ip = ip1->ihl * 4;

    if(size_ip < 20) {
        LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet: Invalid IP header length (Ethernet): " <<  size_ip << " bytes, packet: " << pkt_count);
        return;
    }

    if(ip1->protocol == IPPROTO_UDP) {
        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet: PROCESSING UDP PACKET");
        }

        udp = (struct udphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip);
        src_port1 = ntohs(udp->source);
        dst_port1 = ntohs(udp->dest);

        if(src_port1 == 2152 || dst_port1 == 2152) {
            gtp = (struct gtp_v1_hdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip + SIZE_UDP);
            len = ntohs(gtp->length);
            isGtpuSeqPresent = (gtp->flags >> 1) & 1;

            if(isGtpuSeqPresent) {
                ip2 = (struct iphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip + SIZE_UDP + 12);
            } else {
                ip2 = (struct iphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip + SIZE_UDP + 8);
            }

            size_ip = ip2->ihl * 4;

            if(size_ip < 20) {
                LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet:Invalid IP header length (UDP->GTP) : " <<  size_ip << " bytes, packet: " << pkt_count);
                return;
            }

            if(ip2->protocol == IPPROTO_TCP) {
                /* define/compute tcp header offset */
                if(isGtpuSeqPresent) {
                    tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip + SIZE_UDP + 12 + size_ip);
                } else {
                    tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip + SIZE_UDP + 8 + size_ip);
                }

                size_tcp = tcp->doff * 4;

                if(size_tcp < 20) {
                    LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet:Invalid IP header length (UDP->GTP->TCP) : " <<  size_tcp << " bytes, packet: " << pkt_count)
                    return;
                }

                handleTCPPacket(header, tcp, ip2);
            }
        }
    } else if(ip1->protocol == IPPROTO_TCP) {
        /* define/compute tcp header offset */
        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet: PROCESSING TCP PACKET");
        }

        if(type == htons(ETH_P_8021Q)) {
            tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + SIZE_VLAN + size_ip);
        } else {
            tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + size_ip);
        }

        size_tcp = tcp->doff * 4;

        if(size_tcp < 20) {
            LOG4CXX_WARN(loggerPacketLoss, "PACKET LOSS STAND ALONE: got_packet:Invalid IP header length (TCP Protocol) : " <<  size_tcp << " bytes, packet: " << pkt_count);
            return;
        }

        handleTCPPacket(header, tcp, ip1);
    }

    return;
}

int testPacketLoss(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 net;
    LOG4CXX_INFO(loggerBroadcast, "Packet Capture PreProcessor STAND ALONE - " << pcp_version);
    string testInstr(" \n \
      TEST SETUP: DOWNLINK INET --> UE \n \
      SERVER A --> BRIDGE Laptop --> Ericsson Corporate Network --> SERVER B \n \
      Linux Laptop (eth0) --> (eth3) Nmlab Laptop (eth0) -->  Ericsson Corporate Network --> (eth0) atsfsx141 \n \
      SERVER A = INET ( => PCP STARTED WITH CMD \"./pcp-pect-packet-loss -testPacketLoss -i eth0 -f \"<IP address of SERVER A>\" -p 10\") \n \
      SERVER B = UE \n \
      \n \
      TEST SETUP: UPLINK UE --> INET \n \
      SERVER A --> BRIDGE Laptop --> Ericsson Corporate Network --> SERVER B \n \
      Linux Laptop (eth0) --> (eth3) Nmlab Laptop (eth0) -->  Ericsson Corporate Network --> (eth0) atsfsx141 \n \
      SERVER A = UE \n \
      SERVER B = INET (PCP STARTED WITH CMD \"./pcp-pect-packet-loss -testPacketLoss -i eth0 -f \"<IP address of SERVER B>\" -p 10\") \n \
      \n \
      TEST INSTRUCTIONS: \n \
      1: Start PCP application on the Server B, specify IP of INET SERVER (different for UL and DL) for the -f option \n \
         \"./pcp-pect-packet-loss -testPacketLoss -i eth0 -f <INET Server IP) -u <UE Server IP) -p 10\" \n \
         \n \
      2: Copy a LARGE file [1GB] from the Server A  to the Server B using command:\n \
         \"SCP -4 -P 22 <local = Server A > <remote = Server B> \" \n \
         \n \
      3: Add in  the desired LOSS on \"BRIDGE LAPTOP\"  to eth0 \n \
          \n \
          \"tc qdisc <add | change> dev eth0 root netem loss <LOSS>\" \n \
          \n \
      3: View output in filewriter.log using command:\n \
         \"tail -f file_writer.log |grep \"PACKET LOSS\" \n \
         \n \
      4: Press ENTER To Continue\n  \0");
    initSignalHandler();
    //strcpy(params.defaultFilter,"((src net 10.45.193.157) and (src port 22)) or ((dst net 10.45.193.157) and (dst port 22))\0");
    // scp from atsfsx160 on any port to atsfsx141 on port 22
    strcpy(params.defaultFilter, "((net 10.45.193.157) and (port 22))\0");
    strcpy(params.defaultPort, "(port 22))\0");
    params.printInterval = 60;
    params.ueIP=0;
    
    while(1) {
        static struct option long_options[] = {
            {"interface", required_argument, 0, 'i'},
            {"input_file", required_argument, 0, 'r'},
            {"filter", required_argument, 0, 'f'},
            {"ueip", optional_argument, 0, 'u'},
            {"printInterval", required_argument, 0, 'p'},
            {"help",   required_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        long c = getopt_long(argc, argv, "testPacketLoss:i:r:f:u:p:h",
                             long_options, &option_index);

        if(c == -1) {
            break;
        }

        switch(c) {
            case 'i':
                strcpy(params.device, optarg);
                break;

            case 'r':
                strcpy(params.input_file, optarg);
                break;

            case 'p':
                params.printInterval = strtoul(optarg, NULL, 0);
                break;

            case 'f':
                char ip_str[200];
                strcpy(ip_str, optarg);
                snprintf(ip_str, sizeof(ip_str), "%s", optarg);
                ipToDecimal(ip_str, &params.filterIP);
                snprintf(params.filter, sizeof(params.filter), "((net %s) and (port 22))", optarg);
                break;
            
            case 'u':
                char ueip_str[200];
                strcpy(ueip_str, optarg);
                snprintf(ueip_str, sizeof(ueip_str), "%s", optarg);
                ipToDecimal(ueip_str, &params.ueIP);
                cout << "UEIP ip_str = " << ueip_str << ": params.ueip = " << params.ueIP << endl;
                //snprintf(params.ueip, sizeof(params.filter), "((net %s) and (port 22))", optarg);
                break;

            case 'h':
                print_app_usage();
                exit(EXIT_FAILURE);
                break;

            default:
                break;
        }
    }

    if(strcmp(params.input_file, "") != 0 && strcmp(params.device, "") != 0) {
        LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Device and input file, both cannot be specified at the same time");
        LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Device and input file, both cannot be specified at the same time");
        print_app_usage();
        exit(EXIT_FAILURE);
    }

    if(strcmp(params.device, "") != 0) {
        LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: Capturing on device " << params.device << testInstr);
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: Device: " << params.device);
        getchar();
    } else if(strcmp(params.input_file, "") != 0) {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Input File: " << params.input_file);
        LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Input File: " << params.input_file);
    } else {
        LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Device or file name needed ");
        LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Device or file name needed");
        print_app_usage();
        exit(EXIT_FAILURE);
    }

    if(strcmp(params.filter, "") == 0) {
        strcpy(params.filter, params.defaultFilter);
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Using Default Filter expresion:  " << params.filter);
        LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Using Default Filter expresion: " << params.filter);
    } else {
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Using Specified Filter expresion:  " << params.filter);
        LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Using Specified Filter expresion: " << params.filter);
    }

    LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Print Interval = " << params.printInterval);
    LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Print Interval = " << params.printInterval);

    if(strcmp(params.device, "") != 0) {
        /* get network number and mask associated with capture device */
        if(pcap_lookupnet(params.device, &net, &mask, errbuf) == -1) {
            LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't get netmask for device :  " << params.device << ": ERROR MESSAGE = " << errbuf);
            LOG4CXX_INFO(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't get netmask for device :  " << params.device << ": ERROR MESSAGE = " << errbuf);
            net = 0;
            mask = 0;
        }

        /* open capture device */
        handle = pcap_open_live(params.device, SNAP_LEN, 1, 1000, errbuf);

        if(handle == NULL) {
            LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't open device device :  " << params.device << ": ERROR MESSAGE = " << errbuf);
            LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't open device device :  " << params.device << ": ERROR MESSAGE = " << errbuf);
            exit(EXIT_FAILURE);
        }

        /* make sure we're capturing on an Ethernet device [2] */
        if(pcap_datalink(handle) != DLT_EN10MB) {
            LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: " << params.device << " is not an Ethernet device " << errbuf);
            LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss:  " << params.device << " is not an Ethernet device" << errbuf);
            exit(EXIT_FAILURE);
        }
    } else if(strcmp(params.input_file, "") != 0) {
        // open capture file for offline processing
        handle = pcap_open_offline(params.input_file, errbuf);

        if(handle == NULL) {
            LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't open file :  " << params.input_file  << ": ERROR MESSAGE = " << errbuf);
            LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't open file : " << params.input_file  << ": ERROR MESSAGE = " << errbuf);
            exit(EXIT_FAILURE);
        }
    } else {
        LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: No input device found ");
        LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: No input device found ");
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if(pcap_compile(handle, &fp, params.filter, 0, net) == -1) {
        LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss: Using Default Filter expresion:  " << params.filter << ": ERROR MESSAGE = " << pcap_geterr(handle));
        LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Using Default Filter expresion: " << params.filter << ": ERROR MESSAGE = " << pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if(pcap_setfilter(handle, &fp) == -1) {
        LOG4CXX_ERROR(loggerPacketLoss, "PACKET LOSS STAND ALONE: testPacketLoss:Couldn't install filter:  " << params.filter << ": ERROR MESSAGE = " << pcap_geterr(handle));
        LOG4CXX_ERROR(loggerConsole, "PACKET LOSS STAND ALONE: testPacketLoss: Couldn't install filter : " << params.filter << ": ERROR MESSAGE = " << pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    printPktLossRateInfo_Header();
    time(&rop_now);
    /* now we can set our callback function */
    pcap_loop(handle, -1, got_packet, NULL);
    /* cleanup */
    cleanupPacketLossStandAlone();
    LOG4CXX_INFO(loggerPacketLoss, "\nPACKET LOSS STAND ALONE: testPacketLoss: Capture complete.\n ");
    LOG4CXX_INFO(loggerConsole, "\nPACKET LOSS STAND ALONE: testPacketLoss: Capture complete.\n");
    return 0;
}
