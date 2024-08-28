/************************************************************************
 * COPYRIGHT (C) Ericsson 2012                                           *
 * The copyright to the computer program(s) herein is the property       *
 * of Telefonaktiebolaget LM Ericsson.                                   *
 * The program(s) may be used and/or copied only with the written        *
 * permission from Telefonaktiebolaget LM Ericsson or in accordance with *
 * the terms and conditions stipulated in the agreement/contract         *
 * under which the program(s) have been supplied.                        *
 *************************************************************************
 *************************************************************************
 * File: pcpglue.c
 * Date: December 7, 2012
 * Author: LMI/LXR/PE Simon Richardson
 ************************************************************************/

/**********************************************************************
 * This code reads a packet from either a file or a live interface,
 * then writes that packet to a list of output files.  The output
 * files need only exist in the filesystem: they could be files,
 * devices or pipes.
 *
 * An option exists to un-tunnel the packets by removing the GTP
 * header from the packet.
 **********************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <sstream>
#include <sys/prctl.h>
#include <iostream>

// ip stuff for the gtpv1 header find function
#include <iomanip>
#include <locale>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "config.h"
#include "gtpv1_utils.h"
#include "gtp_ie_gtpv2.h"
#include "logger.hpp"
#include "pcpglue.hpp"
#include "packet_utils.h"
#include "flow.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define SNAPLEN	      65536
#define ONE_THOUSAND  1000
#define ONE_MILLION   1000000
#define LOG_PRECISION 2


using std::cout;
using std::endl;
using std::setprecision;
using std::hex;
using std::ios;

static char errbuf[PCAP_ERRBUF_SIZE];
packetbuffer packet_pool[MAX_NUM_OF_PACKET_BUFFERS];

extern int waitForFileWriter;
extern EArgs evaluatedArguments;
extern pthread_mutex_t flowCountersMutex;
extern pthread_mutex_t packetLossMutex;

extern HashTableStatisticsStruct hashTableCtrs;
extern HashTableTimeoutClassStruct hashTimeoutClass;
extern packetLossStatisticsStruct pktLossCtrs;
extern cdpTimers cdpAdvertsTimer, cdpMapsTimer, cdpNewsTimer, cdpPhotoTimer, cdpSWuTimer, cdpSpeedTimer, cdpWeatherTimer, cdpLlmnrTimer, cdpSimpleHostTimer[8];
extern int cdpTimersEnabled;
extern const char *CDP_SIMPLE_HOST[];
extern int MAX_SIMPLE_HOSTS;

using namespace log4cxx;

/**
 * This Function takes the packet from the assigned interface and extracts the IP and direction of the packet
 * As the packet is of size 1600 bytes we have room on the end for the IP address we have un-tunnelled.
 * this is placed at the caplen + 1 of the packet
 */
void source_next_packet(u_char *config_source_ptr, const struct pcap_pkthdr *h, const u_char *bytes) {
    packet_source input = (packet_source) config_source_ptr;
    int pool_packet = 0, queue;
    struct PectPacketHeader *pectHeader;
    u_char *packet;
    unsigned long destinationMACAddress = readByteArray((unsigned char *) bytes, 6, 0); //destination address comes first !!
    unsigned long sourceMACAddress = readByteArray((unsigned char *) bytes, 6, 6);

    //queue is not  the number of threads started. It is the number of threads usesing each packet buffer. when UseMultplePacketBuffer==ture then queue=1
    do {
        if(!(packet_pool[input->packetBufferNum]->droppedPacketCount)) {
            pool_packet = packetbuffer_grab_free(packet_pool[input->packetBufferNum]);
        }

        int dropPacket = checkIfPacketBufferBlocked(packet_pool[input->packetBufferNum], input->packetBufferNum, pool_packet);

        if(dropPacket) {
            return;
        }
    } while(pool_packet <= 0); //packet_pool can not be zero. packet_pool will be zero if checkIfPacketBufferBlocked FREES the blockage and returns dropPacket=0.

    if(!input->pbFull && packet_pool[input->packetBufferNum]->freePacketCount < 10) {
        LOG4CXX_DEBUG(loggerPcpGlue, "source_next_packet: PacketBuffer " << input->packetBufferNum << "filled (<10 packets free)");
        input->pbFull = true;
    } else if(input->pbFull && packet_pool[input->packetBufferNum]->freePacketCount > 1000) {
        LOG4CXX_DEBUG(loggerPcpGlue, "source_next_packet: PacketBuffer " << input->packetBufferNum << "recovered (>1000 packets free)");
        input->pbFull = false;
    }

    pectHeader = packetbuffer_header(packet_pool[input->packetBufferNum], pool_packet);
    packet = (u_char *) packetbuffer_data(packet_pool[input->packetBufferNum], pool_packet);
    memcpy(&pectHeader->pcapHeader, h, sizeof(struct pcap_pkthdr));

    if(pectHeader->pcapHeader.caplen > PACKET_MAX_BYTES) {
        pectHeader->pcapHeader.caplen = PACKET_MAX_BYTES;
        input->truncated++;
    }

    memcpy(packet, bytes, pectHeader->pcapHeader.caplen);
    //un-tunnel the packet and find the UE IP address
    pectHeader->packetDirection = NOT_YET_DEFINED;
    pectHeader->packetTime_uS = ((unsigned long long) h->ts.tv_sec) * PKTLOSS_RESOLUTION  + (unsigned long long)h->ts.tv_usec;
    
    // ENSURE that layer 1 &/ 2 details set in get_ip_header
    pectHeader->userPacketIPHeader = NULL;
	pectHeader->userHeaderSize=0;
	pectHeader->userTotalLength=0;
	pectHeader->ip1_fragmented = 0;
	pectHeader->ip2_fragmented = 0;
	pectHeader->ip2_fragmented_dropped = 0;
	pectHeader->udp1_srcPort = 0;
    pectHeader->udp1_dstPort = 0;
	
	
    int retVal = get_ip_header(pectHeader, bytes);
    // counters for fragmentation
    hashTableCtrs.totalNumPackets_source[input->packetBufferNum]++;
    // Dropping all L1 fragments
    if(pectHeader->ip1_fragmented) {
		hashTableCtrs.numPacketsFragmented_L1_source[input->packetBufferNum]++;
	}
	// Keeping L2 fragment 0 and dropping remainder.
	if(pectHeader->ip2_fragmented_dropped) {
		hashTableCtrs.numPacketsFragmented_L2_source[input->packetBufferNum]++;
	}
	
	if(retVal) {
		LOG4CXX_TRACE(loggerPcpGlue,"GTP-U PACKET Invalid: source_next_packet(): Packet is Fragmented/ non UDP /Non GTP / Small packet/ Non Ethernet.  It will be Dropped.");
        packetbuffer_release(packet_pool[input->packetBufferNum], pool_packet);
        return;
    }
    
    if((pectHeader->userPacketIPHeader == NULL)) {
		LOG4CXX_WARN(loggerPcpGlue,"GTP-U PACKET Invalid: source_next_packet(): No Layer 2 Information in packet (pectHeader->userPacketIPHeader == NULL).  It will be Dropped.");
        packetbuffer_release(packet_pool[input->packetBufferNum], pool_packet);
        return;
    }
    
    int retVal2 = parseLayer3Info(pectHeader->userPacketIPHeader, sourceMACAddress, destinationMACAddress, pectHeader);
    // retVal == 2 is a parseLayer4Info Error
    if(retVal2==2) {
        LOG4CXX_TRACE(loggerPcpGlue, "GTP-U PACKET : source_next_packet(): Unable to parse layer 4 info.  ");
        packetbuffer_release(packet_pool[input->packetBufferNum], pool_packet);
        return;
    }
    
    if(retVal2==1) {
        LOG4CXX_WARN(loggerPcpGlue, "GTP-U PACKET : source_next_packet(): No MAC: source_next_packet():Unable to retrieve the UEIP from packet, Source MAC: 0x" << std::hex << sourceMACAddress
						 << " Destination MAC: 0x" << std::hex << destinationMACAddress << ".");
        packetbuffer_release(packet_pool[input->packetBufferNum], pool_packet);
        return;
    }
	
	// ENABLE THIS ONLY IF NEEDED: helper_print_packet_details_to_log(&(pectHeader->pcapHeader), packet, pectHeader, 1, NULL);
	
    pthread_mutex_lock(&(input->mutex));
    input->bytes += h->caplen;
    input->packets++;
    pthread_mutex_unlock(&(input->mutex));

    //char ip;
    if(!input->queue) {
        queue = (ntohl(pectHeader->fourTuple.ueIP) & (config_sink_count - 1)) + 1;
    } else {
        queue = input->queue;
    }

    packetbuffer_queue(packet_pool[input->packetBufferNum], queue, pool_packet);
    packetbuffer_release(packet_pool[input->packetBufferNum], pool_packet);
}

void source_cleanup(void *init) {
    if(init == NULL) {
        return;
    }

    packet_source source = (packet_source) init;
    pcap_breakloop(source->input);
    sleep(5); // pcap loop can read at least one more packet after a pcap breakloop is issued;
    pcap_close(source->input);
    LOG4CXX_INFO(loggerPcpGlue, "stopping source: " << source->packetBufferNum);
}

void *source_main(void *init) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    packet_source source;
    source = (packet_source) init;
    stringstream s;
    s << "pectSourc_" << source->queue << "_" << source->packetBufferNum;
    prctl(PR_SET_NAME, s.str().c_str(), 0, 0, 0);
    pthread_cleanup_push(source_cleanup, init);
    int result = pcap_loop(source->input, -1, &source_next_packet, (u_char *) source);

    if(result == -2) {
        LOG4CXX_INFO(loggerPcpGlue, "GTP-U: source_main:  Stop reading from the buffer. Stopped by breakloop.");
    }

    if(result == -1) {
        LOG4CXX_ERROR(loggerPcpGlue, "Problem buffering " << source->source_name << ": " << pcap_geterr(source->input) << ".");
    }

    pthread_cleanup_pop(1);
    LOG4CXX_INFO(loggerPcpGlue, "source " << source->input << " has stopped.");
    return (0);
}

void sink_cleanup(void *init) {
    if(init == NULL) {
        LOG4CXX_ERROR(loggerPcpGlue, "Failed to close closing one of the sink threads (\'init\' was NULL");
        return;
    }

    packet_sink sink = (packet_sink) init;
    LOG4CXX_INFO(loggerPcpGlue, "closing sink " << sink->packetBufferNum);
    classify_end(sink->cd, sink->packetBufferNum);
}

void *sink_main(void *init) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    //efitleo: EQEV-14145: Attempt to solve problem of sink streams not closing;
    //                     calling thread start_source_sink has "cancel type" of DEFERRED; so changed this also
    //pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS , NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    packet_sink sink;
    int pool_packet;
    struct PectPacketHeader *pectHeader = NULL;
    u_char *packet;
    int index;
    sink = (packet_sink) init;
    ServiceProvider sp(sink->packetBufferNum);
    sink->cd = classify_start(sink->packetBufferNum, &sp);
    stringstream s;
    s << "pectClass_" << sink->queue << "_" << sink->packetBufferNum;
    prctl(PR_SET_NAME, s.str().c_str(), 0, 0, 0);

    if(!sink->cd) {
        LOG4CXX_FATAL(loggerPcpGlue, "Unable to start the classification engine for queue " << sink->queue << ": Packet Buffer " << sink->packetBufferNum << ".");
        exit(255);
    }

    if(evaluatedArguments.useMultiplePacketBuffers) {
        index =  sink->packetBufferNum;
    } else {
        index = sink->queue;
    }

    int retryCounter = 0;
    pthread_cleanup_push(sink_cleanup, init);

    while(1) {   // never return
        retryCounter = 0;

        do {
            pool_packet = packetbuffer_grab_next(packet_pool[sink->packetBufferNum], sink->queue, 1);
            retryCounter++;

            if(retryCounter > 100) {
                usleep(retryCounter * 7000);
            }
        } while(pool_packet < 0);

        pectHeader = packetbuffer_header(packet_pool[sink->packetBufferNum], pool_packet);
        packet = (u_char *) packetbuffer_data(packet_pool[sink->packetBufferNum], pool_packet);
        classify(sink->cd, index, pectHeader, packet, &sp);
        pthread_mutex_lock(&sink->mutex);
        sink->packets++;
        sink->bytes += (pectHeader->pcapHeader).len;
        pthread_mutex_unlock(&sink->mutex);
        packetbuffer_release(packet_pool[sink->packetBufferNum], pool_packet);
    }

    pthread_cleanup_pop(1);
    return (0);
}

int sink_start(void) {
    // open the sink output threads
    for(int i = 0; i < config_sink_count; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_mutex_init(&flowCountersMutex, 0);
        pthread_mutex_init(&packetLossMutex, 0);
        pthread_mutex_init(&(config_sink_array[i].mutex), 0);
        pthread_create(&(config_sink_array[i].thread), &attr, sink_main, &(config_sink_array[i]));
        pthread_attr_destroy(&attr);
    }

    return (0);
}

int source_start(void) {
    for(int i = 0; i < config_source_count; i++) {
        pthread_attr_t attr;
        pthread_attr_init(&attr);

        if(config_source_array[i].capture_type == CAPTURE_LIVE) {
            config_source_array[i].input = pcap_open_live(config_source_array[i].source_name, SNAPLEN, 0, 1000, errbuf);

            if(!config_source_array[i].input) {
                LOG4CXX_FATAL(loggerPcpGlue,
                              "Cannot open interface \"" << config_source_array[i].source_name << "\" for input: " << errbuf);
                return (1);
            }
        } else {
            config_source_array[i].input = pcap_open_offline(config_source_array[i].source_name, errbuf);

            if(!config_source_array[i].input) {
                LOG4CXX_FATAL(loggerPcpGlue,
                              "Cannot open file \"" << config_source_array[i].source_name << "\" for input: " << errbuf);
                return (1);
            }
        }

        pthread_mutex_init(&(config_source_array[i].mutex), 0);
        pthread_create(&(config_source_array[i].thread), &attr, source_main, &(config_source_array[i]));
        pthread_attr_destroy(&attr);
    }

    return (0);
}

/**
 * This function populates the inputLogBuffer with text for the log message.
 *
 * @param inputLogBuffer
 * @param timeDurationInSeconds
 */
void printInputQueueLogToBuffer(string *inputLogBuffer, int timeDurationInSeconds) {
    for(int i = 0; i < config_source_count; i++) {
        double megaBytes = 0, megaBitsPerSecond = 0;
        unsigned long packets;
        stringstream inputRecord;
        inputRecord.setf(ios::fixed, ios::floatfield);
        inputRecord.precision(LOG_PRECISION);
        inputRecord.imbue(std::locale("en_US"));
        pthread_mutex_lock(&(config_source_array[i].mutex));
        packets = config_source_array[i].packets;
        megaBytes = (double)(config_source_array[i].bytes / ONE_MILLION);
        megaBitsPerSecond = (double)((megaBytes * 8) / timeDurationInSeconds);

        // Debug prefix to log message.
        if(loggerPcpGlue->isDebugEnabled()) {
            inputRecord << "From: " << config_source_array[i].source_name
                        << " To: PB" << config_source_array[i].packetBufferNum
                        << "[" << config_source_array[i].queue << "] ";
        }

        config_source_array[i].packets = 0;
        config_source_array[i].bytes = 0;
        pthread_mutex_unlock(&(config_source_array[i].mutex));
        inputRecord << "IN[" << packets << " packets; ";

        // For determining the Byte amount to output.
        if(megaBytes >= ONE_THOUSAND) {   // Use GigaByte level values.
            double gigaBytes = megaBytes / ONE_THOUSAND;
            inputRecord << gigaBytes << " GB; ";
        } else if(megaBytes < 1) {   // Use KiloByte level values.
            double kiloBytes = megaBytes * ONE_THOUSAND;
            inputRecord << kiloBytes << " KB; ";
        } else {
            inputRecord << megaBytes << " MB; ";
        }

        // For determining the bit per second amount to output.
        if(megaBitsPerSecond >= ONE_THOUSAND) {   // If it's a GigaByte amount.
            inputRecord << (megaBitsPerSecond / ONE_THOUSAND) << " Gb/s] ";
        } else if(megaBitsPerSecond < 1) {   // If it's a KiloByte amount.
            inputRecord << (megaBitsPerSecond * ONE_THOUSAND) << " Kb/s] ";
        } else { // If it's a MegaByte amount.
            inputRecord << megaBitsPerSecond << " Mb/s] ";
        }

        inputLogBuffer[i] = inputRecord.str();
        inputRecord.flush();
        inputRecord.clear();
    }
}

/**
 * This function populates the outputLogBuffer with text for the log message.
 *
 * @param outputLogBuffer
 * @param timeDurationInSeconds
 */
void printOutputQueueLogToBuffer(string *outputLogBuffer, int timeDurationInSeconds) {
    for(int i = 0; i < config_sink_count; i++) {
        double megaBytes = 0, megaBitsPerSecond = 0;
        unsigned long packets;
        stringstream outputRecord;
        outputRecord.setf(ios::fixed, ios::floatfield);
        outputRecord.precision(LOG_PRECISION);
        outputRecord.imbue(std::locale("en_US"));
        pthread_mutex_lock(&(config_sink_array[i].mutex));
        packets = config_sink_array[i].packets;
        megaBytes = (double)(config_sink_array[i].bytes / ONE_MILLION);
        megaBitsPerSecond = (double)((megaBytes * 8) / timeDurationInSeconds);
        config_sink_array[i].packets = 0;
        config_sink_array[i].bytes = 0;
        pthread_mutex_unlock(&(config_sink_array[i].mutex));
        outputRecord << "OUT[" << packets << " packets; ";

        // For determining the Byte amount to output.
        if(megaBytes >= ONE_THOUSAND) {   // Use GigaByte level values.
            outputRecord << (megaBytes / ONE_THOUSAND) << " GB; ";
        } else if(megaBytes < 1) {   // Use KiloByte level values.
            outputRecord << (megaBytes * ONE_THOUSAND) << " KB; ";
        } else { // Use MegaByte level values.
            outputRecord << megaBytes << " MB; ";
        }

        // For determining the bit per second amount to output.
        if(megaBitsPerSecond >= ONE_THOUSAND) {   // If it's a GigaByte amount.
            outputRecord << (megaBitsPerSecond / ONE_THOUSAND) << " Gb/s] ";
        } else if(megaBitsPerSecond < 1) {   // If it's a KiloByte amount.
            outputRecord << (megaBitsPerSecond * ONE_THOUSAND) << " Kb/s] ";
        } else { // If it's a MegaByte amount.
            outputRecord << megaBitsPerSecond << " Mb/s] ";
        }

        outputLogBuffer[i] = outputRecord.str();
        outputRecord.flush();
        outputRecord.clear();
    }
}

/*
 * Print out the running totals of the stats.
 * Since there is no mutex, there may occasionally be strange values.
 */
void printPacketBufferLogToBuffer(string *freePackets) {
	if(evaluatedArguments.useMultiplePacketBuffers) {
		for(int i = 0; i < config_sink_count; i++) {
			stringstream packetRecord;
			/*
			 * If not using multiple packet buffers, then packet_pool used is 1.
			 * packet_pool[0] is for future use of hash on UEIP.
			 */
			int pktBufNum = i + 1;
			checkIfBlockedROPCount(packet_pool[pktBufNum], pktBufNum);

			if(evaluatedArguments.useMultiplePacketBuffers || i == 1) {
				int tokenDroppedPacket = 0; // just to indicate visually that we have started a BLOCKED  ROP

				if(packet_pool[i + 1]->blockedROPCount > 0) {
					tokenDroppedPacket = 1;
				}

				packetRecord << "FREE" << packet_pool[i + 1] << "; #ROPS Blocked [cur/total] = " << packet_pool[i + 1]->blockedROPCount << "/" << packet_pool[i + 1]->cumulativeBlockedROPCount
							 << "; #Pkts Dropped " <<  packet_pool[i + 1]->cumulativeDroppedPacketCount + tokenDroppedPacket
							 << "; PB Size = " << evaluatedArguments.packetBufferSize;
			} else {
				packetRecord << "";
			}

			resetBlockedROPCount(packet_pool[pktBufNum], pktBufNum);
			freePackets[i] = packetRecord.str();
			packetRecord.flush();
			packetRecord.clear();
		}
	}
	else { // useMultiplePacketBuffers == false
		stringstream packetRecord;
		/*
		 * If not using multiple packet buffers, then packet_pool used is 1.
		 * packet_pool[0] is for future use of hash on UEIP.
		 */
		int pktBufNum = 1;
		checkIfBlockedROPCount(packet_pool[pktBufNum], pktBufNum);
		int tokenDroppedPacket = 0; // just to indicate visually that we have started a BLOCKED  ROP

		if(packet_pool[1]->blockedROPCount > 0) {
			tokenDroppedPacket = 1;
		}

		packetRecord << "FREE" << packet_pool[1] << "; #ROPS Blocked [cur/total] = " << packet_pool[1]->blockedROPCount << "/" << packet_pool[1]->cumulativeBlockedROPCount
					 << "; #Pkts Dropped " <<  packet_pool[1]->cumulativeDroppedPacketCount + tokenDroppedPacket
					 << "; PB Size = " << evaluatedArguments.packetBufferSize;
		resetBlockedROPCount(packet_pool[pktBufNum], pktBufNum);
		freePackets[0] = packetRecord.str();
		packetRecord.flush();
		packetRecord.clear();
	}
}


/**
* This function prints packet loss flow stats.
*

*/
void printPacketLossFlowStats() {
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS: # Flows where four tuple has changed from original. Classifier says not a new flow (new_element=0) but four tuple info has changed from that used to initialise the flow");

        for(int i = 0; i < config_sink_count; i++) {
            LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS: QUEUE # " << i + 1 << ". # Flows not initialised. No packet loss recorded =  "
                         << hashTableCtrs.numFlowsNotInitializedByPacketLoss[i + 1] << "/" << hashTableCtrs.totalFlowsThisQueuePacketLoss[i + 1]);
        }
    }
}

/**
* This function prints Hostname stats.
*

*/
void printHostnameStats() {
    if((loggerClassifyHostname->isDebugEnabled()) || (loggerClassifyHostname->isTraceEnabled())) {
        unsigned long hostTotal;

        for(int i = 0; i < config_sink_count; i++) {
            hostTotal = hashTableCtrs.numFlowsHttpHostName[i + 1] + hashTableCtrs.numFlowsHttpDependentHostName[i + 1] + hashTableCtrs.numFlowsHttpNoHostName[i + 1] + hashTableCtrs.numFlowsNonHttpNoHostName[i + 1];
            LOG4CXX_INFO(loggerPcpGlue, " HOSTNAME: QUEUE # " << i + 1 << ". #Flows [HTTP with Hostname / HTTP Dependent Protocol with Hostname/ HTTP No Hostname / Non HTTP No Hostname / Total #NEW Flows]  =  "
                         <<  hashTableCtrs.numFlowsHttpHostName[i + 1] << "/"
                         << hashTableCtrs.numFlowsHttpDependentHostName[i + 1] << "/"
                         << hashTableCtrs.numFlowsHttpNoHostName[i + 1] << "/"
                         << hashTableCtrs.numFlowsNonHttpNoHostName[i + 1] << "/"
                         << hashTableCtrs.totalNumNewFlows[i + 1]
                         << " [" << hostTotal << "]");
        }
    }
}

/**
* Reusabe function to calculate the Packets per seconds for CDP prtocols
*

*/
void calculateCdpStats(const char *theTitle, struct cdpTimers *cdpTimer) {
    unsigned long long totalNanoSeconds, nSecPerPkt, detectionRate;
    unsigned long long totalPackets, totalFlows, totalMatch, totalNeedNextPkt, totalHttpExclude, totalExclude;
    double totalSeconds;
    totalNanoSeconds = 0;
    totalPackets = 0;
    totalFlows = 0;
    totalNeedNextPkt = 0;
    totalHttpExclude = 0;
    totalExclude = 0;
    totalMatch = 0;

    for(int i = 0; i < config_sink_count; i++) {
        totalNanoSeconds += cdpTimer->cumulativeTime[i + 1];
        totalPackets += cdpTimer->numPacketsChecked[i + 1];
        totalFlows  += cdpTimer->numberOfFlowsChecked[i + 1];
        totalMatch  += cdpTimer->numberOfFlowsMatched [i + 1];
        totalNeedNextPkt  += cdpTimer->numberOfFlowsNeedNextPkt[i + 1];
        totalHttpExclude  += cdpTimer->numberOfFlowsHTTPExcluded[i + 1];
        totalExclude  += cdpTimer->numberOfFlowsExcluded[i + 1];
        //LOG4CXX_INFO(loggerPcpGlue, " " CDP TIMERS "<< theTitle << " : QUEUE # " << i + 1 << ": " << cdpTimer->numPacketsChecked[i+1] << " Packets processed in : " << cdpTimer->cumulativeTime[i+1] << " nSec" );
    }

    totalSeconds = ((double)totalNanoSeconds / 1000000000);

    if((totalNanoSeconds != 0) && (totalPackets != 0)) {
        nSecPerPkt = (unsigned long long)((double) totalNanoSeconds / (double) totalPackets);
    } else {
        nSecPerPkt = 0;
    }

    if((totalFlows != 0) && (totalPackets != 0)) {
        detectionRate = (unsigned long long)(ceil((double) totalPackets / (double) totalFlows));
    } else {
        detectionRate = 0;
    }

    LOG4CXX_INFO(loggerPcpGlue, " CDP TIMERS " << theTitle
                 << " : " << totalFlows << " Flows ["
                 << totalPackets << " Packets] ( "
                 << totalMatch << " match, "
                 << totalNeedNextPkt << " need next pkt, "
                 << totalHttpExclude << " Http Exclude], "
                 << totalExclude << " Exclude)  : "
                 << totalNanoSeconds << " nSec [" << totalSeconds << " Sec]"
                 << ": nSec / Pack = " << nSecPerPkt
                 << ": Detection Rate = " << detectionRate << " pkts per flow");
    cdpTimer->reset();
}
/**
* This function prints Custom Protocol Timers.
*

*/
void printCdpTimerStats() {
    if(cdpTimersEnabled) {
        calculateCdpStats((const char *) "speedtest      .\0", &cdpSpeedTimer);
        calculateCdpStats((const char *) "weather        .\0", &cdpWeatherTimer);
        calculateCdpStats((const char *) "maps           .\0", &cdpMapsTimer);
        calculateCdpStats((const char *) "news           .\0", &cdpNewsTimer);
        calculateCdpStats((const char *) "advertisements .\0", &cdpAdvertsTimer);
        calculateCdpStats((const char *) "software-update.\0", &cdpSWuTimer);
        calculateCdpStats((const char *) "photo-sharing  .\0", &cdpPhotoTimer);
        calculateCdpStats((const char *) "LLMNR          .\0", &cdpLlmnrTimer);
        int hostNum;

        for(hostNum = 0; hostNum < MAX_SIMPLE_HOSTS; hostNum++) {
            calculateCdpStats((const char *) CDP_SIMPLE_HOST[hostNum], &cdpSimpleHostTimer[hostNum]);
        }
    }
}

/**
* This function prints packet loss flow stats.
*

*/
void printNoPacketLossRateStats() {
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        double percentRate;

        for(int i = 0; i < config_sink_count; i++) {
            if(hashTableCtrs.numFlowsPktLoss_INET[i + 1] > 0) {
                percentRate = (((double)(hashTableCtrs.numFlowsNoPktLossRate_INET[i + 1]) / (double)(hashTableCtrs.numFlowsPktLoss_INET[i + 1])) * 100);
            } else {
                percentRate = 0;
            }

            LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS: QUEUE # " << i + 1 << ". # Times No packet loss recorded (Check Data Integrity Failed) UE -> INTERNET "
                         << hashTableCtrs.numFlowsNoPktLossRate_INET[i + 1] << "/" << hashTableCtrs.numFlowsPktLoss_INET[i + 1] << " (" << percentRate << "%)") ;
        }

        for(int i = 0; i < config_sink_count; i++) {
            if(hashTableCtrs.numFlowsPktLoss_UE[i + 1] > 0) {
                percentRate = (((double)(hashTableCtrs.numFlowsNoPktLossRate_UE[i + 1]) / (double)(hashTableCtrs.numFlowsPktLoss_UE[i + 1])) * 100);
            } else {
                percentRate = 0;
            }

            LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS: QUEUE # " << i + 1 << ". # Times No packet loss recorded (Check Data Integrity Failed) INTERNET -> UE "
                         << hashTableCtrs.numFlowsNoPktLossRate_UE[i + 1] << "/" << hashTableCtrs.numFlowsPktLoss_UE[i + 1] << " (" << percentRate << "%)");
        }

        hashTableCtrs.resetPktLossCounters();
    }
}
/**
* prints number fragmented packets per ROP stats
*

*/
void printFragmentedStats() {
    unsigned long long totalPkts, fragL1, fragL2;
    fragL1 = 0;
    fragL2 = 0;
    totalPkts=0;

    for(int i = 0; i < config_sink_count; i++) {
        totalPkts += hashTableCtrs.totalNumPackets_source[i + 1];
        fragL1 += hashTableCtrs.numPacketsFragmented_L1_source[i + 1];
        fragL2 += hashTableCtrs.numPacketsFragmented_L2_source[i + 1];
    }
    
    LOG4CXX_INFO(loggerPcpGlue, " FRAG STATS (Per ROP)"
                 << ": Total " << totalPkts << " Packets"
                 << ": Dropped IP L1 Fragments " << fragL1 << " Packets"
                 << ": Dropped IP L2 Fragments " << fragL2 << " Packets"
                 );
    hashTableCtrs.resetFragCounters();
}
/**
 * This function prints log messages from the formatted data sources.
 *
 * @param inputBuffer
 * @param outputBuffer
 * @param freePacketsBuffer
 */
void printQueueAndPacketBufferStatsToLog(string *inputBuffer, string *outputBuffer, string *freePacketsBuffer) {
    LOG4CXX_INFO(loggerPcpGlue, "-----------------------------------");
	if(evaluatedArguments.useMultiplePacketBuffers) {
		for(int i = 0; i < config_sink_count; i++) {
			// TODO: Put in a check for OutOfBoundsException in the arrays.
			stringstream buffer;
			buffer << "PACKETBUFFER [" << i + 1 << "] STATS: " << inputBuffer[i] << outputBuffer[i] << freePacketsBuffer[i] ;
			LOG4CXX_INFO(loggerPcpGlue, buffer.str());
			buffer.flush();
			buffer.clear();
		}
	}
	else { // useMultiplePacketBuffers == false
		LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER STATS: " << freePacketsBuffer[0]);
		for(int i = 0; i < config_sink_count; i++) {
			// TODO: Put in a check for OutOfBoundsException in the arrays.
			stringstream buffer;
			buffer << "QUEUE [" << i + 1 << "] STATS: " << inputBuffer[i] << outputBuffer[i] ;
			LOG4CXX_INFO(loggerPcpGlue, buffer.str());
			buffer.flush();
			buffer.clear();
		}
	}
    LOG4CXX_INFO(loggerPcpGlue, "-----------------------------------");
}

void source_monitor(int seconds) {
    string inputBuffer[config_sink_count], outputBuffer[config_sink_count], freePacketsBuffer[config_sink_count];
    // Print input, output and packet buffer stats to buffers.
    printInputQueueLogToBuffer(inputBuffer, seconds);
    printOutputQueueLogToBuffer(outputBuffer, seconds);
    printPacketBufferLogToBuffer(freePacketsBuffer);
    // Print the formatted log message.
    printQueueAndPacketBufferStatsToLog(inputBuffer, outputBuffer, freePacketsBuffer);
    printPacketLossFlowStats();
    printPacketLossStats();
    printHostnameStats();
    printCdpTimerStats();
    printFragmentedStats();
    // Continue on printing logs.
    classifyPrintLog();
}

void source_sink_cleanup(void *init) {
    LOG4CXX_INFO(loggerPcpGlue, "PCP source thread termination.... Starting.");

    for(int i = 0; i < config_sink_count; i++) {
        if(config_source_array[i].thread != 0) {
            sleep(3);
            pthread_cancel(config_source_array[i].thread);
        }
    }

    LOG4CXX_INFO(loggerPcpGlue, "PCP source thread termination.... Waiting.");

    for(int i = 0; i < config_sink_count; i++) {
        if(config_source_array[i].thread != 0) {
            pthread_join(config_source_array[i].thread, NULL);
        }
    }

    LOG4CXX_INFO(loggerPcpGlue, "PCP source thread termination....  Finished.");
    sleep(3);
    LOG4CXX_INFO(loggerPcpGlue, "PCP sink thread termination.... Starting.");

    for(int i = 0; i < config_sink_count; i++) {
        if(config_sink_array[i].thread != 0) {
            sleep(3);
            pthread_cancel(config_sink_array[i].thread);
        }
    }

    sleep(3);
    LOG4CXX_INFO(loggerPcpGlue, "PCP sink thread termination.... Waiting.");

    for(int i = 0; i < config_sink_count; i++) {
        if(config_sink_array[i].thread != 0) {
            pthread_join(config_sink_array[i].thread, NULL);
        }
    }

    LOG4CXX_INFO(loggerPcpGlue, "PCP sink thread termination....  Finished.");
    LOG4CXX_INFO(loggerPcpGlue, "PCP main thread terminated.");
}

void *start_source_sink(void *init) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    prctl(PR_SET_NAME, "pect_monitor", 0, 0, 0);
    LOG4CXX_INFO(loggerPcpGlue, "Starting packet capture and classification.");
    //TODO: Configurable maximum number of packets

    if(evaluatedArguments.useMultiplePacketBuffers) {
        // config_source_count is same size as max number of required packet buffers
        for(int i = 1; i <= config_source_count ; i++) {
            packet_pool[i] = packetbuffer_start(1, evaluatedArguments.packetBufferSize);
        }
    } else { //packet pool[0] will be used for future use for distribution by hashing on UEIP.
        packet_pool[1] = packetbuffer_start(config_sink_count + 1, evaluatedArguments.packetBufferSize);
    }

    sink_start();
    source_start();
    int time = evaluatedArguments.printPacketBufferStatsInterval;
    pthread_cleanup_push(source_sink_cleanup, init);

    while(1) {
        pthread_testcancel();
        source_monitor(time);
        sleep(time);
    }

    pthread_cleanup_pop(1);
    return (0); // for now, will never happen
}

/**
 * Prints statistical information about the hash table.
 */
void printHashTableStatistics() {
    for(int i = 0; i < config_sink_count; i++) {
        char msg[50];
        snprintf(msg, sizeof(msg), "SUBSCRIBER [%d] : ", i + 1);
        packet_sink sink;
        sink = &config_sink_array[i] ;
        u32 numUsedElements = ipoque_to_hash_used_elements(sink->cd->subscriber_toh);
        u32 maxNumUsedElements = ipoque_to_hash_maximum_number_of_used_elements(sink->cd->subscriber_toh);
        u32 numElementsThatCanBeStored = ipoque_to_hash_number_of_elements(sink->cd->subscriber_toh);
        LOG4CXX_TRACE(loggerClassify, msg << "Number of elements currently used in the given hash table " << numUsedElements);
        LOG4CXX_TRACE(loggerClassify, msg << "Maximum number of elements used at any given time " << maxNumUsedElements);
        LOG4CXX_TRACE(loggerClassify, msg << "Number of elements that can be stored in the hash table with the current memory size " << numElementsThatCanBeStored);
        hashTableRemovalReason(msg , sink->cd->subscriber_toh);
        snprintf(msg, sizeof(msg), "CONNECTION [%d] : ", i + 1);
        numUsedElements = ipoque_to_hash_used_elements(sink->cd->connection_toh);
        maxNumUsedElements = ipoque_to_hash_maximum_number_of_used_elements(sink->cd->connection_toh);
        numElementsThatCanBeStored = ipoque_to_hash_number_of_elements(sink->cd->connection_toh);
        LOG4CXX_TRACE(loggerClassify, msg << "Number of elements currently used in the given hash table " << numUsedElements);
        LOG4CXX_TRACE(loggerClassify, msg << "Maximum number of elements used at any given time " << maxNumUsedElements);
        LOG4CXX_TRACE(loggerClassify, msg << "Number of elements that can be stored in the hash table with the current memory size " << numElementsThatCanBeStored);
        hashTableRemovalReason(msg , sink->cd->connection_toh);
        LOG4CXX_TRACE(loggerClassify, "Flow Timeout Classification [Per ROP]: SHORT = " << hashTimeoutClass.shortTimeoutClass << ": MEDIUM = " << hashTimeoutClass.mediumTimeoutClass << ": LONG = " << hashTimeoutClass.longTimeoutClass);
    }
}

/**
 * Prints statistical information about Packet Loss.
 */
void printPacketLossStats() {
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        char msg[300];
        unsigned long packets, tcpPackets;
        uint32_t pktlLoss_INET_TO_UE, pktlLoss_UE_TO_INET;
        unsigned long percentage_loss_UE_TO_INET = 0, percentage_loss_INET_TO_UE = 0;
        uint32_t pktlossRate_UE_TO_INET, pktlossRate_INET_TO_UE;
        pthread_mutex_lock(&packetLossMutex);
        packets = pktLossCtrs.totalPackets;
        tcpPackets = pktLossCtrs.tcpPackets;
        pktlLoss_INET_TO_UE = pktLossCtrs.internetToUEpktLoss;
        pktlLoss_UE_TO_INET = pktLossCtrs.ueToInternetpktLoss;
        pktlossRate_UE_TO_INET = pktLossCtrs.maxLoss_ueToInternet;
        pktlossRate_INET_TO_UE = pktLossCtrs.maxLoss_internetToUE;
        pktLossCtrs.reset();
        pthread_mutex_unlock(&packetLossMutex);

        if(tcpPackets != 0) {
            percentage_loss_UE_TO_INET = ((unsigned long) pktlLoss_UE_TO_INET * PKTLOSS_RATE_RESOLUTION * 100) / tcpPackets;
            percentage_loss_INET_TO_UE = ((unsigned long)pktlLoss_INET_TO_UE * PKTLOSS_RATE_RESOLUTION * 100) / tcpPackets;
        }

        snprintf(msg, sizeof(msg), "PACKET LOSS STATS: Total Packets = %lu; Tcp Packets = %lu;# Packets with Packet Loss UE->INTERNET = %u [%lu]; INTERNET->UE =%u [%lu];Max Packet Loss [x %u] UE->INTERNET = %u; INTERNET->UE = %u", packets, tcpPackets, pktlLoss_UE_TO_INET, percentage_loss_UE_TO_INET, pktlLoss_INET_TO_UE, percentage_loss_INET_TO_UE, (uint32_t)PKTLOSS_RATE_RESOLUTION , pktlossRate_UE_TO_INET, pktlossRate_INET_TO_UE);
        LOG4CXX_INFO(loggerPacketLoss, msg);
    }
}

/*
 * Print out the running totals of the stats.
 * Since there is no mutex, there may occasionally be strange values.
 */
void classifyPrintLog() {
    unsigned long long theNumFlowsAdded = 0, theNumFlowsToBeRemoved = 0;
    unsigned long theNumFlowsAddedThisROP = 0, theNumFlowsToBeRemovedThisROP = 0;

    for(int i = 0; i < config_sink_count; i++) {
        theNumFlowsAddedThisROP += hashTableCtrs.numFlowsAddedThisROP[i];
        theNumFlowsAdded += hashTableCtrs.numFlowsAdded[i];
        theNumFlowsToBeRemovedThisROP += hashTableCtrs.numFlowsToBeRemovedThisROP[i];
        theNumFlowsToBeRemoved += hashTableCtrs.numFlowsToBeRemoved[i];
        hashTableCtrs.numFlowsAddedThisROP[i] = 0;
        hashTableCtrs.numFlowsToBeRemovedThisROP[i] = 0;
    }

    LOG4CXX_INFO(loggerClassify, "FLOW STATS: Active Flows:  (Added This ROP/Total) " << theNumFlowsAddedThisROP << "/" << theNumFlowsAdded
                 << ", Removal Requests: (This ROP/Total) " << theNumFlowsToBeRemovedThisROP << "/" << theNumFlowsToBeRemoved);

    if(theNumFlowsAddedThisROP > 0) {
        if(loggerClassify->isTraceEnabled()) {  // Cannot AND this with the if above due to the else.
            printHashTableStatistics(); // This function only prints TRACE messages for classify.
        }
    } else {
        LOG4CXX_INFO(loggerClassify, "No Hash Map Statistics as no new flows added.");
    }
}
