#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <string.h>
#include <boost/tr1/unordered_map.hpp>
#include <fstream>
#include <sstream>
#include <list>
#include <memory>
#include <pthread.h>
#include <sys/prctl.h>
#include <csignal>

#include "config.h"
#include "file_writer.hpp"
#include "gtp_ie.h"
#include "GTPVProbe.h"
#include "gtp_ie_gtpv2.h"
#include "gtpc_map_serialisation_utils.h"
#include "gtpv2_main.h"
#include "gtpv1_utils.h"
#include "GTPv1_packetFields.h"
#include "logger.hpp"
#include "mutex.hpp"
#include "MagicStringTester.h"
#include "pcpglue.hpp"
#include "UE_map.hpp"
#include "license_controller.hpp"
#include "gtpv1_message_handler.h"
#include "gtpv1_maps.h"
#include "gtpv1_message_utils.h"
#include "gtpv1_message_handler_types.h"
#include "packetLossStandAlone.hpp"

// include headers that implement a archive in simple text format
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/unordered_map.hpp>
#include <boost/archive/archive_exception.hpp>


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

using namespace std;
using namespace log4cxx;
int totalPacketsProcessedDuringRun = 0;
int gtp_records_written = 0;
int closingGTP_C_source = 0;
int closingGTP_C_sink = 0;

extern unsigned int TESTING_PACKET_LOSS_SA;

extern unsigned int TESTING_PACKET_LOSS_SA;

// Function prototypes
int processGtpcPackets(struct pcap_pkthdr *pkthdr,  const unsigned char *packet, bool cooked, int dlink, PacketCounter *packetCounter);

void *sinkGTPCPacket(void *init);
void *sourceGTPCPacket(void *init);
void logStats(time_t last_stat);

//PGconn *conn;

char output_file_name[FILENAME_MAX];
packetbuffer gtpcPacketPool;

ofstream f_out;
ostream *v2_out = &f_out;
LicenseController *licenseController = NULL;

time_t file_time = 0;
time_t last_maint = 0;

extern EArgs evaluatedArguments;
extern packetLossStatisticsStruct pktLossCtrs;

unsigned long n_pdp_req = 0;
unsigned long n_pdp_resp = 0;
unsigned long n_update_req = 0;
unsigned long n_update_resp = 0;
unsigned long n_delete_req = 0;
unsigned long n_delete_resp = 0;
unsigned long pdp_resp_teid_not_found = 0;
unsigned long pdp_resp_imsi_not_found = 0;
unsigned long purgedPDPSessionCount = 0;
unsigned long imsiCount = 0;

GTPV1MessageHandlerStats_t messageHandlerStats;

/**
 * Log an error for problems with the ueMap
 *
*/
void logUeMapMessage(u_int32_t theHashKey, PDPSession *theSession) {
    LOG4CXX_INFO(loggerGtpcParser, "Hash Key = " << theHashKey
                 << " PDPSession UEIP = " << theSession->ue_addr
                 << " IMSI = " << theSession->imsi
                 << " sgsn TEID = " << theSession->sgsn_c.teid
                 << " ggsn_c TEID = " << theSession->ggsn_c.teid
                 << " dle TEID = " << theSession->dle.teid);
}


void printaddr(unsigned int a) {
    in_addr addr;
    addr.s_addr = a;
    LOG4CXX_TRACE(loggerGtpcParser, "I.P Address:" << inet_ntoa(addr));
}


void processMessage(unsigned char *data, int dataLength, DecodedMsg *message);


double diffclock(clock_t clock1, clock_t clock2) {
    double diffticks = (double)(clock1 - clock2);
    double diffms = (diffticks * 10) / CLOCKS_PER_SEC;
    return diffms;
}

static void signalHandler(int signal) {
    static bool isTerminating = false;

    if(isTerminating == true) {
        LOG4CXX_INFO(loggerBroadcast, "Termination in progress...");
        return;
    }

    isTerminating = true;
    LOG4CXX_INFO(loggerBroadcast, "Stopping Packet Capture Pre-Processor.");

    if(TESTING_PACKET_LOSS_SA) {
        cleanupPacketLossStandAlone();
    }

    if(signal == SIGINT) {
        LOG4CXX_INFO(loggerPect, "Packet Capture Pre-Processor application will be terminated due to interrupt request.");
    } else if(signal == SIGTERM) {
        LOG4CXX_INFO(loggerPect, "Packet Capture Pre-Processor application will be terminated due to termination request.");
    } else if(signal == SIGABRT) {
        LOG4CXX_INFO(loggerPect, "Packet Capture Pre-Processor application will be terminated due to abnormal termination signal.");
    } else {
        LOG4CXX_ERROR(loggerPect, "Packet Capture Pre-Processor application will be terminated due to unknown signal: " << signal);
    }

    if(licenseController != NULL) {
        LOG4CXX_INFO(loggerBroadcast, "Waiting for Packet Capture Pre-Processor to stop.");
        licenseController->terminateApplication();
    }

    cout << endl; // just want a new line for formatting
    LOG4CXX_INFO(loggerBroadcast, "Packet Capture Pre-Processor stopped.");
    exit(0);
}

void initSignalHandler() {
    if(signal(SIGINT, signalHandler) == SIG_ERR) {
        LOG4CXX_ERROR(loggerConsole, "An error occurred while setting a signal handler.\n");
    }

    if(signal(SIGTERM, signalHandler) == SIG_ERR) {
        LOG4CXX_ERROR(loggerConsole, "An error occurred while setting a signal handler.\n");
    }

    if(signal(SIGABRT, signalHandler) == SIG_ERR) {
        LOG4CXX_ERROR(loggerConsole, "An error occurred while setting a signal handler.\n");
    }
}

unsigned int TESTING_PACKET_LOSS_SA;

int main(int argc, char **argv) {
    licenseController = NULL;
    // PROCESS ARGUMENTS
    pcap_t *descr = NULL;
    std::cout << "INFO  broadcast - Waiting for Packet Capture PreProcessor to start" << std::endl;
    prctl(PR_SET_NAME, "pect_log", 0, 0, 0);

    if(initializeLogging() == EXIT_FAILURE) {
        std::cout << "ERROR: Error initializing logging, shutting down." << std::endl;
        exit(2);
    }

    LOG4CXX_INFO(loggerPect, "*****************************************************");
    LOG4CXX_INFO(loggerPect, "Waiting for Packet Capture PreProcessor to start");

    if(strcmp(argv[1], "-testPacketLoss") == 0) {
        LOG4CXX_INFO(loggerConfiguration, "TESTING PACKET LOSS STAND ALONE");
        LOG4CXX_INFO(loggerConsole, "TESTING PACKET LOSS STAND ALONE");
        TESTING_PACKET_LOSS_SA = 1;
        testPacketLoss(argc, argv);
        return 0;
    }

    prctl(PR_SET_NAME, "gtpc_pcap", 0, 0, 0);
    TESTING_PACKET_LOSS_SA = 0;

    if(parseArgs(argc, argv, &descr) != 0) {
        LOG4CXX_FATAL(loggerPect, "Argument errors, exiting.");
        LOG4CXX_FATAL(loggerConfiguration, "Argument errors, exiting.");
        return 1;
    }

    if(configurePacketBuffer()) {
        LOG4CXX_FATAL(loggerPect, "Argument errors, exiting.");
        return (255);
    }

    LOG4CXX_INFO(loggerLicense, "----------------------------------------------------------------------");
    int result = LicenseController::getLicenseController()->checkLicense();
    LOG4CXX_INFO(loggerLicense, "----------------------------------------------------------------------");

    if(result != 0) {
        LOG4CXX_FATAL(loggerLicense, "Packet Capture Pre-processor application will be terminated due to invalid license.");
        LOG4CXX_FATAL(loggerConsole, "Packet Capture Pre-processor application will be terminated due to invalid license.");
        exit(-1);
    }

    LOG4CXX_INFO(loggerBroadcast, "Initial license check success.");
    // Read the GTP-C Cache from File.
    readGtpcCache();
    //LOG4CXX_INFO(loggerBroadcast, "Total GTP-C sessions loaded " << ueMap_GTPC.size());
    gtpcPacketPool = packetbuffer_start(1, evaluatedArguments.packetBufferSize);
    // Thread for PCP Glue.
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_t threadPCPGlue;
    //pktLossCtrs.reset();
    //pktLossCtrs.initRedZone();
    pthread_create(&(threadPCPGlue), &attr, start_source_sink, NULL);
    // Thread for the File Writer.
    pthread_attr_t attr_threadPrintUEMap;
    pthread_attr_init(&attr_threadPrintUEMap);
    pthread_t threadPrintUEMap;
    pthread_create(&(threadPrintUEMap), &attr_threadPrintUEMap, threadForPrintUeMap, NULL);
    // Thread for GTP-C parser sink.
    pthread_attr_t attrGtpcParserSink;
    pthread_attr_init(&attrGtpcParserSink);
    pthread_t threadGtpcParserSink;
    pthread_create(&(threadGtpcParserSink), &attrGtpcParserSink, sinkGTPCPacket, NULL);
    // Thread for GTP-C parser source.
    pthread_attr_t attrGtpcParserSource;
    pthread_attr_init(&attrGtpcParserSource);
    pthread_t threadGtpcParserSource;
    pthread_create(&(threadGtpcParserSource), &attrGtpcParserSource, sourceGTPCPacket, descr);
    // Thread to write GTP-C cache to file on a time interval.
    pthread_attr_t attr_threadWriteGtpcCache;
    pthread_attr_init(&attr_threadWriteGtpcCache);
    pthread_t threadWriteGtpcCache;
    pthread_create(&(threadWriteGtpcCache), &attr_threadWriteGtpcCache, gtpcWriteTimer, NULL);
    licenseController = LicenseController::getLicenseController();
    licenseController->addThreadToController(threadPCPGlue);
    licenseController->addThreadToController(threadPrintUEMap);
    licenseController->addThreadToController(threadGtpcParserSource);
    licenseController->addThreadToController(threadGtpcParserSink);
    licenseController->addThreadToController(threadWriteGtpcCache);
    LOG4CXX_INFO(loggerPect, "PCP-PECT All Threads Started, completing classification initialisation.");
    LOG4CXX_DEBUG(loggerConsole, "PCP-PECT All Threads Started, completing classification initialisation.");
    initSignalHandler();
    licenseController->start();
}
void sinkGTPCPacketCleanup(void *init) {
    LOG4CXX_INFO(loggerPect, "GTP-C_CLOSE: Cleanup GTP-C sink: ... Starting");

    if(init != NULL) {
        // Put any cleanup here:
        PacketCounter *packetCounter = (PacketCounter *) init;

        if(packetCounter != NULL) {
            if(!closingGTP_C_sink) {
                closingGTP_C_sink = 1; //efitleo: attempt to fix EVEV-16224
                delete(packetCounter);
                LOG4CXX_INFO(loggerPect, "GTP-C_CLOSE: Cleanup GTP-C sink: ... Finished");
            } else {
                LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Already Cleaning GTP-C Sink");
            }
        } else {
            LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Unable to Cleanup GTP-C Sink: packetCounter is NULL");
        }
    } else {
        LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Unable to Cleanup GTP-C Sink: init pointer is NULL");
    }
}

void sourceGTPCPacketCleanup(void *init) {
    LOG4CXX_INFO(loggerPect, "GTP-C_CLOSE: Cleanup GTP-C source: ... Starting");

    if(init != NULL) {
        pcap_t *descr = (pcap_t *) init;

        if(descr != NULL) { //efitleo: attempt to fix EQEV-16224
            if(!closingGTP_C_source) {
                closingGTP_C_source = 1; //efitleo: attempt to fix EVEV-16224
                pcap_breakloop(descr);
                pcap_close(descr);
                LOG4CXX_INFO(loggerPect, "GTP-C_CLOSE: Cleanup GTP-C source: ... Finished");
            } else {
                LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Already Cleaning GTP-C source");
            }
        } else {
            LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Unable to Cleanup GTP-C source: pcap descriptor is NULL");
        }
    } else {
        LOG4CXX_WARN(loggerPect, "GTP-C_CLOSE: Unable to Cleanup GTP-C source: pcap init pointer is NULL");
    }
}

pcap_t *openGtpcPcap() {
    pcap_t *descrPtr;
    char errbuf[PCAP_ERRBUF_SIZE];
    bzero(errbuf, PCAP_ERRBUF_SIZE);

    if(strcmp(evaluatedArguments.type.c_str(), "true") == 0) {
        evaluatedArguments.GTP_capture_type_is_live_interface = 1;
        descrPtr = pcap_open_live(evaluatedArguments.GTPCInput.c_str(), BUFSIZ, 1, 1000, errbuf);
        LOG4CXX_INFO(loggerConfiguration, "GTPC packet capture on interface " << evaluatedArguments.GTPCInput.c_str());
        LOG4CXX_DEBUG(loggerConsole, "GTPC packet capture on interface " << evaluatedArguments.GTPCInput.c_str());
    } else if(strcmp(evaluatedArguments.type.c_str(), "false") == 0) {
        evaluatedArguments.GTP_capture_type_is_live_interface = 0;
        descrPtr = pcap_open_offline(evaluatedArguments.GTPCInput.c_str(), errbuf);
        LOG4CXX_INFO(loggerConfiguration, "GTPC packet capture on file " << evaluatedArguments.GTPCInput.c_str());
        LOG4CXX_DEBUG(loggerConsole, "GTPC packet capture on interface " << evaluatedArguments.GTPCInput.c_str());
    } else {
        evaluatedArguments.GTP_capture_type_is_live_interface = -1;
        LOG4CXX_FATAL(loggerConfiguration, "Unable to open: " << evaluatedArguments.GTPCInput);
        LOG4CXX_FATAL(loggerConsole, "Unable to open: " << evaluatedArguments.GTPCInput);
        return NULL;
    }

    if(descrPtr == NULL) {
        LOG4CXX_FATAL(loggerConfiguration, "GTPC packet capture open failed: " << errbuf);
        LOG4CXX_FATAL(loggerConsole, "GTPC packet capture open failed: " << errbuf);
        return NULL;
    }

    return descrPtr;
}

void *sourceGTPCPacket(void *init) {
    prctl(PR_SET_NAME, "pectGtpc_source", 0, 0, 0);
    pcap_t *descr = openGtpcPcap();
    // efitleo: don't use unique_ptr as PacketCounter deleted in sink ;
    // Fix for EQEV- 16224 : See http://en.cppreference.com/w/cpp/memory/unique_ptr
    //unique_ptr<PacketCounter> packetCounterPtr(PacketCounter::getInstance());
    PacketCounter *packetCounter = PacketCounter::getInstance();
    struct timeval then;
    const u_char *networkInterfacePacketPointer;
    char *bufferPacketPointer;
    struct PectPacketHeader *pectHeader;
    int nextFreePacktFromBuffer;
    int gtpcSinkQueue = 1;
    struct pcap_pkthdr *pkthdr; /* pcap.h */
    gettimeofday(&then, NULL);
    closingGTP_C_source = 0; //efitleo: attempt to fix EVEV-16224
    pthread_cleanup_push(sourceGTPCPacketCleanup, init);

    do {
        enum GTPFlags::PCAPReadStatus retval = (GTPFlags::PCAPReadStatus) pcap_next_ex(descr, &pkthdr, &networkInterfacePacketPointer);

        if(retval == GTPFlags::EndOfFile) {
            if(evaluatedArguments.GTP_capture_type_is_live_interface == 1) {
                LOG4CXX_INFO(loggerGtpcParser, "GTP-C: sourceGTPCPacket :Stop reading from the GTPC Stream . Stopped by Breakloop .");
                break;
            } else { // file interface. keep reading so that GTPU can finish. GTPC is the main thread
                sleep(5);
                continue;
            }
        }

        if(retval == GTPFlags::TIMEOUT) {
            continue;
        }

        packetCounter->incrementTotalPackets();
        totalPacketsProcessedDuringRun++;

        if(retval == GTPFlags::ERROR) {
            packetCounter->incrementTotalErrorPackets();
            continue;
        } else if(retval != GTPFlags::OK) {
            packetCounter->incrementTotalUnexpectedPackets();
            continue;
        }

        do {
            nextFreePacktFromBuffer = packetbuffer_grab_free(gtpcPacketPool);
        } while(nextFreePacktFromBuffer < 0);

        pectHeader = packetbuffer_header(gtpcPacketPool, nextFreePacktFromBuffer);
        bufferPacketPointer = (char *) packetbuffer_data(gtpcPacketPool, nextFreePacktFromBuffer);
        memcpy(&pectHeader->pcapHeader, pkthdr, sizeof(struct pcap_pkthdr));

        if(pectHeader->pcapHeader.caplen > PACKET_MAX_BYTES) {
            pectHeader->pcapHeader.caplen = PACKET_MAX_BYTES;
        }

        memcpy(bufferPacketPointer, networkInterfacePacketPointer, pectHeader->pcapHeader.caplen);
        pectHeader->cooked = false;
        pectHeader->dlink = pcap_datalink(descr);

        if(pectHeader->dlink == 113) {
            pectHeader->cooked = true;
        }

        packetbuffer_queue(gtpcPacketPool, gtpcSinkQueue, nextFreePacktFromBuffer);
        packetbuffer_release(gtpcPacketPool, nextFreePacktFromBuffer);
    } while(true);

    pthread_cleanup_pop(1);
    return 0;
}

time_t statsLogTimer = 0;

void *sinkGTPCPacket(void *init) {
    prctl(PR_SET_NAME, "pectGtpc_sink", 0, 0, 0);
    int gtpcSinkQueue = 1;
    int nextPacketFromBuffer;
    struct PectPacketHeader *pectHeader;
    const unsigned char *packet;
    int retryCounter;
    closingGTP_C_sink = 0;
    PacketCounter *packetCounter = PacketCounter::getInstance();
    pthread_cleanup_push(sinkGTPCPacketCleanup, packetCounter);

    do {   // never return
        retryCounter = 0;

        do {
            nextPacketFromBuffer = packetbuffer_grab_next(gtpcPacketPool, gtpcSinkQueue, 1);
            retryCounter++;

            if(retryCounter > 100) {
                usleep(retryCounter * 7000);
            }
        } while(nextPacketFromBuffer < 0);

        pectHeader = packetbuffer_header(gtpcPacketPool, nextPacketFromBuffer);
        packet = (const unsigned char *) packetbuffer_data(gtpcPacketPool, nextPacketFromBuffer);
        processGtpcPackets(&pectHeader->pcapHeader, packet, pectHeader->cooked, pectHeader->dlink, packetCounter);
        packetbuffer_release(gtpcPacketPool, nextPacketFromBuffer);
    } while(true);

    pthread_cleanup_pop(1);
    return 0;
}

int processGtpcPackets(struct pcap_pkthdr *pkthdr, const unsigned char *packet, bool cooked, int dlink, PacketCounter *packetCounter) {
    // Start  of main file read loop
    const struct my_ip *ip;
    int length;

    if(!GetPacketPointerAndLength(packet, cooked, &ip, &length, pkthdr)) {
        return 1;
    }

    int len = ntohs(ip->ip_len);
    int hlen = IP_HL(ip); /* header length */
    int version = IP_V(ip);/* ip version */

    if(!checkDataMatches("Version: ", IPVersion::IPV4, version)) {
        packetCounter->incrementNonIPV4Packets();
        return 1;
    }

    if(!checkDataGE("Header length", 5, hlen)) {
        packetCounter->incrementInvalidHeaderLengthPackets();
        return 1;
    }

    if(!checkDataGE("Truncated IP", len, length)) {
        packetCounter->incrementTruncatedPackets();
        return 1;
    }

    //Start of IP packet processing after initial packet checks
    if(ip->ip_p != GTPFlags::UDP) {
        packetCounter->incrementNonUDPPackets();
        return 1;
    }

    if(ntohs(ip->ip_off) & (IP_MF | IP_OFFMASK)) {
        // Fragmented
        packetCounter->incrementFragmentedPackets();
        return 1;
    }

    // TODO: Add check for fragmented packet
    //TODO check sizeof
    unsigned char *udp = (unsigned char *) ip + hlen * sizeof(int);
    unsigned short sport = extractPortFromPacket(&udp[0]);
    unsigned short dport = extractPortFromPacket(&udp[2]);

    if(sport != GTPPorts::GTP_CONTROL_PORT && dport != GTPPorts::GTP_CONTROL_PORT) {
        return 1;
    }

    unsigned char *gtp = udp + 8; // UDP header is 8 bytes long
    GTP_Control_Basic_Header gtpHeader = *(GTP_Control_Basic_Header *) gtp;

    if(gtpHeader.Version == 1) {
        PacketCounter::getInstance()->incrementTotalNumberOfVersion(1);
    } else if(gtpHeader.Version == 2) {
        PacketCounter::getInstance()->incrementTotalNumberOfVersion(2);
    }

    if(!(gtpHeader.Version == 1
            && (evaluatedArguments.GTPCVersion == VERSION_ONE || evaluatedArguments.GTPCVersion == VERSION_BOTH))) {
        if(gtpHeader.Version == 2
                && (evaluatedArguments.GTPCVersion == VERSION_TWO || evaluatedArguments.GTPCVersion == VERSION_BOTH)) {
            LOG4CXX_INFO(loggerGtpcParser, "GTP-V2 packet Received: packet not processed as GTPV2 Disabled");
            //processV2Packet(packet, pkthdr, dlink);
        }

        logV2Stats(pkthdr->ts.tv_sec);
        return 1;
    }

    //efitleo: EQEV-5831; Ensure that we only process gtpv1 packets
    if(gtpHeader.Version == 1) {
        timeoutGTPSessions(pkthdr->ts.tv_sec, evaluatedArguments);
        timeoutSequenceNumbers(pkthdr->ts.tv_sec, messageHandlerStats);
        struct DecodedMsg msg;
        //TODO move the following to DecodedMsg constructor.
        msg.timestamp = (double) pkthdr->ts.tv_sec + (double) pkthdr->ts.tv_usec / 1e6;
        msg.src_addr = ntohl(ip->ip_src.s_addr);
        msg.dst_addr = ntohl(ip->ip_dst.s_addr);
        msg.src_port = sport;
        msg.dst_port = dport;
        msg.teid = ntohl(gtpHeader.TunnelEndpointIdentifier);
        msg.lac = -1;
        msg.messageType = gtpHeader.MessageType;
        unsigned char *data;
        GTP_Control_Header theHeader;

        if(gtpHeader.N_PDUNumberFlag || gtpHeader.SequenceNumberFlag || gtpHeader.ExtensionHeaderFlag) {
            theHeader.fullHeader = *(GTP_Control_Full_Header *) gtp;
            data = gtp + sizeof(GTP_Control_Full_Header);
            msg.sequenceNumber = ntohs(theHeader.fullHeader.SequenceNumber);  // Capture the sequence number if it's present
            msg.sequenceNumberPresent = 1;
        } else {
            theHeader.basicHeader = *(GTP_Control_Basic_Header *) gtp;
            data = gtp + sizeof(GTP_Control_Basic_Header);
        }

        if(gtpHeader.ExtensionHeaderFlag) {
            LOG4CXX_TRACE(loggerGtpcParser, "Extension header");

            while(data[-1] > 0) {
                if(data[0] <= 0) {
                    LOG4CXX_ERROR(loggerGtpcParser, "Wrong Extension header");
                    break;
                }

                data += (data[0]) * 4; // TODO - factor out 4
            }
        }

        unsigned short int gtplength = ntohs(gtpHeader.TotalLength);
        int datalen = gtplength - (int)(data - gtp - (int) sizeof(GTP_Control_Basic_Header));  //changed from 8 to sizeof Michael 16_07_12
        processMessage(data, datalen, &msg);
        logStats(pkthdr->ts.tv_sec);
        return 0;
    } else {
        LOG4CXX_INFO(loggerGtpcParser,
                     "Unidentified GTPC Version received [" << gtpHeader.Version << " ] Packet not processed");
        return 1;
    }
}

void logStats(time_t currentPacket) {
    if(currentPacket > statsLogTimer) {
        statsLogTimer = (currentPacket - (currentPacket % 60)) + 60; // Initialise to the next round minute;
        LOG4CXX_INFO(loggerGtpcParser, "GTP-C messages: CREATE req/resp[" << messageHandlerStats.createRequestCount << "/" <<
                     messageHandlerStats.createResponseCount << "] UPDATE req/resp[" << messageHandlerStats.updateRequestCount << "/" <<
                     messageHandlerStats.updateResponseCount << "] DELETE req/resp[" << messageHandlerStats.deleteRequestCount << "/" <<
                     messageHandlerStats.deleteResponseCount << "]");
        LOG4CXX_INFO(loggerGtpcParser, "Unmatched Sequence Numbers/Sessions: Create[" << messageHandlerStats.createResponseUnmatchedSeqCount
                     << "] Update[" << messageHandlerStats.updateResponseUnmatchedSeqCount << "/" << messageHandlerStats.updateRequestUnmatchedSession
                     << "] Delete[" << messageHandlerStats.deleteResponseUnmatchedSeqCount << "/" << messageHandlerStats.deleteRequestUnmatchedSession << "]");
        LOG4CXX_INFO(loggerGtpcParser, "Pending response messages: Create[" << messageHandlerStats.pendingCreateResponses << "] Update["
                     << messageHandlerStats.pendingUpdateResponses << "] Delete[" << messageHandlerStats.pendingDeleteResponses << "]");
        LOG4CXX_INFO(loggerGtpcParser, "Unmatched create requests [" << messageHandlerStats.unmatchedCreateRequests << "]");
        logSequenceStats();
        logGTPCMapStatistics();
        LOG4CXX_INFO(loggerGtpcParser, PacketCounter::getInstance());
        PacketCounter::getInstance()->clearCounters();
        messageHandlerStats.reset();
    }
}

void decodeMessage(unsigned char *data, int dataLength, DecodedMsg *message) {
    int pos = 0;

    while(pos < dataLength) {
        pos = DecodeIE(data, pos, dataLength, message);
    }
}

void processMessage(unsigned char *data, int dataLength, DecodedMsg *message) {
    switch(message->messageType) {
        case GTPMessageTypes::ECHO_REQUEST:
        case GTPMessageTypes::ECHO_RESPONSE:
        case GTPMessageTypes::VERSION_NOT_SUPPORTED:
        case GTPMessageTypes::SEND_ROUTING_FOR_QPRS_REQUEST:
        case GTPMessageTypes::SEND_ROUTING_FOR_QPRS_RESPONSE:
            break;

        case GTPMessageTypes::CREATE_PDP_CONTEXT_REQUEST:
            decodeMessage(data, dataLength, message);
            handleGTPV1CreatePDPContextRequest(message, messageHandlerStats);
            n_pdp_req++;
            break;

        case GTPMessageTypes::CREATE_PDP_CONTEXT_RESPONSE:
            decodeMessage(data, dataLength, message);
            handleGTPV1CreatePDPContextResponse(message, messageHandlerStats);
            n_pdp_resp++;
            break;

        case GTPMessageTypes::UPDATE_PDP_CONTEXT_REQUEST:
            decodeMessage(data, dataLength, message);
            handleGTPV1UpdatePDPContextRequest(message, messageHandlerStats);
            break;

        case GTPMessageTypes::UPDATE_PDP_CONTEXT_RESPONSE:
            decodeMessage(data, dataLength, message);
            handleGTPV1UpdatePDPContextResponse(message, messageHandlerStats);
            break;

        case GTPMessageTypes::DELETE_PDP_CONTEXT_REQUEST:
            decodeMessage(data, dataLength, message);
            handleGTPV1DeletePDPContextRequest(message, messageHandlerStats);
            break;

        case GTPMessageTypes::DELETE_PDP_CONTEXT_RESPONSE:
            decodeMessage(data, dataLength, message);
            handleGTPV1DeletePDPContextResponse(message, messageHandlerStats);
            break;

        default:
            LOG4CXX_DEBUG(loggerGtpcParser, "Undecoded message type: " << (unsigned int) message->messageType);
            //Michael 16_07_12
            break;
    }
}
