/*
 * Classify_unit_test.cc
 *
 *  Created on: 14 Mar 2013
 *      Author: efitleo
 */

// System Includes
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <pcap.h>

#include "Classify_unit_test.hpp"

// Test files includes
#include "classify.h"
#include "packet_utils.h"


#include <pcap.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#define IPQ_TICK_RESOLUTION			(1000)
#define CAAP_MAX_PROTOCOLS (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 32)
// Ignore the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"

static u32 _size_flow_struct = 0;
static u32 _real_size_flow_struct = 0;
static u32 _flow_data_offset = 0;
static u64 ipq_hash_size = 1000 * 1024 * 1024; //1GB
static u32 ipq_tick_resolution = 1000;
static u32 ipq_connection_timeout = 20; // seconds for testing
static u32 _size_id_struct = 0;
static u64 protocol_counters[CAAP_MAX_PROTOCOLS + 1];
extern struct EArgs evaluatedArguments;


/* variables needed for libpcap */
pcap_t *_pcap_handle = NULL;
char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
// NOTE This will cause SEG Fualt.. don't use hard coded file names..
const char *_pcap_file = "/mnt/storage/pcapFiles/stream28_23032012_1K_packets.pcap";
int _pcap_datalink_type = 0;

extern HashTableStatisticsStruct hashTableCtrs;
extern HashTableTimeoutClassStruct hashTimeoutClass;

classify_data testCd;
//extern unsigned ipq_connection_timeout_value;

static void testUtilsFree32bitSafe(void *ptr, void *userptr) {
    free(ptr);
}

static void *teatUtilsClassifyTohMalloc(unsigned long size, void *uheap) {
    void *ret;
    ret = malloc((size_t) size);
    return ret;
}

static void *testUtilsClassifymalloc(unsigned long size) {
    void *ret;
    ret = malloc((size_t) size);
    return ret;
}

static void testUtilsInitFlowHashTable(classify_data cd) {
    _real_size_flow_struct = ipoque_pace_get_sizeof_flow_data(cd->ipq);
    _size_flow_struct = _real_size_flow_struct + (int) sizeof(struct flow_data);
    _flow_data_offset = _real_size_flow_struct;
    cd->connection_toh = ipoque_to_hash_create2(ipq_hash_size, _size_flow_struct,
                         sizeof(struct ipoque_unique_flow_struct), ipq_connection_timeout * ipq_tick_resolution, NULL, NULL,
                         teatUtilsClassifyTohMalloc, testUtilsFree32bitSafe, NULL);

    if(cd->connection_toh == NULL) {
        FAILM("ipoque_init_detection_module connection_toh [Flow]  malloc failed.");
    }
}

static void testUtilsinitSubscriberHashTable(classify_data cd) {
    _size_id_struct = ipoque_pace_get_sizeof_id_data(cd->ipq);
    cd->subscriber_toh = ipoque_to_hash_create2(ipq_hash_size, _size_id_struct, sizeof(u32),
                         ipq_connection_timeout * ipq_tick_resolution, NULL, NULL, teatUtilsClassifyTohMalloc,
                         testUtilsFree32bitSafe, NULL);

    if(cd->subscriber_toh == NULL) {
        FAILM("ipoque_init_detection_module subscriber_toh  malloc failed.");
    }
}

classify_data testUtilsClassifyStart(void) {
    classify_data cd;
    IPOQUE_PROTOCOL_BITMASK protocols;
    cd = (struct classify_data_struct *) calloc(1, sizeof(struct classify_data_struct));
    _size_id_struct = ipoque_pace_get_sizeof_id_data(cd->ipq);
    cd->ipq = ipoque_init_detection_module(IPQ_TICK_RESOLUTION, testUtilsClassifymalloc, 0);
    cd->ue_Map_Classification = new UEFlowMap_t();
    ipoque_set_rdt_correlation(cd->ipq, 1);
    IPOQUE_BITMASK_SET_ALL(protocols);
    // TODO: be a bit more choosy about these!
    ipoque_set_protocol_detection_bitmask2(cd->ipq, &protocols);
    ipoque_set_plain_tunnel_decapsulation_level(cd->ipq, 50);
    testUtilsInitFlowHashTable(cd);
    testUtilsinitSubscriberHashTable(cd);
    bzero(protocol_counters, (CAAP_MAX_PROTOCOLS + 1) * sizeof(u64));
    clearFlowCounters();
    clearTimeoutClassCounters();
    return (cd);
}

void testClearFlowCountersClassify() {
    hashTableCtrs.lastNumberFlowsAdded = 1;
    hashTableCtrs.numFlowsActuallyRemoved = 1;
    hashTableCtrs.numFlowsAdded = 1;
    hashTableCtrs.numFlowsToBeRemoved = 1;
    ASSERTM("\nTest Flow Counter : lastNumberFlowsAdded should be 1 ", hashTableCtrs.lastNumberFlowsAdded == 1);
    ASSERTM("\nTest Flow Counter : numFlowsActuallyRemoved should be 1 ", hashTableCtrs.numFlowsActuallyRemoved == 1);
    ASSERTM("\nTest Flow Counter : numFlowsAdded should be 1 ", hashTableCtrs.numFlowsAdded == 1);
    ASSERTM("\nTest Flow Counter : numFlowsToBeRemoved should be 1 ", hashTableCtrs.numFlowsToBeRemoved == 1);
    clearFlowCounters();
    ASSERTM("\nTest Flow Counter cleared : lastNumberFlowsAdded should be 0 ", hashTableCtrs.lastNumberFlowsAdded == 0);
    ASSERTM("\nTest Flow Counter cleared : numFlowsActuallyRemoved should be 0 ",
            hashTableCtrs.numFlowsActuallyRemoved == 0);
    ASSERTM("\nTest Flow Counter cleared : numFlowsAdded should be 0 ", hashTableCtrs.numFlowsAdded == 0);
    ASSERTM("\nTest Flow Counter cleared : numFlowsToBeRemoved should be 0 ", hashTableCtrs.numFlowsToBeRemoved == 0);
}

void testGetPortNumberHeadingToUE() {
    char ip[] = "\x45\x00\x00\x34\x23\x9e\x40\x00\x40\x06\xaa\xa3\xc0\xa8\x00\x0c\x4a\x7d\x61\x51\xd0\x8b\x00\x50\x71\xa9\x12\x67\x9e\x41\x38\x20\x80\x10\x20\x22\x8b\xec\x00\x00\x01\x01\x08\x0a\x02\x8f\x4a\x19\x77\x63\x6e\xd2";
    iphdr *ipHeader = (iphdr *) ip;
    PectPacketHeader pectHeader;
    unsigned int ipPacketLength =  52;
    parseLayer4Info(HEADING_TO_USER_EQUIPMENT, ipHeader, &pectHeader, ipPacketLength);
    ASSERTM("ue port number should be 80", pectHeader.fourTuple.uePort == 80);
    ASSERTM("dst port number should be 53387", pectHeader.fourTuple.serverPort == 53387);
}

void testGetPortNumberHeadingToInternet() {
    char ip[] = "\x45\x00\x00\x34\x23\x9e\x40\x00\x40\x06\xaa\xa3\xc0\xa8\x00\x0c\x4a\x7d\x61\x51\xd0\x8b\x00\x50\x71\xa9\x12\x67\x9e\x41\x38\x20\x80\x10\x20\x22\x8b\xec\x00\x00\x01\x01\x08\x0a\x02\x8f\x4a\x19\x77\x63\x6e\xd2";
    iphdr *ipHeader = (iphdr *) ip;
    PectPacketHeader pectHeader;
    bool isTcpPacket;
    unsigned int ipPacketLength =  52;
    parseLayer4Info(HEADING_TO_INTERNET, ipHeader, &pectHeader, ipPacketLength);
    ASSERTM("ue port number should be 53387", pectHeader.fourTuple.uePort == 53387);
    ASSERTM("dst port number should be 80", pectHeader.fourTuple.serverPort == 80);
}

void testIsTcpPacket_True() {
    //                                  Protocol field v
    char ip[] = "\x45\x00\x00\x34\x23\x9e\x40\x00\x40\x06\xaa\xa3\xc0\xa8\x00\x0c\x4a\x7d\x61\x51\xd0\x8b\x00\x50\x71\xa9\x12\x67\x9e\x41\x38\x20\x80\x10\x20\x22\x8b\xec\x00\x00\x01\x01\x08\x0a\x02\x8f\x4a\x19\x77\x63\x6e\xd2";
    iphdr *ipHeader = (iphdr *) ip;
    PectPacketHeader pectHeader;
    unsigned short int uePort, serverPort;
    bool isTcpPacket;
    unsigned int ipPacketLength =  52;
    parseLayer4Info(HEADING_TO_INTERNET, ipHeader, &pectHeader, ipPacketLength);
    ASSERTM("The packet should be a TCP packet.", pectHeader.isTcpPacket == true);
}

void testIsTcpPacket_False() {
    //                                  Protocol field v
    char ip[] = "\x45\x00\x00\x34\x23\x9e\x40\x00\x40\x11\xaa\xa3\xc0\xa8\x00\x0c\x4a\x7d\x61\x51\xd0\x8b\x00\x50\x71\xa9\x12\x67\x9e\x41\x38\x20\x80\x10\x20\x22\x8b\xec\x00\x00\x01\x01\x08\x0a\x02\x8f\x4a\x19\x77\x63\x6e\xd2";
    iphdr *ipHeader = (iphdr *) ip;
    PectPacketHeader pectHeader;
    bool isTcpPacket;
    unsigned int ipPacketLength =  52;
    parseLayer4Info(HEADING_TO_INTERNET, ipHeader, &pectHeader, ipPacketLength);
    ASSERTM("The packet should not be a TCP packet.", pectHeader.isTcpPacket == false);
}

void testIsTcpPacket_False_NotTcpOrUDP() {
    //                                  Protocol field v
    char ip[] = "\x45\x00\x00\x34\x23\x9e\x40\x00\x40\xaa\xaa\xa3\xc0\xa8\x00\x0c\x4a\x7d\x61\x51\xd0\x8b\x00\x50\x71\xa9\x12\x67\x9e\x41\x38\x20\x80\x10\x20\x22\x8b\xec\x00\x00\x01\x01\x08\x0a\x02\x8f\x4a\x19\x77\x63\x6e\xd2";
    iphdr *ipHeader = (iphdr *) ip;
    PectPacketHeader pectHeader;
    bool isTcpPacket;
    unsigned int ipPacketLength =  52;
    parseLayer4Info(HEADING_TO_INTERNET, ipHeader, &pectHeader, ipPacketLength);
    ASSERTM("The packet should not be a TCP packet.", pectHeader.isTcpPacket == false);
}


void testClearTimeoutClassCounters() {
    hashTimeoutClass.shortTimeoutClass = 1;
    hashTimeoutClass.mediumTimeoutClass = 1;
    hashTimeoutClass.longTimeoutClass = 1;
    hashTimeoutClass.unknownTimeoutclass = 1;
    ASSERTM("\nTest Timeout Class Counter : shortTimeoutClass should be 1 ", hashTimeoutClass.shortTimeoutClass == 1);
    ASSERTM("\nTest Timeout Class Counter : mediumTimeoutClass should be 1 ", hashTimeoutClass.mediumTimeoutClass == 1);
    ASSERTM("\nTest Timeout Class Counter : longTimeoutClass should be 1 ", hashTimeoutClass.longTimeoutClass == 1);
    ASSERTM("\nTest Timeout Class Counter : unknownTimeoutclass should be 1 ",
            hashTimeoutClass.unknownTimeoutclass == 1);
    clearTimeoutClassCounters();
    ASSERTM("\nTest Timeout Class Counter cleared : shortTimeoutClass should be 0 ",
            hashTimeoutClass.shortTimeoutClass == 0);
    ASSERTM("\nTest Timeout Class Counter cleared : mediumTimeoutClass should be 0 ",
            hashTimeoutClass.mediumTimeoutClass == 0);
    ASSERTM("\nTest Timeout Class Counter cleared : longTimeoutClass should be 0 ",
            hashTimeoutClass.longTimeoutClass == 0);
    ASSERTM("\nTest Timeout Class Counter cleared : unknownTimeoutclass should be 0 ",
            hashTimeoutClass.unknownTimeoutclass == 0);
}

// FUNCTION NOT USED: HERE For Future development
/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
void my_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int count = 1;
    fprintf(stdout, "%d, ", count);

    if(count == 4) {
        fprintf(stdout, "Come on baby sayyy you love me!!! ");
    }

    if(count == 7) {
        fprintf(stdout, "Tiiimmmeesss!! ");
    }

    fflush(stdout);
    count++;
}

// FUNCTION NOT USED: HERE For Future development
int testUtilsprocessPcap(int numPkts) {
    int i;
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    const u_char *packet;
    struct pcap_pkthdr hdr; /* pcap.h */
    struct ether_header *eptr; /* net/ethernet.h */
    /* open device for reading */
    // NOTE This will cause SEG Fualt.. don't use hard coded file names..
    char *_pcapFile = "stream28_23032012_1K_packets.pcap";
    descr = pcap_open_offline(_pcapFile, errbuf);

    if(descr == NULL) {
        printf("Cant open File \n");
        exit(1);
    }

    /* allright here we call pcap_loop(..) and pass in our callback function */
    /* int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)*/
    /* If you are wondering what the user argument is all about, so am I!!   */
    pcap_loop(descr, numPkts, my_callback, NULL);
    fprintf(stdout, "\nDone processing packets... wheew!\n");
    return 0;
}

void testUtilsFlowTimeoutClass(int TimeoutClassType) {
    struct timeval now;
    gettimeofday(&now, NULL);
    testCd = testUtilsClassifyStart();
    //testUtilsprocessPcap(7);

    if(TimeoutClassType == 1) {
        flowTimeoutClass(testCd);
        ASSERTM("\nTest Flow Timeout Class : mediumTimeoutClass should be 1 ",
                hashTimeoutClass.mediumTimeoutClass == 1);
        flowTimeoutClass(testCd);
        ASSERTM("\nTest Flow Timeout Class : mediumTimeoutClass should be 2 ",
                hashTimeoutClass.mediumTimeoutClass == 2);
    }

    if(TimeoutClassType == 2) {
        flowTimeoutClass(testCd);
        ASSERTM("\nTest Flow Timeout Class : shortTimeoutClass should be 0 ", hashTimeoutClass.shortTimeoutClass == 0);
    }

    if(TimeoutClassType == 3) {
        flowTimeoutClass(testCd);
        ASSERTM("\nTest Flow Timeout Class : longTimeoutClass should be 0 ", hashTimeoutClass.longTimeoutClass == 0);
    }

    if(TimeoutClassType == 4) {
        flowTimeoutClass(testCd);
        ASSERTM("\nTest Flow Timeout Class : unknownTimeoutclass should be 0 ",
                hashTimeoutClass.unknownTimeoutclass == 0);
    }

    //printf("hashTimeoutClass.shortTimeoutClass = %lu \n", hashTimeoutClass.shortTimeoutClass);
    //printf("hashTimeoutClass.mediumTimeoutClass = %lu \n", hashTimeoutClass.mediumTimeoutClass);
    //printf("hashTimeoutClass.longTimeoutClass = %lu  \n", hashTimeoutClass.longTimeoutClass);
    //printf("hashTimeoutClass.unknownTimeoutclass = %lu \n", hashTimeoutClass.unknownTimeoutclass);
}

void testFlowTimeoutClass() {
    //had plans to open pcap files and test this better, but for some reason I can't get pcap_loop call back to work..
    //pcap_loop call back works ok if not in unit test?
    testUtilsFlowTimeoutClass(1);
    testUtilsFlowTimeoutClass(2);
    testUtilsFlowTimeoutClass(3);
    testUtilsFlowTimeoutClass(4);
}

void testIncrementFlowCountersPacketCount() {
    UEFlowMap_t flowMap;
    flow_data testFlowData;
    PectPacketHeader *pectHeader = new PectPacketHeader();
    struct pcap_pkthdr header;
    header.caplen = 8765;
    memcpy(&(pectHeader->pcapHeader), &header , sizeof(pcap_pkthdr));
    testFlowData.init();
    testFlowData.packetsDown = 0;
    testFlowData.packetsUp = 0;
    struct flow_latency_struct latency;
    latency.diff_syn_synack_possible = 1;
    latency.diff_syn_synack = 10;
    latency.diff_synack_ack_possible = 1;
    latency.diff_synack_ack = 20;
    incrementFlowCounters(1, 1, &testFlowData, 10, 123543, pectHeader, HEADING_TO_INTERNET, &latency, &flowMap);
    stringstream s;
    s << "Upstream packet counter not incremented; Upstream count: " << testFlowData.packetsUp
      << " (Expected 1) Downstream count: " << testFlowData.packetsDown << " (Expected 0)";
    ASSERTM(s.str().c_str(), testFlowData.packetsUp == 1);
    incrementFlowCounters(1, 0, &testFlowData, 10, 123543, pectHeader, HEADING_TO_USER_EQUIPMENT, &latency, &flowMap);
    s.clear();
    s << "Downstream packet counter not incremented correctly; Upstream count: " << testFlowData.packetsUp
      << " (Expected 1) Downstream count: " << testFlowData.packetsDown << " (Expected 1)";
    ASSERTM(s.str().c_str(), testFlowData.packetsDown == 1);
}

void testIncrementFlowCountersTimestampInOrderPackets() {
    struct flow_latency_struct latency;
    latency.diff_syn_synack_possible = 1;
    latency.diff_syn_synack = 10;
    latency.diff_synack_ack_possible = 1;
    latency.diff_synack_ack = 20;
    UEFlowMap_t flowMap;
    flow_data testFlowData;
    pcap_pkthdr header;
    PectPacketHeader *pectHeader = new PectPacketHeader();
    testFlowData.init();
    header.ts.tv_sec = 123;
    header.ts.tv_usec = 987;
    memcpy(&(pectHeader->pcapHeader), &header , sizeof(pcap_pkthdr));
    incrementFlowCounters(1, 1, &testFlowData, 10, 123543, pectHeader, HEADING_TO_INTERNET, &latency, &flowMap);
    double firstPacketTime = (double) header.ts.tv_sec + (double) header.ts.tv_usec / 1e6;
    stringstream s;
    s << "Expected: firstPacket=" << firstPacketTime << " lastPacketTime=" << firstPacketTime << " Actual: firstPacketTime=" << testFlowData.firstPacketTime << " lastPacketTime=" << testFlowData.lastPacketTime << endl;
    ASSERTM(s.str().c_str(), testFlowData.firstPacketTime == firstPacketTime && testFlowData.lastPacketTime == firstPacketTime);
    header.ts.tv_sec = 345;
    header.ts.tv_usec = 876;
    memcpy(&(pectHeader->pcapHeader), &header , sizeof(pcap_pkthdr));
    incrementFlowCounters(1, 0, &testFlowData, 10, 123543, pectHeader, HEADING_TO_INTERNET, &latency, &flowMap);
    double lastPacketTime = (double) header.ts.tv_sec + (double) header.ts.tv_usec / 1e6;
    s.clear();
    s << "Expected: firstPacket=" << firstPacketTime << " lastPacketTime=" << lastPacketTime << " Actual: firstPacketTime=" << testFlowData.firstPacketTime << " lastPacketTime=" << testFlowData.lastPacketTime << endl;
    ASSERTM(s.str().c_str(), testFlowData.firstPacketTime == firstPacketTime && testFlowData.lastPacketTime == lastPacketTime);
}

void testIncrementFlowCountersTimestampOutOfOrderPackets() {
    struct flow_latency_struct latency;
    latency.diff_syn_synack_possible = 1;
    latency.diff_syn_synack = 10;
    latency.diff_synack_ack_possible = 1;
    latency.diff_synack_ack = 20;
    UEFlowMap_t flowMap;
    flow_data testFlowData;
    pcap_pkthdr header;
    PectPacketHeader  *pectHeader = new PectPacketHeader();
    testFlowData.init();
    header.ts.tv_sec = 345;
    header.ts.tv_usec = 876;
    memcpy(&(pectHeader->pcapHeader), &header , sizeof(pcap_pkthdr));
    incrementFlowCounters(1, 1, &testFlowData, 10, 123543, pectHeader, HEADING_TO_INTERNET, &latency, &flowMap);
    double firstPacketTime = (double) header.ts.tv_sec + (double) header.ts.tv_usec / 1e6;
    stringstream s;
    s << "Expected: firstPacket=" << firstPacketTime << " lastPacketTime=" << firstPacketTime << " Actual: firstPacketTime=" << testFlowData.firstPacketTime << " lastPacketTime=" << testFlowData.lastPacketTime << endl;
    ASSERTM(s.str().c_str(), testFlowData.firstPacketTime == firstPacketTime && testFlowData.lastPacketTime == firstPacketTime);
    header.ts.tv_sec = 123;
    header.ts.tv_usec = 987;
    memcpy(&(pectHeader->pcapHeader), &header , sizeof(pcap_pkthdr));
    incrementFlowCounters(1, 0, &testFlowData, 10, 123543, pectHeader, HEADING_TO_INTERNET, &latency, &flowMap);
    double lastPacketTime = (double) header.ts.tv_sec + (double) header.ts.tv_usec / 1e6;
    s.clear();
    s << "Expected: firstPacket=" << lastPacketTime << " lastPacketTime=" << firstPacketTime << " Actual: firstPacketTime=" << testFlowData.firstPacketTime << " lastPacketTime=" << testFlowData.lastPacketTime << endl;
    ASSERTM(s.str().c_str(), testFlowData.firstPacketTime == lastPacketTime && testFlowData.lastPacketTime == firstPacketTime);
}

void testCalculateBoundryTime() {
    double myTime, expectedTime;
    myTime = 1367396554.24765;
    expectedTime = 1367396520;
    unsigned long long ropBoundryTime;
    calculateBoundryTime(&myTime, &ropBoundryTime);
    stringstream s;
    s << endl << "testCalculateBoundryTime: ROP Boundry calculation incorrect. Got " <<   ropBoundryTime << "Expected " << expectedTime ;
    ASSERTM(s.str().c_str() , (ropBoundryTime == 1367396520));
}

void testGetIpoquePaceVersion() {
    classify_data cd = testUtilsClassifyStart();
    ipoque_pace_version_t paceVersion;
    getIpoquePaceVersion(&paceVersion);
    string expectedVersion("1.47");
    unsigned int resData = expectedVersion.compare(string(paceVersion.version_string));
    stringstream s;
    s << endl << "testGetIpoquePaceVersion: Incorrect PACE Version Got " <<  string(paceVersion.version_string) << ": Expected " << expectedVersion ;
    ASSERTM(s.str().c_str(), resData == 0);
}

void testGetIpoquePaceAPIVersion() {
    classify_data cd = testUtilsClassifyStart();
    ipoque_pace_api_version_t paceApiVersion;
    getIpoquePaceAPIVersion(&paceApiVersion);
    u32 expectedVersion = 29;
    stringstream s;
    s << endl << "testGetIpoquePaceAPIVersion: Incorrect PACE API Version Got " <<  paceApiVersion.api_version << ": Expected " << expectedVersion ;
    ASSERTM(s.str().c_str(), expectedVersion == paceApiVersion.api_version);
}
/*
 * LICENSE CURRENTLTY DIACTIVATED
void testCheckIpoquePaceLicense() {
    classify_data cd = testUtilsClassifyStart();
    enum ipoque_pace_licensing_loading_result res = IPOQUE_LICENSE_LOAD_FAILED;
    //checkIpoquePaceLicense(cd, &res);
    //ASSERTM("LOADING LICENSE FAILED" , res == IPOQUE_LICENSE_LOAD_SUCCESS);
    evaluatedArguments.ipoquePaceLicenseFile = "/shared_app/ipoque_license/99999999999_atrcxb2313.lic";
    cout << "EXPECTING ERROR MESSAGE:- 'ERROR console - Problem Loading IPOQUE License; Contact your Administrator; See Log Files for more information' " << endl;
    checkIpoquePaceLicense(cd, &res);
    ASSERTM("LOADING LICENSE SHOULD HAVE FAILED; BUT PASSED" , res == IPOQUE_LICENSE_LOAD_FAILED);
}
*/

cute::suite runClassifySuite(cute::suite s) {
    // Add all tests under here.
    s.push_back(CUTE(testClearFlowCountersClassify));
    s.push_back(CUTE(testClearTimeoutClassCounters));
    s.push_back(CUTE(testFlowTimeoutClass));
    s.push_back(CUTE(testIncrementFlowCountersPacketCount));
    s.push_back(CUTE(testIncrementFlowCountersTimestampInOrderPackets));
    s.push_back(CUTE(testIncrementFlowCountersTimestampOutOfOrderPackets));
    s.push_back(CUTE(testGetPortNumberHeadingToUE));
    s.push_back(CUTE(testGetPortNumberHeadingToInternet));
    s.push_back(CUTE(testIsTcpPacket_True));
    s.push_back(CUTE(testIsTcpPacket_False));
    s.push_back(CUTE(testCalculateBoundryTime));
    s.push_back(CUTE(testGetIpoquePaceAPIVersion));
    s.push_back(CUTE(testGetIpoquePaceVersion));
    //s.push_back(CUTE(testCheckIpoquePaceLicense));
    s.push_back(CUTE(testIsTcpPacket_False_NotTcpOrUDP));
    // Add all tests above here.
    return s;
}

// Re-enable the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
