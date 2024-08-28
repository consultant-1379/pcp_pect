#ifndef CLASSIFY_H
# define CLASSIFY_H

#include <netinet/ip.h>
#include <pcap.h>
#include <log4cxx/logger.h>
#include "ipq_api.h"
#include "flow.h"
#include "flow.h"
#include "UE_map.hpp"
#include "packet_utils.h"
#include "clientfinder.hpp"
#include "packetloss3.h"
#include "service_provider.hpp"

extern log4cxx::LoggerPtr classify_logger;
extern const char* pcp_version;
/*
 * Wrapper for the classifier.  The classify data is stored as an
 * incomplete type so that it is agnostic about the underlying
 * classification engine.
 */
typedef struct classify_data_struct *classify_data;
#define UA_MAX_LENGTH 2048


struct classify_data_struct {
    char *uaBuffer;
    ClientFinder *clientFinder;
    struct ipoque_detection_module_struct *ipq;
    struct timeorderedhash *connection_toh;	// Flow hash table
    struct timeorderedhash *subscriber_toh;	 //Subscriber [data] hash table
    unsigned int ipoqueTOHTotalSlotSize;  //total slot size of time order hash
    unsigned int ipoqueFlowSize;
    u32 ipqNormalConnectionTimeout;
    u32 ipqShortConnectionTimeout;
    u32 ipqLongConnectionTimeout;
    
    size_t flowsLastProduced; // The last ROP boundary at which we produced flows

    PectIP4Tuple fourTuple;  //needed for LLMNR protocol
};

struct HashTableTimeoutClassStruct {
    unsigned long shortTimeoutClass;
    unsigned long mediumTimeoutClass;
    unsigned long longTimeoutClass;
    unsigned long unknownTimeoutclass;

    void reset() {
        shortTimeoutClass = 0;
        mediumTimeoutClass = 0;
        longTimeoutClass = 0;
        unknownTimeoutclass = 0;
    }
};
struct cdpTimers {
    unsigned long long cumulativeTime[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numPacketsChecked[MAX_NUM_FLOWS_SUPPORTED];
    int queueNum;
    unsigned long long numberOfFlowsChecked[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numberOfFlowsMatched[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numberOfFlowsNeedNextPkt[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numberOfFlowsExcluded[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numberOfFlowsHTTPExcluded[MAX_NUM_FLOWS_SUPPORTED];

    void reset() {
        for(int i = 0; i < MAX_NUM_FLOWS_SUPPORTED; i++) {
            cumulativeTime[i] = 0;
            numPacketsChecked[i] = 0;
            numberOfFlowsChecked[i] = 0;
            numberOfFlowsMatched[i] = 0;
            numberOfFlowsNeedNextPkt[i] = 0;
            numberOfFlowsExcluded[i] = 0;
            numberOfFlowsHTTPExcluded[i] = 0;
        }
    }

};

struct cdpLlmnrDataStruct {
    struct cdpTimers *ptrToCdpTimersStruct;
    struct PectIP4Tuple *ptrToPectIP4TupleStruct;
};


struct cdpHostDataStruct {
    struct cdpTimers *ptrToCdpTimersStruct;
    struct flow_data *ptrToFlowDataStruct;
    
    int cdpType;

    const char **ptrtoCDP_HTTP_DEFAULT;
    const char **ptrtoCDP_HTTP;
    const char **ptrtoCDP_HTTP_USER_AGENT;
    const char **ptrtoCDP_HTTP_URL;


    int iCDP_HTTP_DEFAULT_SIZE;
    int iCDP_HTTP_SIZE;
    int iCDP_HTTP_USER_AGENT_SIZE;
    int iCDP_HTTP_URL_SIZE;

    std::vector<size_t> *ptrtoCDP_HTTP_DEFAULT_LEN;
    std::vector<size_t> *ptrtoCDP_HTTP_LEN;
    std::vector<size_t> *ptrtoCDP_HTTP_USER_AGENT_LEN;
    std::vector<size_t> *ptrtoCDP_HTTP_URL_LEN;
};

struct HashTableStatisticsStruct {
    unsigned long numFlowsToBeRemoved[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numFlowsAdded[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsAddedThisROP[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numFlowsToBeRemovedThisROP[MAX_NUM_FLOWS_SUPPORTED];
    
    unsigned long numFlowsNotInitializedByPacketLoss[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long totalFlowsThisQueuePacketLoss[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsPktLoss_UE[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsPktLoss_INET[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsNoPktLossRate_UE[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsNoPktLossRate_INET[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsHttpNoHostName[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long totalNumNewFlows[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsHttpHostName[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsHttpDependentHostName[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long numFlowsNonHttpNoHostName[MAX_NUM_FLOWS_SUPPORTED];
    
    unsigned long long totalNumPackets_source[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numPacketsFragmented_L1_source[MAX_NUM_FLOWS_SUPPORTED];
    unsigned long long numPacketsFragmented_L2_source[MAX_NUM_FLOWS_SUPPORTED];
    
    

    void reset() {


        for(int i = 0; i < MAX_NUM_FLOWS_SUPPORTED; i++) {
			numFlowsToBeRemoved[i] = 0;
			numFlowsAdded[i] = 0;
			numFlowsAddedThisROP[i] = 0;
			numFlowsToBeRemovedThisROP[i] = 0;
            numFlowsNotInitializedByPacketLoss[i] = 0;
            totalFlowsThisQueuePacketLoss[i] = 0;
            numFlowsNoPktLossRate_INET[i] = 0;
            numFlowsNoPktLossRate_UE[i] = 0;
            numFlowsPktLoss_INET[i] = 0;
            numFlowsPktLoss_UE[i] = 0;
            numFlowsHttpNoHostName[i] = 0;
            totalNumNewFlows[i] = 0;
            numFlowsHttpHostName[i] = 0;
            numFlowsHttpDependentHostName[i] = 0;
            numFlowsNonHttpNoHostName[i] = 0;
            
            totalNumPackets_source[i] = 0;
            numPacketsFragmented_L1_source[i] = 0;
            numPacketsFragmented_L2_source[i] = 0;
        }
    }

    void resetPktLossCounters() {
        for(int i = 0; i < MAX_NUM_FLOWS_SUPPORTED; i++) {
            numFlowsNoPktLossRate_INET[i] = 0;
            numFlowsNoPktLossRate_UE[i] = 0;
            numFlowsPktLoss_INET[i] = 0;
            numFlowsPktLoss_UE[i] = 0;
        }
    }
    
    void resetFragCounters() {
		 for(int i = 0; i < MAX_NUM_FLOWS_SUPPORTED; i++) {
            totalNumPackets_source[i] = 0;
            numPacketsFragmented_L1_source[i] = 0;
            numPacketsFragmented_L2_source[i] = 0;
		}
	}
} ;


classify_data classify_start(int pktbufNu, ServiceProvider *serviceProvider);

void classify_end(classify_data cd, unsigned int pbNum);

void classify(classify_data cd, int queue_num, const struct PectPacketHeader *h, const u_char *bytes, ServiceProvider *serviceProvider);


//int toh_timout_cleanUp_UEFlowMap_findUEIPinMAP(struct flow_data *fd);
int toh_timout_cleanUp_UEFlowMap_checkFlowRemoved(struct flow_data *fd, FlowList_t *RemoveFromMap, int mapRemoved);
//int toh_timout_cleanUp_UEFlowMap_removeFlows(struct flow_data *fd, FlowList_t *RemoveFromMap, struct in_addr *ueip, UEFlowMap_t::iterator *UE_it);
void toh_timout_cleanUp_UEFlowMap_printAddresses(struct ipoque_unique_flow_struct *unique_flow, struct flow_data *fd);
void toh_timout_cleanUp_UEFlowMap_printFlowInfo(u8 *unique_buf, struct ipoque_unique_flow_struct *unique_flow);
void toh_timout_cleanUp_UEFlowMap_printFlowDataInfo(struct flow_data *fd);
void incrementFlowCounters(struct ipoque_detection_module_struct *ipqStruct, int queue_num, u8 new_element, flow_data *flow_data, unsigned int protocol, unsigned int application, unsigned int sub_protocol,
                           u_int32_t theIPForHashSearch, const struct PectPacketHeader *pectHeader, const PacketDirection_t direction,
                           const struct flow_latency_struct *latency, int *checkServiceProvider);
void classifyPrintLog(void);
void clearFlowCounters(void);
void clearTimeoutClassCounters(void);
void hashTableRemovalReason(char *hashTableType, timeorderedhash *hashTable);
void flowTimeoutClass(classify_data cd);
void calculateBoundryTime(double *theTime,  unsigned long long *ropBoundryTime);
void extractUriExtension(classify_data cd, flow_data *flow_data);
void extractDataReceived(classify_data cd, flow_data *flow_data, bool isTcpPacket);
void getIpoquePaceVersion(ipoque_pace_version_t *paceVersion);
void getIpoquePaceAPIVersion(ipoque_pace_api_version_t *paceApiVersion);
void printNoPacketLossRateStats();
void clearFlowTimeoutClassStats();
void helper_print_packet_details_and_flow_details (const struct iphdr *iph_L1, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, struct flow_data *flow_data, struct ipoque_flow_struct *flow, classify_data cd, int print_packet) ;
void test_flowID_intergity_header();
void getIP_dotDecimal_from_host_format_ip_u32(u32 host_ip, char* ip_str, int len);
void getIP_dotDecimal_from_netwok_format_ip_long(u32 ip_long, char* ip_str, int len);
void printUniqueFlow(struct ipoque_unique_flow_struct *unique_flow, const char* msg, char* outBuf, int outBufSize) ;
void printHashFiveTuple(classify_data cd, uint32_t ip, const char* msg, char* outBuf, int outBufSize,  struct ipoque_flow_struct *flow, struct ipoque_unique_flow_struct *unique_flow);
void dump_hash_table(classify_data cd);
void test_flowID_intergity(classify_data cd, struct iphdr *iph_L1, u16 theSize, flow_data *flow_data, const struct PectPacketHeader *pectHeader,  u8 *new_flow, struct ipoque_flow_struct *flow) ;
void helper_print_packet_details_and_flow_details_to_log (const struct iphdr *iph_L1, const struct pcap_pkthdr *header, const u_char *packet, const struct PectPacketHeader *pectHeader, struct flow_data *flow_data, struct ipoque_flow_struct *flow, classify_data cd, int print_packet) ;
//void checkIpoquePaceLicense(classify_data cd, enum ipoque_pace_licensing_loading_result *res);

#endif
