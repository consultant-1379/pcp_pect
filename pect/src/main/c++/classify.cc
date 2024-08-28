#include "classify.h"
#include "clientfinder.hpp"
#include "flow.h"
#include "pect_file_writer.hpp"
#include "captool_file_writer.hpp"
#include "staple_file_writer.hpp"
#include "GTPv1_packetFields.h"
#include "gtp_ie_gtpv2.h"
#include "gtpv1_utils.h"
#include "ipq_api.h"
#include "logger.hpp"
#include "mutex.hpp"
#include "pcpglue.hpp"
#include "packet_utils.h"
#include "UE_map.hpp"
#include "file_writer_map.hpp"
#include "file_writer_map_manager.hpp"
#include "custom_protocols_and_groups.h"
#include "service_provider.hpp"


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
#define IPOQUE_TOH_QUEUE_MAX_LEN(toh) ipoque_to_hash_maximum_number_of_used_elements(toh)
#define IPQ_TICK_RESOLUTION			(1000000)
#define CAAP_MAX_PROTOCOLS (IPOQUE_MAX_SUPPORTED_PROTOCOLS + 32)
IPOQUE_PROTOCOL_BITMASK iptables_bm;

#define DEBUG   // TODO -- comment this out
#ifdef DEBUG
#define STRING(X)	#X
#define ASSERT(x) {if(!(x)) {fprintf(stderr, "Assert failed at %s:%d\n", __FILE__, __LINE__); exit(255);}}
#else
#define ASSERT(x)
#endif
#define rdtscl(low) __asm__ __volatile__("rdtsc" : "=a" (low) : : "edx")

static u32 _size_flow_struct = 0;
static u32 _real_size_flow_struct = 0;
u32 _flow_data_offset = 0;
//static u64 ipq_hash_size = (u64) 1900 * 1024 * 1024; //1.9G  should be 1M flows per classifier @flow struct size of 1384 + 372 = 1756 bytes (8 stream = 8.6 M FLows)
//static u64 ipq_hash_size = (u64) 2500 * 1024 * 1024; //2.5G  should be 1.4M flows per classifier @flow struct size of 1384 + 372 = 1756 bytes (8 stream = 11.2 M FLows)
//static u64 ipq_hash_size = (u64) 1400 * 1024 * 1024; // 1.4G  should be ~794K flows per classifier @flow struct size of 1384 + 372 = 1756 bytes (@ 16 stream = total 11.2 M FLows)
//static u64 ipq_hash_size = (u64) 2500 * 1024 * 1024; //2.5G  should be 1.4M flows per classifier @flow struct size of 1384 + 372 = 1756 bytes (8 streams = 11.2 M FLows; 16 streams 22.4M FLows)
//static u64 ipq_hash_size = (u64) 1900 * 1024 * 1024; //1.9G  should be 1M flows (1077835) per classifier @flow struct size of 1384 + 372 = 1756 bytes (8 stream = 8.6M FLows; 16 streams = 17.2M FLows)

static u64 ipq_hash_size = (u64) 3000 * 1024 * 1024; //3.0G  should be 1.7M flows per classifier @flow struct size of 1384 + 372 = 1756 bytes (8 streams = 13.6M Flows; 16 streams 27.3M FLows)

static u32 _size_id_struct = 0;
static u64 protocol_counters[CAAP_MAX_PROTOCOLS + 1];
static const char *IPOQUE_protocol_short_str[] = {IPOQUE_PROTOCOL_SHORT_STRING_CDP};

HashTableStatisticsStruct hashTableCtrs;
HashTableTimeoutClassStruct hashTimeoutClass;
pthread_mutex_t flowCountersMutex;
pthread_mutex_t packetLossMutex;
cdpTimers cdpAdvertsTimer, cdpMapsTimer, cdpNewsTimer, cdpPhotoTimer, cdpSWuTimer, cdpSpeedTimer, cdpWeatherTimer, cdpLlmnrTimer, cdpSimpleHostTimer[8];
int cdpTimersEnabled;
cdpLlmnrDataStruct cdpLlmnrData;
cdpHostDataStruct cdpAdvertsData, cdpMapsData, cdpNewsData, cdpPhotoData, cdpSWuData, cdpSpeedData, cdpWeatherData, cdpSimpleHostData[8];

int cdpNonDefaultArrayEnabled;
int cdpURLdecodeEnabled;
int cdpUserAgentDecodeEnabled;
int cdpHostDecodeDepth[IPOQUE_MAX_HTTP_CUSTOM_PROTOCOLS];
int pectFileOutputFormat_isPect;
const char *pcp_version = "45-A17";


// Shared objects
extern EArgs evaluatedArguments;
extern const unsigned short throughputThresholdFactor;
extern const unsigned long long throughputDefaultThreshold;


const char *CDP_SIMPLE_HOST[] = {
    "flurry.com\0",
    "andomedia.com\0",
    "admob.com\0",
    "symantecliveupdate.com\0",
    "McAfee AutoUpdate\0",
    "teamlava.com\0",
    "SpeedyShare\0",
    "Slacker\0"
};

// efitleo :  Multiple Timeout Queues
/**
 * Classify each flow into proposed different time out ranges.
 * (Using multiple timeout queues)
 * Return ; integer of the queue that it is classed to
 */
int getFlowTimeoutClass(classify_data cd, int queueNum) {
    ipoque_flow_timeout_class timoutclass = ipoque_pace_get_flow_timeout_class(cd->ipq);
    int timeoutClassNum = -1;

    switch(timoutclass) {
        case IPOQUE_SHORT_FLOW_TIMEOUT:
            ipoque_to_hash_set_timeout_queue(cd->connection_toh, 1);
            timeoutClassNum = 1;
            break;

        case IPOQUE_MEDIUM_FLOW_TIMEOUT:
            // uses default queue i.e. Zero (0)
            ipoque_to_hash_set_timeout_queue(cd->connection_toh, 0);
            timeoutClassNum = 0;
            break;

        case IPOQUE_LARGE_FLOW_TIMEOUT:
            ipoque_to_hash_set_timeout_queue(cd->connection_toh, 2);
            timeoutClassNum = 2;
            break;

        default:
            LOG4CXX_ERROR(loggerClassify, "TIMEOUT CLASS = UNKNOWN");
            timeoutClassNum = 3;
            break;
    }

    return timeoutClassNum;
}

static void *ipq_get_id(u8 *ip, u8 is_ip_v6, classify_data cd) {
    void *r;
    u8 new_entry = 0;

    if(cd->subscriber_toh == NULL) {
        LOG4CXX_WARN(loggerClassify, "Hash table is NULL when trying to get the ID.");
        return NULL;
    }

    if(is_ip_v6 != 0) {
        return NULL;
    } else {
        r = ipoque_to_hash_insert(cd->subscriber_toh, ip, &new_entry);
    }

    if(new_entry != 0) {
        bzero(r, _size_id_struct);
    }

    return r;
}

static void *classify_malloc(unsigned long size) {
    void *ret;
    ret = malloc((size_t) size);
    return ret;
}

static void *classify_toh_malloc(unsigned long size, void *uheap) {
    void *ret;
    ret = malloc((size_t) size);
    return ret;
}

static void classify_free(void *ptr) {
    free(ptr);
}


void cdpEndTimer(timespec *startTime, struct cdpTimers *cdpTimer, int matched) {
    if(cdpTimersEnabled) {
        timespec endTime;
        unsigned long long st, et;

        if(matched == 1) {
            cdpTimer->numberOfFlowsMatched[cdpTimer->queueNum]++;
        }

        if(matched == 2) {
            cdpTimer->numberOfFlowsNeedNextPkt[cdpTimer->queueNum]++;
        }

        if(matched == 3) {
            cdpTimer->numberOfFlowsHTTPExcluded[cdpTimer->queueNum]++;
        }

        if(matched == 4) {
            cdpTimer->numberOfFlowsExcluded[cdpTimer->queueNum]++;
        }

        int faultRes = clock_gettime(CLOCK_REALTIME, &endTime);

        if(faultRes) {
            LOG4CXX_ERROR(loggerPcpGlue, "CDP TIMERS : PROBLEM Getting Clock time Function result = " <<  faultRes);
            return;
        }

        st = startTime->tv_sec * 1000000000 + startTime->tv_nsec;
        et = endTime.tv_sec * 1000000000 + endTime.tv_nsec;
        cdpTimer->cumulativeTime[cdpTimer->queueNum]  += (et - st);
        //LOG4CXX_INFO(loggerPcpGlue, "CDP TIMERS : Queue = "  <<  cdpTimer->queueNum
        //<< " # Packets = " << cdpTimer->numPacketsChecked[cdpTimer->queueNum]
        //<< " Start Times Sec = " << startTime->tv_sec << " nSec = " << startTime->tv_nsec << " Full = " << st
        //<< " End Times Sec = " << endTime.tv_sec << " nSec = " << endTime.tv_nsec  << " Full = " << et
        //<< " diff nSec = " << (et -st)
        //<< " cdpTimer->cumulativeTime[cdpTimer->queueNum]  nSec = " << cdpTimer->cumulativeTime[cdpTimer->queueNum]);
    }
}
void cdpStartTimer(timespec *returnStartTime, struct cdpTimers *cdpTimer) {
    if(cdpTimersEnabled) {
        int faultRes = clock_gettime(CLOCK_REALTIME, returnStartTime);

        if(faultRes) {
            LOG4CXX_ERROR(loggerPcpGlue, "CDP TIMERS : PROBLEM Getting Clock time Function result = " <<  faultRes << ": Disabling CDP TIMERS");
            cdpTimersEnabled = 0;
        } else {
            cdpTimer->numPacketsChecked[cdpTimer->queueNum]++;
        }
    }
}
/*
 * Used by  toh_timout_cleanUp_UEFlowMap to print the FLow info in the unique_buf
 *
 */
void toh_timout_cleanUp_UEFlowMap_printFlowInfo(u8 *unique_buf, struct ipoque_unique_flow_struct *unique_flow) {
    LOG4CXX_TRACE(loggerClassify,
                  "toh_timout_cleanUp_UEFlowMap: FLOW (IP : PORT) Lower " << IPAddress(unique_flow->lower_ip) << " : " << ntohs(unique_flow->lower_port) << " -- " << " Upper " << IPAddress(unique_flow->upper_ip) << " : " << ntohs(unique_flow->upper_port) << " Protocol = " << unique_flow->protocol);
}

/*
 * Used by  toh_timout_cleanUp_UEFlowMap to print the FLow info in the user_buf
 *
 */
void toh_timout_cleanUp_UEFlowMap_printFlowDataInfo(struct flow_data *fd) {
    LOG4CXX_TRACE(loggerClassify,
                  "toh_timout_cleanUp_UEFlowMap: FLOW DATA INFO :- UEIP = " << IPAddress(fd->fourTuple.ueIP) << ": Protocol = " << fd->protocol);
}

/*
 * Used by  toh_timout_cleanUp_UEFlowMap to print the addresses of Flow and Flow_Data
 */
void toh_timout_cleanUp_UEFlowMap_printAddresses(struct ipoque_unique_flow_struct *unique_flow, struct flow_data *fd) {
    LOG4CXX_TRACE(loggerClassify,
                  "toh_timout_cleanUp_UEFlowMap: unique Flow Addr = " << hex << unique_flow << ", Flow data Addr [user] = " << hex << fd);
}


/*
 * This function is called by toh_timeout_callback each time a flow is removed from the ipoque flow hash map
 * It is passed in a reference  to the flow[called unique_buf] and to flow_data [called user_buf]
 * Strategy, is to :
 * a) For DEBUG, print information on the 5 tuple from the flow
 * b) For DEBUG, print the corresponding UEIP from the flow_data
 *    This is the UEIP of the flow_data to remove
 * c) Find a match for the UEIP in the ue_Map_Classification.
 *    ue_Map_Classification has ueip as key and a pointer to a list of struct flow_data* as a value
 * d) find a match for the address of  the flow data from the call back  to the flow data of each entry in the UE FLow MAP
 *    This is the flow that we have to remove
 * e) remove the required flow
 * f) check if the list of struct flow_data's is empty. If so then we can remove this key value pair from the ue_Map_Classification table.
 */
static void toh_timout_cleanUp_UEFlowMap(IPOQUE_TIMESTAMP_COUNTER_SIZE ts, u8 *unique_buf, u8 *user_buf,
        void *userdata) {
    struct ipoque_unique_flow_struct *unique_flow = (struct ipoque_unique_flow_struct *)((u8 *) unique_buf);
    struct flow_data *fd = (struct flow_data *)(((u8 *) user_buf) + _flow_data_offset);
    toh_timout_cleanUp_UEFlowMap_printFlowInfo(unique_buf, unique_flow);
    toh_timout_cleanUp_UEFlowMap_printFlowDataInfo(fd);
    toh_timout_cleanUp_UEFlowMap_printAddresses(unique_flow, fd);
    char testName[20] = "toh_timeout\0";

    if(fd->isTcpFlow == true) {
        if((loggerClassify->isTraceEnabled())) {
            printPktLossMapInfo_inet(fd, 0, testName,  fd->fourTuple);
            printPktLossMapInfo_ue(fd, 0, testName,  fd->fourTuple);
        }
    }

    // If its a TCP FLOW, then clean up the Sequence Maps
    if(fd->isTcpFlow == true) {
        // note, calling fd->tcpPktLossInfo.cleanupMaps() does not actually free the memory here. Not sure Why. Maybe a C vs C++ thing
        //       Whereby fd is initialised by malloc, which does not understand classes, and the method cleanupMaps is a class method
        //       So calling cleanupMaps() from the classify side means nothing, as the SeqNumber maps are pointing to NULL or something random.
        pktLossCleanupMaps(fd); // FREE does not call destructors

        if((loggerClassify->isTraceEnabled())) {
            if(fd->tcpPktLossInfo.expectedSeqNumReceived_inet != NULL) {
                printPktLossMapInfo_inet(fd, 1, testName,  fd->fourTuple);
            } else {
                LOG4CXX_INFO(loggerClassify, "PKT LOSS MAPS toh_timout :1 : fd->tcpPktLossInfo.expectedSeqNumReceived_inet = " << fd->tcpPktLossInfo.expectedSeqNumReceived_inet);
            }

            if(fd->tcpPktLossInfo.expectedSeqNumReceived_ue != NULL) {
                printPktLossMapInfo_ue(fd, 1, testName,  fd->fourTuple);
            } else {
                LOG4CXX_INFO(loggerClassify, "PKT LOSS MAPS toh_timout :1 : fd->tcpPktLossInfo.expectedSeqNumReceived_ue = " << fd->tcpPktLossInfo.expectedSeqNumReceived_ue);
            }
        }
    }
}

/*
 * This function is called by ipoque each time a flow is removed from the ipoque flow hash map
 * It is passed a reference  to the flow[called unique_buf] and to flow_data [called user_buf]
 *
 * Cleanup the ue_Map_Classification  here for entries that ipoque has removed from its MAPS due to timeout
 * Also TODO; do any flow statistics here.
 */
extern struct FileCounters pectFileCounters;
extern struct FileCounters captoolFileCounters;
extern struct FileCounters stapleFileCounters;

static void toh_timeout_callback(IPOQUE_TIMESTAMP_COUNTER_SIZE ts, u8 *unique_buf, u8 *user_buf, void *userdata) {
    struct flow_data *fd = (struct flow_data *)(((u8 *) user_buf) + _flow_data_offset);

    if(fd->queueNumber >= 0) {
        hashTableCtrs.numFlowsToBeRemoved[fd->queueNumber]++;
        hashTableCtrs.numFlowsToBeRemovedThisROP[fd->queueNumber]++;
    }

    //classify_data cdp = (classify_data) userdata;
    //hashTableRemovalReason("TIMOUT CALLBACK",cdp->connection_toh);
    if(fd->bytes >= evaluatedArguments.minFlowSize) {
        //if(evaluatedArguments.fileOutputFormat.compare("legacy") == 0) {  // string compare > 2M times per minute.. ouch
        if(!pectFileOutputFormat_isPect) {   // 0=Legacy 1=Pect
            captoolTimeoutFlowData(fd, captoolFileCounters);
            stapleTimeoutFlowData(fd, stapleFileCounters);
        } else {
            timeoutFlowData(fd, pectFileCounters);
        }
    }

    // Cleanup the map after we've handled the timeout
    toh_timout_cleanUp_UEFlowMap(ts, unique_buf, user_buf, userdata);
}

static void free_32bit_safe(void *ptr, void *userptr) {
    free(ptr);
}
//efitleo:  Multiple Timeout Queues
static void enable_multi_timeout(classify_data cd) {
    if(ipoque_to_hash_enable_multiple_timeout(cd->connection_toh, 3) != 0) {
        LOG4CXX_INFO(loggerClassify, "TIMEOUT: multi timeout initialization failed");
        exit(1);
    }

    if(ipoque_to_hash_set_timeout_ext(cd->connection_toh, cd->ipqShortConnectionTimeout, 1) != 0) {
        LOG4CXX_INFO(loggerClassify, "TIMEOUT: Setting Short Flow Timeout Failed: cd->ipqShortConnectionTimeout = " << cd->ipqShortConnectionTimeout);
        exit(1);
    }

    if(ipoque_to_hash_set_timeout_ext(cd->connection_toh, cd->ipqLongConnectionTimeout, 2) != 0) {
        LOG4CXX_INFO(loggerClassify, "TIMEOUT: Setting Long Flow Timeout Failed: cd->ipqLongConnectionTimeout = " << cd->ipqLongConnectionTimeout);
        exit(1);
    }
}

static void init_flow_hash_table(classify_data cd) {
    _real_size_flow_struct = ipoque_pace_get_sizeof_flow_data(cd->ipq) ;
    _size_flow_struct = _real_size_flow_struct + (int) sizeof(struct flow_data);
    _flow_data_offset = _real_size_flow_struct;
    cd->ipoqueFlowSize = _real_size_flow_struct;
    cd->ipoqueTOHTotalSlotSize = _size_flow_struct;
    cd->connection_toh = ipoque_to_hash_create2(ipq_hash_size, _size_flow_struct,
                         sizeof(struct ipoque_unique_flow_struct), cd->ipqNormalConnectionTimeout * IPQ_TICK_RESOLUTION,
                         toh_timeout_callback, cd, classify_toh_malloc, free_32bit_safe, NULL);

    if(cd->connection_toh == NULL) {
        LOG4CXX_FATAL(loggerClassify, "ipoque_init_detection_module connection_toh [Flow]  malloc failed.");
        exit(1);
    }

    //efitleo:  Multiple Timeout Queues
    enable_multi_timeout(cd);
}

static void init_subscriber_hash_table(classify_data cd) {
    _size_id_struct = ipoque_pace_get_sizeof_id_data(cd->ipq);
    cd->subscriber_toh = ipoque_to_hash_create2(ipq_hash_size, _size_id_struct, sizeof(u32),
                         cd->ipqNormalConnectionTimeout * IPQ_TICK_RESOLUTION, NULL, NULL, classify_toh_malloc, free_32bit_safe,
                         NULL);

    if(cd->subscriber_toh == NULL) {
        LOG4CXX_FATAL(loggerClassify, "ipoque_init_detection_module subscriber_toh  malloc failed.");
        exit(1);
    }
}

/*
 * Free up the memory used by Ipoques Pace at exit
 *
 */
static void free_ipoquePace_memory(classify_data cd) {
    /* free allocated memory in PACE */
    ipoque_exit_detection_module(cd->ipq, classify_free);
    /* clear and destroy connection tracking hash table */
    ipoque_to_hash_clear(cd->connection_toh);
    ipoque_to_hash_destroy2(cd->connection_toh);
    /* clear and destroy subscriber tracking hash table */
    ipoque_to_hash_clear(cd->subscriber_toh);
    ipoque_to_hash_destroy2(cd->subscriber_toh);
} /* pace_exit */


void clearFlowCounters() {
    pthread_mutex_lock(&flowCountersMutex);
    hashTableCtrs.reset();
    pthread_mutex_unlock(&flowCountersMutex);
}

void clearTimeoutClassCounters() {
    pthread_mutex_lock(&flowCountersMutex);
    hashTimeoutClass.reset();
    pthread_mutex_unlock(&flowCountersMutex);
}

/**
 * Classify each flow into proposed different time out ranges.
 *
 */
void flowTimeoutClass(classify_data cd) {
    ipoque_flow_timeout_class timoutclass = ipoque_pace_get_flow_timeout_class(cd->ipq);

    switch(timoutclass) {
        case IPOQUE_SHORT_FLOW_TIMEOUT:
            LOG4CXX_TRACE(loggerClassify, "TIMEOUT CLASS = IPOQUE_SHORT_FLOW_TIMEOUT");
            pthread_mutex_lock(&flowCountersMutex);
            hashTimeoutClass.shortTimeoutClass++;
            pthread_mutex_unlock(&flowCountersMutex);
            break;

        case IPOQUE_MEDIUM_FLOW_TIMEOUT:
            LOG4CXX_TRACE(loggerClassify, "TIMEOUT CLASS = IPOQUE_MEDIUM_FLOW_TIMEOUT");
            pthread_mutex_lock(&flowCountersMutex);
            hashTimeoutClass.mediumTimeoutClass++;
            pthread_mutex_unlock(&flowCountersMutex);
            break;

        case IPOQUE_LARGE_FLOW_TIMEOUT:
            LOG4CXX_TRACE(loggerClassify, "TIMEOUT CLASS = IPOQUE_LARGE_FLOW_TIMEOUT");
            pthread_mutex_lock(&flowCountersMutex);
            hashTimeoutClass.longTimeoutClass++;
            pthread_mutex_unlock(&flowCountersMutex);
            break;

        default:
            LOG4CXX_TRACE(loggerClassify, "TIMEOUT CLASS = UNKNOWN");
            pthread_mutex_lock(&flowCountersMutex);
            hashTimeoutClass.unknownTimeoutclass++;
            pthread_mutex_unlock(&flowCountersMutex);
            break;
    }
}



/**
 * Reason why last entry was removed from has table.
 *
 */
void hashTableRemovalReason(char *hashTableType, timeorderedhash *hashTable) {
    toh_removal_reason removalReason = ipoque_to_hash_get_last_removal_reason(hashTable);

    switch(removalReason) {
        case TOH_DELETED:
            LOG4CXX_TRACE(loggerClassify, hashTableType << "Removal reason for last remove operation = TOH_DELETED");
            break;

        case TOH_TIMEDOUT:
            LOG4CXX_TRACE(loggerClassify, hashTableType << "Removal reason for last remove operation = TOH_TIMEDOUT");
            break;

        case TOH_OVERFLOWED:
            LOG4CXX_TRACE(loggerClassify,
                          hashTableType << "Removal reason for last remove operation = TOH_OVERFLOWED");
            break;

        default:
            LOG4CXX_TRACE(loggerClassify, hashTableType << "Removal reason for last remove operation = UNKNOWN");
            break;
    }
}

/*
 * get the PACE Version
 *
 */
void getIpoquePaceVersion(ipoque_pace_version_t *paceVersion) {
    *paceVersion = ipoque_pace_get_version();
    LOG4CXX_DEBUG(loggerConsole, "Classification Engine Version [MAJOR.MINOR.PATCH]:" << paceVersion->version_string);
    LOG4CXX_INFO(loggerClassify, "Classification Engine Version [MAJOR.MINOR.PATCH]:" << paceVersion->version_string);
}

/*
 * get the PACE API Version
 *
 */
void getIpoquePaceAPIVersion(ipoque_pace_api_version_t *paceApiVersion) {
    *paceApiVersion = ipoque_pace_get_api_version();
    LOG4CXX_DEBUG(loggerConsole, "Classification Engine API Version :" << paceApiVersion->api_version);
    LOG4CXX_INFO(loggerClassify, "Classification Engine API Version :" << paceApiVersion->api_version);
}

/*
 * checks the IPoque License is working
 *
 * THIS IS CURRENTLY DEACITIVATED IN ORDER TO MAKE USE OF IPOQUE 1.45.1 mk2 TO HANDEL LICENSING WITH MAC ADDRESS ISSUES

void checkIpoquePaceLicense(classify_data cd, enum ipoque_pace_licensing_loading_result *res) {
    LOG4CXX_DEBUG(loggerConsole, "Loading Classification Engine License");
    LOG4CXX_INFO(loggerClassify, "Loading Classification Engine License");
    *res = ipoque_pace_load_license(cd->ipq, evaluatedArguments.ipoquePaceLicenseFile.c_str());

    if(*res != IPOQUE_LICENSE_LOAD_SUCCESS) {
        LOG4CXX_ERROR(loggerClassify, "Problem Loading Classification Engine License; Contact your Administrator");
        LOG4CXX_ERROR(loggerConsole, "Problem Loading Classification Engine License; Contact your Administrator; See Log Files for more information");
        const ipoque_pace_license_information_t *license_info;
        license_info = ipoque_pace_get_license_information(cd->ipq);
        LOG4CXX_ERROR(loggerClassify, "License initialisation error code: " << license_info->init_error_code);
        LOG4CXX_ERROR(loggerClassify, "License initialisation error reason: " << license_info->init_error_reason);
        LOG4CXX_ERROR(loggerClassify, "License load error code: " << license_info->load_error_code);
        LOG4CXX_ERROR(loggerClassify, "License load error reason: "  << license_info->load_error_reason);
        LOG4CXX_ERROR(loggerClassify, "License validation error code: " << license_info->validation_error_code);
        LOG4CXX_ERROR(loggerClassify, "License validation error reason: " << license_info->validation_error_reason);
        LOG4CXX_ERROR(loggerClassify, "License limitation error code: " << license_info->limitation_error_code);
        LOG4CXX_ERROR(loggerClassify, "License limitation error reason: " << license_info->limitation_error_reason);
        LOG4CXX_ERROR(loggerClassify, "Number of macaddresses found: " << license_info->no_of_mac_addresses_found);
        LOG4CXX_ERROR(loggerClassify, "Current bandwidth usage: " << license_info->current_percentage_bandwidth_limit_usage);
        LOG4CXX_ERROR(loggerClassify, "THE APPLICATION  WILL EXIT WITH IN ONE ROP PERIOD");
        LOG4CXX_ERROR(loggerConsole, "THE APPLICATION  WILL EXIT WITH IN ONE ROP PERIOD");
        evaluatedArguments.programTimeout = 20;
    }
}
*/
void getSubProtocolString(struct ipoque_detection_module_struct *ipqStruct, u16 theProtocol, u16 theSubProtocol, char *retValue) {
    if((pectFileOutputFormat_isPect) || (loggerCaptoolExtendedOutput->isDebugEnabled()))  {
        if((theSubProtocol == UINT_MAX) || (theSubProtocol > IPOQUE_MAX_SUPPORTED_SUB_PROTOCOLS)) {
            snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
        } else {
            const char *sp_str;
            sp_str = ipoque_pace_get_subprotocol_name(ipqStruct, theProtocol, theSubProtocol);

            if(sp_str != NULL) {
                snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%s", sp_str);
                retValue[MAX_SUB_PROTOCOL_STRING_LENGTH - 1] = '\0';
            } else {
                snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%u", theSubProtocol);
            }
        }
    } else {
        retValue = NULL;
    }
}
void debugPrintProtocolInfo(const char *theTitle, unsigned char *theName, u16 theName_len) {
    char buf[5000];
    strncpy(buf, (char *) theName, theName_len);
    buf[theName_len] = '\0';
    LOG4CXX_INFO(loggerClassify, "PROTOCOL :" << theTitle << " = " << buf << ": length = " << theName_len);
}
void debugPrintProtocolInfo(const char *theTitle, unsigned char *theName, u16 theName_len, unsigned int theProtocol) {
    char buf[5000];
    strncpy(buf, (char *) theName, theName_len);
    buf[theName_len] = '\0';
    LOG4CXX_INFO(loggerClassify, "PROTOCOL :" << theTitle << " = " << buf << ": length = " << theName_len << ": Protocol = " <<  IPOQUE_protocol_short_str[theProtocol]);
}
void debugPrintURLInfo(const char *theTitle, struct ipoque_detection_module_struct *ipoque_struct) {
    char buf[5000];
    unsigned char *url = NULL;
    u16 url_len = 0;
    /* get the HTTP URL information */
    ipoque_detection_get_http_request_url(ipoque_struct, &url, &url_len);

    /* if URL is available,  */
    if(url != NULL) {
        strncpy(buf, (char *) url, url_len);
        buf[url_len] = '\0';
        LOG4CXX_INFO(loggerClassify, "PROTOCOL :" << theTitle << " = " << buf << ": length = " << url_len);
    }
}

//efitleo: 23June14; EQEV-14220 ; updated to indicate the ue port need not be 5355 for LLMNR (just server port)
void debugPrintIPInfoLLMNR(const char *theTitle, const PectIP4Tuple *theFourTuple, uint32_t theIP, uint32_t theServerPort) {
    struct in_addr ueIPIn;
    struct in_addr serverIPIn;
    struct in_addr theMatchIP;
    ueIPIn.s_addr = htonl((theFourTuple->ueIP));
    serverIPIn.s_addr = htonl((theFourTuple->serverIP));
    theMatchIP.s_addr = htonl((theIP));
    char ueIPBuf[40];
    char serverIPBuf[40];
    char theIPBuf[40];
    inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
    inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
    inet_ntop(AF_INET, &theMatchIP, theIPBuf, 40);
    LOG4CXX_INFO(loggerClassify, "PROTOCOL : " << theTitle << " = "
                 << ueIPBuf << "(" << theFourTuple->ueIP << ")" << "," << theFourTuple->uePort
                 << ", " << serverIPBuf << "(" << theFourTuple->serverIP << ")" << "," << theFourTuple->serverPort
                 << ", " << theIPBuf << "(" << theIP << ")" << "," << theServerPort);
}

void debugPrintIPInfo(const char *theTitle, PectIP4Tuple *theFourTuple) {
    struct in_addr ueIPIn;
    struct in_addr serverIPIn;
    ueIPIn.s_addr = htonl((theFourTuple->ueIP));
    serverIPIn.s_addr = htonl((theFourTuple->serverIP));
    char ueIPBuf[40];
    char serverIPBuf[40];
    inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
    inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
    LOG4CXX_INFO(loggerClassify, "FLOW INFO : " << theTitle << " = "
                 << ueIPBuf << "(" << theFourTuple->ueIP << ")" << "," << theFourTuple->uePort
                 << ", " << serverIPBuf << "(" << theFourTuple->serverIP << ")" << "," << theFourTuple->serverPort);
}

void debugPrintCdpPacketNum(const char *theTitle, struct cdpTimers *cdpTimer, struct flow_data *fd) {
    LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << ": Queue #  "  <<  cdpTimer->queueNum
                 <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]
                 <<  ": fd->cdpNumPackets = " << fd->cdpNumPackets
                 <<  ": fd->cdpSTATE = " << fd->cdpSTATE
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING]
                 <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST]);
}

void debugPrintCdpPacketNum(const char *theTitle, struct cdpTimers *cdpTimer) {
    LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << ": Queue #  "  <<  cdpTimer->queueNum
                 <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]);
}
void debugPrintCdpPacketNum(const char *theTitle, struct cdpTimers *cdpTimer, struct flow_data *fd, const struct ipoque_cdp_generic_info *generic_info) {
    if((generic_info != NULL) && (fd != NULL) && (cdpTimer != NULL)) {
        LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << ": Queue #  "  <<  cdpTimer->queueNum
                     <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]
                     <<  ": generic_info->packet_direction = " <<  generic_info->packet_direction
                     <<  ": generic_info->initial_packet_direction = " <<  generic_info->initial_packet_direction
                     <<  ": generic_info->flow_packet_counter[0] = " <<  generic_info->flow_packet_counter[0]
                     <<  ": generic_info->flow_packet_counter[1] = " <<  generic_info->flow_packet_counter[1]
                     <<  ": generic_info->protocol = " <<  generic_info->protocol
                     <<  ": fd->cdpNumPackets = " << fd->cdpNumPackets
                     <<  ": fd->cdpSTATE = " << fd->cdpSTATE
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST]);
    }
}
void debugPrintCdpPacketNum(const char *theTitle, struct cdpTimers *cdpTimer, struct flow_data *fd, const struct ipoque_cdp_generic_info *generic_info, int cdpType) {
    if((generic_info != NULL) && (fd != NULL) && (cdpTimer != NULL)) {
        LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << ": CDP PROTOCOL  " << CDP_PROTOCOL_HTTP[cdpType - 1] << ": Queue #  "  <<  cdpTimer->queueNum
                     <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]
                     <<  ": generic_info->packet_direction = " <<  generic_info->packet_direction
                     <<  ": generic_info->initial_packet_direction = " <<  generic_info->initial_packet_direction
                     <<  ": generic_info->flow_packet_counter[0] = " <<  generic_info->flow_packet_counter[0]
                     <<  ": generic_info->flow_packet_counter[1] = " <<  generic_info->flow_packet_counter[1]
                     <<  ": generic_info->protocol = " <<  generic_info->protocol
                     <<  ": fd->cdpNumPackets = " << fd->cdpNumPackets
                     <<  ": fd->cdpSTATE = " << fd->cdpSTATE
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_WEATHER]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_MAPS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_NEWS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING]
                     <<  ": fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST] = " << fd->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST]);
    }
}
void debugPrintCdpHostInfo(const char *theTitle, struct cdpTimers *cdpTimer, unsigned char *hosts, unsigned char *content,
                           unsigned char *user_agent, u16 host_len, u16 content_len, u16 user_agent_len) {
    char bufHosts[500] = {0}, bufContent[500] = {0} , bufUA[500] = {0};

    if(hosts != NULL) {
        strncpy(bufHosts, (char *) hosts, host_len);
        bufHosts[host_len] = '\0';
    }

    if(content != NULL) {
        strncpy(bufContent, (char *) content, content_len);
        bufContent[content_len] = '\0';
    }

    if(user_agent != NULL) {
        strncpy(bufUA, (char *) user_agent, user_agent_len);
        bufUA[user_agent_len] = '\0';
    }

    LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << ": Queue #  "  <<  cdpTimer->queueNum
                 <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]
                 <<  ": hosts = " <<  bufHosts << "[" << host_len << "]"
                 <<  ": content = " <<  bufContent << "[" << content_len << "]"
                 <<  ": user_agent = " <<  bufUA << "[" << user_agent_len << "]");
}

void debugPrintCdpHostInfo(const char *theTitle, struct cdpTimers *cdpTimer, unsigned char *hosts, unsigned char *content,
                           unsigned char *user_agent, u16 host_len, u16 content_len, u16 user_agent_len, int cdpType) {
    char bufHosts[500] = {0}, bufContent[500] = {0} , bufUA[500] = {0};

    if(hosts != NULL) {
        strncpy(bufHosts, (char *) hosts, host_len);
        bufHosts[host_len] = '\0';
    }

    if(content != NULL) {
        strncpy(bufContent, (char *) content, content_len);
        bufContent[content_len] = '\0';
    }

    if(user_agent != NULL) {
        strncpy(bufUA, (char *) user_agent, user_agent_len);
        bufUA[user_agent_len] = '\0';
    }

    LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : " << theTitle << "CDP PROTOCOL " << CDP_PROTOCOL_HTTP[cdpType - 1] << ": Queue #  "  <<  cdpTimer->queueNum
                 <<  ": PKT # " <<  cdpTimer->numPacketsChecked[cdpTimer->queueNum]
                 <<  ": hosts = " <<  bufHosts << "[" << host_len << "]"
                 <<  ": content = " <<  bufContent << "[" << content_len << "]"
                 <<  ": user_agent = " <<  bufUA << "[" << user_agent_len << "]");
}

void initCdpDetectionData(struct ipoque_detection_module_struct *ipoque_struct, struct flow_data *flow) {
    if((flow->cdpEXCLUDED[CDP_PROTOCOL_SPEEDTEST] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_WEATHER] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_MAPS] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_NEWS] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_ADVERTISEMENTS] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_SW_UPDATES] == CDP_EXCLUDE) &&
            (flow->cdpEXCLUDED[CDP_PROTOCOL_PHOTO_SHARING] == CDP_EXCLUDE)) {
        flow->cdpSTATE = CDP_EXCLUDE;
        return;
    }
}


/*
 * This is an overall method for host based CDP.
 */

enum ipoque_cdp_return cdpHttpConnection(struct ipoque_detection_module_struct *ipoque_struct,
        void *userptr, void *flow_area, void *src_area, void *dst_area) {
    struct cdpHostDataStruct *cdpHostData = (struct cdpHostDataStruct *) userptr;
    struct cdpTimers *cdpHttpTimer = cdpHostData->ptrToCdpTimersStruct ;
    //struct flow_data *flow = cdpHostData->ptrToFlowDataStruct;  // NOTE NEED TO uncomment ptrToFlowDataStruct in classify method
    const char **CDP_HTTP_DEFAULT = cdpHostData->ptrtoCDP_HTTP_DEFAULT;
    const char **CDP_HTTP = cdpHostData->ptrtoCDP_HTTP;
    const char **CDP_HTTP_USER_AGENT = cdpHostData->ptrtoCDP_HTTP_USER_AGENT;
    const char **CDP_HTTP_URL = cdpHostData->ptrtoCDP_HTTP_URL;
    //int cdpType = cdpHostData->cdpType;
    int CDP_HTTP_URL_SIZE = cdpHostData->iCDP_HTTP_URL_SIZE;
    int CDP_HTTP_USER_AGENT_SIZE = cdpHostData->iCDP_HTTP_USER_AGENT_SIZE;
    int CDP_HTTP_DEFAULT_SIZE = cdpHostData->iCDP_HTTP_DEFAULT_SIZE;
    int CDP_HTTP_SIZE = cdpHostData->iCDP_HTTP_SIZE;
    std::vector<size_t> *CDP_HTTP_DEFAULT_LEN = cdpHostData->ptrtoCDP_HTTP_DEFAULT_LEN ;
    std::vector<size_t> *CDP_HTTP_LEN = cdpHostData->ptrtoCDP_HTTP_LEN;
    std::vector<size_t> *CDP_HTTP_USER_AGENT_LEN = cdpHostData->ptrtoCDP_HTTP_USER_AGENT_LEN;
    std::vector<size_t> *CDP_HTTP_URL_LEN = cdpHostData->ptrtoCDP_HTTP_URL_LEN;
    timespec startTime;

    if(cdpTimersEnabled) {
        cdpStartTimer(&startTime, cdpHttpTimer);
    }

    /* get generic info to find the detected protocol */
    const struct ipoque_cdp_generic_info *generic_info;
    generic_info = ipoque_pace_cdp_get_generic_info(ipoque_struct);
    //debugPrintCdpPacketNum((const char *) "HTTP: BEFORE Generic",cdpHttpTimer,flow, genericInfo);

    if(generic_info != NULL && generic_info->protocol == IPOQUE_PROTOCOL_HTTP) {
        /* look for the host field in http packets */
        unsigned char *host = NULL;
        unsigned char *content = NULL;
        unsigned char *user_agent = NULL;
        unsigned char *url = NULL;
        u16 host_len = 0;
        u16 content_len = 0;
        u16 user_agent_len = 0;
        u16 url_len = 0;
        /* get the HTTP information */
        ipoque_detection_get_http_host_user_and_content_type(ipoque_struct, &host, &host_len, &content, &content_len, &user_agent, &user_agent_len);

        //debugPrintCdpHostInfo((const char *) "HTTP: BEFORE HOSTS",cdpHttpTimer, host, content, user_agent, host_len,content_len, user_agent_len, cdpType);

        /* if host is available, compare it to a given DEFAULT string */

        //for(int i = 0; i < CDP_HTTP_DEFAULT_SIZE; i++) {
        //LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : cdpHttpConnection : " <<  CDP_PROTOCOL_HTTP[cdpType-1]  << ": Searching for "
        //<< "host = " << CDP_HTTP_DEFAULT[i] << ": host len = " << CDP_HTTP_DEFAULT_LEN->at(i));
        //}
        for(int i = 0; i < CDP_HTTP_DEFAULT_SIZE; i++) {
            if(host != NULL && host_len >= CDP_HTTP_DEFAULT_LEN->at(i)) {
                //LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : cdpHttpConnection : " <<  CDP_PROTOCOL_HTTP[cdpType-1]  << ": Searching for "
                //  << "host = " << CDP_HTTP_DEFAULT[i] << ": host len = " << CDP_HTTP_DEFAULT_LEN->at(i));
                if(memmem(host, host_len, CDP_HTTP_DEFAULT[i], CDP_HTTP_DEFAULT_LEN->at(i)) != NULL) {
                    /* found, so match this CDP  */

                    /* THIS IS A DEBUG PRINT SO DON'T DELETE IT
                    debugPrintProtocolInfo((const char *)"HTTP DEFAULT: Host\0", host, host_len);
                    debugPrintProtocolInfo((const char *)"HTTP DEFAULT: content", content, content_len);
                    debugPrintProtocolInfo((const char *)"HTTP DEFAULT: user_agent", user_agent, user_agent_len);  */
                    if(cdpTimersEnabled) {
                        cdpEndTimer(&startTime, cdpHttpTimer, 1);
                    }

                    return IPOQUE_CDP_MATCH;
                }
            }
        }

        if(cdpNonDefaultArrayEnabled) {
            /* if host is available, compare it to a given string */
            //LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : cdpHttpConnection :Processing Non DEFAUT HOST");
            for(int i = 0; i < CDP_HTTP_SIZE; i++) {
                if(host != NULL && host_len >= CDP_HTTP_LEN->at(i)) {
                    if(memcmp(host, CDP_HTTP[i], CDP_HTTP_LEN->at(i)) == 0) {
                        /* found, so match this CDP  */
                        /* THIS IS A DEBUG PRINT SO DON'T DELETE IT
                        debugPrintProtocolInfo((const char *)"HTTP : Host\0", host, host_len);
                        debugPrintProtocolInfo((const char *)"HTTP : content", content, content_len);
                        debugPrintProtocolInfo((const char *)"HTTP : user_agent", user_agent, user_agent_len); */
                        if(cdpTimersEnabled) {
                            cdpEndTimer(&startTime, cdpHttpTimer, 1);
                        }

                        return IPOQUE_CDP_MATCH;
                    }
                }
            }
        }

        if(cdpUserAgentDecodeEnabled) {
            //LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : cdpHttpConnection :Processing USER AGENT");
            for(int i = 0; i < CDP_HTTP_USER_AGENT_SIZE; i++) {
                if(user_agent != NULL && user_agent_len >= CDP_HTTP_USER_AGENT_LEN->at(i)) {
                    if(memmem(user_agent, user_agent_len, CDP_HTTP_USER_AGENT[i], CDP_HTTP_USER_AGENT_LEN->at(i)) != NULL) {
                        /* THIS IS A DEBUG PRINT SO DON'T DELETE IT
                        debugPrintProtocolInfo((const char *)"HTTP USER-AGENT: Host\0", host, host_len);
                        debugPrintProtocolInfo((const char *)"HTTP USER-AGENT: content", content, content_len);
                        debugPrintProtocolInfo((const char *)"HTTP USER-AGENT: user_agent", user_agent, user_agent_len); */
                        if(cdpTimersEnabled) {
                            cdpEndTimer(&startTime, cdpHttpTimer, 1);
                        }

                        return IPOQUE_CDP_MATCH;
                    }
                }
            }
        }

        if(cdpURLdecodeEnabled) {
            //LOG4CXX_INFO(loggerPcpGlue, "CDP INFO : cdpHttpConnection :Processing URL");
            /* get the HTTP URL information */
            ipoque_detection_get_http_request_url(ipoque_struct, &url, &url_len);

            for(int i = 0; i < CDP_HTTP_URL_SIZE; i++) {
                if(url != NULL && url_len >= CDP_HTTP_URL_LEN->at(i)) {
                    if(memmem(url, url_len, CDP_HTTP_URL[i], CDP_HTTP_URL_LEN->at(i)) != NULL)  {
                        /* found, so match this CDP  */
                        /* THIS IS A DEBUG PRINT SO DON'T DELETE IT
                        debugPrintProtocolInfo((const char *)"HTTP URL : \0", url, url_len);  */
                        if(cdpTimersEnabled) {
                            cdpEndTimer(&startTime, cdpHttpTimer, 1);
                        }

                        return IPOQUE_CDP_MATCH;
                    }
                }
            }
        }

        /* host not available or does not match so exclude */
        if(cdpTimersEnabled) {
            cdpEndTimer(&startTime, cdpHttpTimer, 3);
        }

        return IPOQUE_CDP_EXCLUDE;
    }

    if(generic_info != NULL && generic_info->protocol == IPOQUE_PROTOCOL_UNKNOWN) {
        /* wait until HTTP is detected or excluded */
        const IPOQUE_PROTOCOL_BITMASK *bm = ipoque_get_excluded_bitmask(ipoque_struct);

        if(!IPOQUE_COMPARE_PROTOCOL_TO_BITMASK(*bm, IPOQUE_PROTOCOL_HTTP)) {
            if(cdpTimersEnabled) {
                cdpEndTimer(&startTime, cdpHttpTimer, 2);
            }

            return IPOQUE_CDP_NEED_NEXT_PACKET;
        }
    }

    /* fallback: exclude this CDP */
    if(cdpTimersEnabled) {
        cdpEndTimer(&startTime, cdpHttpTimer, 4);
    }

    return IPOQUE_CDP_EXCLUDE;
}

/* LLMNR for IPV4 only */
enum ipoque_cdp_return cdpLLMNR(struct ipoque_detection_module_struct *ipoque_struct,
                                void *userptr, void *flow_area, void *src_area, void *dst_area) {
    //struct PectIP4Tuple *theFourTuple = (struct PectIP4Tuple *) userptr;
    struct cdpLlmnrDataStruct *cdpLlmnrData = (struct cdpLlmnrDataStruct *) userptr;
    struct PectIP4Tuple *theFourTuple = cdpLlmnrData->ptrToPectIP4TupleStruct;
    struct cdpTimers *cdpLlmnrTimer = cdpLlmnrData->ptrToCdpTimersStruct ;
    timespec startTime;

    if(cdpTimersEnabled) {
        cdpStartTimer(&startTime, cdpLlmnrTimer);
    }

    //debugPrintCdpPacketNum((const char *) "LLMNR",cdpLlmnrTimer);
    if(loggerClassify->isTraceEnabled()) {
        LOG4CXX_TRACE(loggerClassify, "PROTOCOL : LLMNR theFourTuple : "
                      << theFourTuple->ueIP << ":" << theFourTuple->uePort  << ", " <<  theFourTuple->serverIP << ":" << theFourTuple->serverPort);
    }

    if(theFourTuple != NULL) {
        //efitleo: 23June14; EQEV-14220 ; updated to indicate the ue port need not be 5355 for LLMNR (just server port)
        if((theFourTuple->serverIP == llmnr_serverIP) && (theFourTuple->serverPort == llmnr_serverPort)) {
            //debugPrintIPInfoLLMNR((const char *)"LLMNR ", theFourTuple, llmnr_serverIP, llmnr_serverPort);
            if(cdpTimersEnabled) {
                cdpEndTimer(&startTime, cdpLlmnrTimer, 1);
            }

            return IPOQUE_CDP_MATCH;
        }
    }

    /* exclude this CDP */
    if(cdpTimersEnabled) {
        cdpEndTimer(&startTime, cdpLlmnrTimer, 4);
    }

    return IPOQUE_CDP_EXCLUDE;
}

static void *malloc_32bit_safe_ext(unsigned long size, void *userptr) {
    return malloc(size);
}

void initialiseCdpHttpData(cdpHostDataStruct *cdpHttpProtocolData, struct cdpTimers *theCdpTimer, int theCdpType,
                           const char **hostDefault, const char **hostNonDefault, const char **userAgentStr, const char **urlStr,
                           int  hostDefault_size, int hostNonDefault_size, int userAgentStr_size, int urlStr_size,
                           std::vector<size_t> *hostDefault_len, std::vector<size_t> *hostNonDefault_len,
                           std::vector<size_t> *userAgentStr_len, std::vector<size_t> *urlStr_len) {
    cdpHttpProtocolData->ptrToCdpTimersStruct = theCdpTimer;
    cdpHttpProtocolData->cdpType = theCdpType;
    cdpHttpProtocolData->ptrtoCDP_HTTP_DEFAULT = hostDefault;
    cdpHttpProtocolData->ptrtoCDP_HTTP = hostNonDefault;
    cdpHttpProtocolData->ptrtoCDP_HTTP_USER_AGENT = userAgentStr;
    cdpHttpProtocolData->ptrtoCDP_HTTP_URL = urlStr;
    cdpHttpProtocolData->iCDP_HTTP_DEFAULT_SIZE = hostDefault_size;
    cdpHttpProtocolData->iCDP_HTTP_SIZE = hostNonDefault_size;
    cdpHttpProtocolData->iCDP_HTTP_USER_AGENT_SIZE = userAgentStr_size;
    cdpHttpProtocolData->iCDP_HTTP_URL_SIZE = urlStr_size;
    cdpHttpProtocolData->ptrtoCDP_HTTP_DEFAULT_LEN = hostDefault_len;
    cdpHttpProtocolData->ptrtoCDP_HTTP_LEN = hostNonDefault_len;
    cdpHttpProtocolData->ptrtoCDP_HTTP_USER_AGENT_LEN = userAgentStr_len;
    cdpHttpProtocolData->ptrtoCDP_HTTP_URL_LEN = urlStr_len;
}

void cdpGetArrayStringLen(const char **theStringArray, int theStringArray_size, std::vector <size_t> &returnTheStringArray_len) {
    for(int i = 0; i < theStringArray_size; i++) {
        if(theStringArray[i] != NULL) {
            returnTheStringArray_len.at(i) = strlen((const char *) theStringArray[i]);
        }
    }
}

/*
 *
 */
void cdpSetTheDecodeDepth(int cdpType, int *cdp_protocol_size) {
    int cdpProtocolSize = *cdp_protocol_size;

    if(cdpHostDecodeDepth[cdpType] < cdpProtocolSize) {
        cdpProtocolSize = cdpHostDecodeDepth[cdpType];
    }

    *cdp_protocol_size = cdpProtocolSize;
}

/*
 * configure custom user protocols based on the host.
 */

void configureCustomProtocolsAndGroups(classify_data cd, ServiceProvider *sp, int pktbufNum) {
    if(ipoque_pace_cdp_set_number_of_protocols(cd->ipq, IPOQUE_MAX_CUSTOM_PROTOCOLS, malloc_32bit_safe_ext, free_32bit_safe, NULL) != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL : The number of custom protocols was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL : The number of custom protocol was not set");
        exit(5);
    }

    CDP_SPEEDTEST_DEFAULT_SIZE = (int)(sizeof(CDP_SPEEDTEST_DEFAULT) / sizeof(CDP_SPEEDTEST_DEFAULT[0]));
    CDP_SPEEDTEST_DEFAULT_LEN.resize(CDP_SPEEDTEST_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_SPEEDTEST_DEFAULT, CDP_SPEEDTEST_DEFAULT_SIZE, CDP_SPEEDTEST_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_SPEEDTEST, &CDP_SPEEDTEST_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    initialiseCdpHttpData(&cdpSpeedData, &cdpSpeedTimer, CDP_PROTOCOL_SPEEDTEST,
                          CDP_SPEEDTEST_DEFAULT, NULL, NULL, NULL,
                          CDP_SPEEDTEST_DEFAULT_SIZE, 0, 0, 0,
                          &CDP_SPEEDTEST_DEFAULT_LEN, NULL, NULL, NULL);
    int checkSpeedtestRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 0, cdpHttpConnection, &cdpSpeedData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkSpeedtestRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The speedtest custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The speedtest custom protocol was not set");
        exit(6);
    }

    CDP_WEATHER_DEFAULT_SIZE = (int)(sizeof(CDP_WEATHER_DEFAULT) / sizeof(CDP_WEATHER_DEFAULT[0]));
    CDP_WEATHER_DEFAULT_LEN.resize(CDP_WEATHER_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_WEATHER_DEFAULT, CDP_WEATHER_DEFAULT_SIZE, CDP_WEATHER_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_WEATHER, &CDP_WEATHER_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_WEATHER_SIZE = (int)(sizeof(CDP_WEATHER) / sizeof(CDP_WEATHER[0]));
    CDP_WEATHER_LEN.resize(CDP_WEATHER_SIZE);
    cdpGetArrayStringLen(CDP_WEATHER, CDP_WEATHER_SIZE, CDP_WEATHER_LEN);
    initialiseCdpHttpData(&cdpWeatherData, &cdpWeatherTimer, CDP_PROTOCOL_WEATHER,
                          CDP_WEATHER_DEFAULT, CDP_WEATHER, NULL, NULL,
                          CDP_WEATHER_DEFAULT_SIZE, CDP_WEATHER_SIZE, 0, 0,
                          &CDP_WEATHER_DEFAULT_LEN, &CDP_WEATHER_LEN, NULL, NULL);
    int checkWeatherRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 1, cdpHttpConnection, &cdpWeatherData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkWeatherRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The WEATHER custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The WEATHER custom protocol was not set");
        exit(6);
    }

    CDP_MAPS_DEFAULT_SIZE = (int)(sizeof(CDP_MAPS_DEFAULT) / sizeof(CDP_MAPS_DEFAULT[0]));
    CDP_MAPS_DEFAULT_LEN.resize(CDP_MAPS_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_MAPS_DEFAULT, CDP_MAPS_DEFAULT_SIZE, CDP_MAPS_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_MAPS, &CDP_MAPS_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_MAPS_SIZE = (int)(sizeof(CDP_MAPS) / sizeof(CDP_MAPS[0]));
    CDP_MAPS_LEN.resize(CDP_MAPS_SIZE);
    cdpGetArrayStringLen(CDP_MAPS, CDP_MAPS_SIZE, CDP_MAPS_LEN);
    CDP_MAPS_URL_SIZE = (int)(sizeof(CDP_MAPS_URL) / sizeof(CDP_MAPS_URL[0]));
    CDP_MAPS_URL_LEN.resize(CDP_MAPS_URL_SIZE);
    cdpGetArrayStringLen(CDP_MAPS_URL, CDP_MAPS_URL_SIZE, CDP_MAPS_URL_LEN);
    CDP_MAPS_USER_AGENT_SIZE = (int)(sizeof(CDP_MAPS_USER_AGENT) / sizeof(CDP_MAPS_USER_AGENT[0]));
    CDP_MAPS_USER_AGENT_LEN.resize(CDP_MAPS_USER_AGENT_SIZE);
    cdpGetArrayStringLen(CDP_MAPS_USER_AGENT, CDP_MAPS_USER_AGENT_SIZE, CDP_MAPS_USER_AGENT_LEN);
    initialiseCdpHttpData(&cdpMapsData, &cdpMapsTimer, CDP_PROTOCOL_MAPS,
                          CDP_MAPS_DEFAULT, CDP_MAPS, CDP_MAPS_USER_AGENT, CDP_MAPS_URL,
                          CDP_MAPS_DEFAULT_SIZE, CDP_MAPS_SIZE, CDP_MAPS_USER_AGENT_SIZE, CDP_MAPS_URL_SIZE,
                          &CDP_MAPS_DEFAULT_LEN, &CDP_MAPS_LEN, &CDP_MAPS_USER_AGENT_LEN, &CDP_MAPS_URL_LEN);
    int checkMapsRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 2, cdpHttpConnection, &cdpMapsData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkMapsRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The MAPS custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The MAPS custom protocol was not set");
        exit(6);
    }

    CDP_NEWS_DEFAULT_SIZE = (int)(sizeof(CDP_NEWS_DEFAULT) / sizeof(CDP_NEWS_DEFAULT[0]));
    CDP_NEWS_DEFAULT_LEN.resize(CDP_NEWS_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_NEWS_DEFAULT, CDP_NEWS_DEFAULT_SIZE, CDP_NEWS_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_NEWS, &CDP_NEWS_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_NEWS_SIZE = (int)(sizeof(CDP_NEWS) / sizeof(CDP_NEWS[0]));
    CDP_NEWS_LEN.resize(CDP_NEWS_SIZE);
    cdpGetArrayStringLen(CDP_NEWS, CDP_NEWS_SIZE, CDP_NEWS_LEN);
    initialiseCdpHttpData(&cdpNewsData, &cdpNewsTimer, CDP_PROTOCOL_NEWS,
                          CDP_NEWS_DEFAULT, CDP_NEWS, NULL, NULL,
                          CDP_NEWS_DEFAULT_SIZE, CDP_NEWS_SIZE, 0, 0,
                          &CDP_NEWS_DEFAULT_LEN, &CDP_NEWS_LEN, NULL, NULL);
    int checkNewsRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 3, cdpHttpConnection, &cdpNewsData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkNewsRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The NEWS custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The NEWS custom protocol was not set");
        exit(6);
    }

    CDP_ADVERTISEMENTS_DEFAULT_SIZE = (int)(sizeof(CDP_ADVERTISEMENTS_DEFAULT) / sizeof(CDP_ADVERTISEMENTS_DEFAULT[0]));
    CDP_ADVERTISEMENTS_DEFAULT_LEN.resize(CDP_ADVERTISEMENTS_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_ADVERTISEMENTS_DEFAULT, CDP_ADVERTISEMENTS_DEFAULT_SIZE, CDP_ADVERTISEMENTS_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_ADVERTISEMENTS, &CDP_ADVERTISEMENTS_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_ADVERTISEMENTS_SIZE = (int)(sizeof(CDP_ADVERTISEMENTS) / sizeof(CDP_ADVERTISEMENTS[0]));
    CDP_ADVERTISEMENTS_LEN.resize(CDP_ADVERTISEMENTS_SIZE);
    cdpGetArrayStringLen(CDP_ADVERTISEMENTS, CDP_ADVERTISEMENTS_SIZE, CDP_ADVERTISEMENTS_LEN);
    CDP_ADVERTISEMENTS_URL_SIZE = (int)(sizeof(CDP_ADVERTISEMENTS_URL) / sizeof(CDP_ADVERTISEMENTS_URL[0]));
    CDP_ADVERTISEMENTS_URL_LEN.resize(CDP_ADVERTISEMENTS_URL_SIZE);
    cdpGetArrayStringLen(CDP_ADVERTISEMENTS_URL, CDP_ADVERTISEMENTS_URL_SIZE, CDP_ADVERTISEMENTS_URL_LEN);
    CDP_ADVERTISEMENTS_USER_AGENT_SIZE = (int)(sizeof(CDP_ADVERTISEMENTS_USER_AGENT) / sizeof(CDP_ADVERTISEMENTS_USER_AGENT[0]));
    CDP_ADVERTISEMENTS_USER_AGENT_LEN.resize(CDP_ADVERTISEMENTS_USER_AGENT_SIZE);
    cdpGetArrayStringLen(CDP_ADVERTISEMENTS_USER_AGENT, CDP_ADVERTISEMENTS_USER_AGENT_SIZE, CDP_ADVERTISEMENTS_USER_AGENT_LEN);
    initialiseCdpHttpData(&cdpAdvertsData, &cdpAdvertsTimer, CDP_PROTOCOL_ADVERTISEMENTS,
                          CDP_ADVERTISEMENTS_DEFAULT, CDP_ADVERTISEMENTS, CDP_ADVERTISEMENTS_USER_AGENT, CDP_ADVERTISEMENTS_URL,
                          CDP_ADVERTISEMENTS_DEFAULT_SIZE, CDP_ADVERTISEMENTS_SIZE, CDP_ADVERTISEMENTS_USER_AGENT_SIZE, CDP_ADVERTISEMENTS_URL_SIZE,
                          &CDP_ADVERTISEMENTS_DEFAULT_LEN, &CDP_ADVERTISEMENTS_LEN, &CDP_ADVERTISEMENTS_USER_AGENT_LEN, &CDP_ADVERTISEMENTS_URL_LEN);
    int checkAdvertisementsRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 4, cdpHttpConnection, &cdpAdvertsData, 0  , 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkAdvertisementsRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The ADVERTISEMENTS custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The ADVERTISEMENTS custom protocol was not set");
        exit(6);
    }

    CDP_SW_UPDATES_DEFAULT_SIZE = (int)(sizeof(CDP_SW_UPDATES_DEFAULT) / sizeof(CDP_SW_UPDATES_DEFAULT[0]));
    CDP_SW_UPDATES_DEFAULT_LEN.resize(CDP_SW_UPDATES_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_SW_UPDATES_DEFAULT, CDP_SW_UPDATES_DEFAULT_SIZE, CDP_SW_UPDATES_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_SW_UPDATES, &CDP_SW_UPDATES_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_SW_UPDATES_SIZE = (int)(sizeof(CDP_SW_UPDATES) / sizeof(CDP_SW_UPDATES[0]));
    CDP_SW_UPDATES_LEN.resize(CDP_SW_UPDATES_SIZE);
    cdpGetArrayStringLen(CDP_SW_UPDATES, CDP_SW_UPDATES_SIZE, CDP_SW_UPDATES_LEN);
    CDP_SW_UPDATES_USER_AGENT_SIZE = (int)(sizeof(CDP_SW_UPDATES_USER_AGENT) / sizeof(CDP_SW_UPDATES_USER_AGENT[0]));
    CDP_SW_UPDATES_USER_AGENT_LEN.resize(CDP_SW_UPDATES_USER_AGENT_SIZE);
    cdpGetArrayStringLen(CDP_SW_UPDATES_USER_AGENT, CDP_SW_UPDATES_USER_AGENT_SIZE, CDP_SW_UPDATES_USER_AGENT_LEN);
    initialiseCdpHttpData(&cdpSWuData, &cdpSWuTimer, CDP_PROTOCOL_SW_UPDATES,
                          CDP_SW_UPDATES_DEFAULT, CDP_SW_UPDATES, CDP_SW_UPDATES_USER_AGENT, NULL,
                          CDP_SW_UPDATES_DEFAULT_SIZE, CDP_SW_UPDATES_SIZE, CDP_SW_UPDATES_USER_AGENT_SIZE, 0,
                          &CDP_SW_UPDATES_DEFAULT_LEN, &CDP_SW_UPDATES_LEN, &CDP_SW_UPDATES_USER_AGENT_LEN, NULL);
    int checkSWUpdateRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 5, cdpHttpConnection, &cdpSWuData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkSWUpdateRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The SOFTWARE UPDATE custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The SOFTWARE UPDATE custom protocol was not set");
        exit(6);
    }

    CDP_PHOTO_SHARING_DEFAULT_SIZE = (int)(sizeof(CDP_PHOTO_SHARING_DEFAULT) / sizeof(CDP_PHOTO_SHARING_DEFAULT[0]));
    CDP_PHOTO_SHARING_DEFAULT_LEN.resize(CDP_PHOTO_SHARING_DEFAULT_SIZE);
    cdpGetArrayStringLen(CDP_PHOTO_SHARING_DEFAULT, CDP_PHOTO_SHARING_DEFAULT_SIZE, CDP_PHOTO_SHARING_DEFAULT_LEN);
    cdpSetTheDecodeDepth(CDP_PROTOCOL_PHOTO_SHARING, &CDP_PHOTO_SHARING_DEFAULT_SIZE); // do after LEN and cdpGetArrayStringLen & before initialiseCdpHttpData
    CDP_PHOTO_SHARING_SIZE = (int)(sizeof(CDP_PHOTO_SHARING) / sizeof(CDP_PHOTO_SHARING[0]));
    CDP_PHOTO_SHARING_LEN.resize(CDP_PHOTO_SHARING_SIZE);
    cdpGetArrayStringLen(CDP_PHOTO_SHARING, CDP_PHOTO_SHARING_SIZE, CDP_PHOTO_SHARING_LEN);
    initialiseCdpHttpData(&cdpPhotoData, &cdpPhotoTimer, CDP_PROTOCOL_PHOTO_SHARING,
                          CDP_PHOTO_SHARING_DEFAULT, CDP_PHOTO_SHARING, NULL, NULL,
                          CDP_PHOTO_SHARING_DEFAULT_SIZE, CDP_PHOTO_SHARING_SIZE, 0, 0,
                          &CDP_PHOTO_SHARING_DEFAULT_LEN, &CDP_PHOTO_SHARING_LEN, NULL, NULL);
    int checkPhotoSharingRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 6, cdpHttpConnection, &cdpPhotoData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkPhotoSharingRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The PHOTO-SHARING custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The PHOTO-SHARING custom protocol was not set");
        exit(6);
    }

    cdpLlmnrData.ptrToCdpTimersStruct = &cdpLlmnrTimer;
    cdpLlmnrData.ptrToPectIP4TupleStruct = &(cd->fourTuple);
    int checkLLMNRRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 7, cdpLLMNR, &cdpLlmnrData, 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

    if(checkLLMNRRegistered != 0) {
        LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The LLMNR custom protocol was not set");
        LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The LLMNR custom protocol was not set");
        exit(6);
    }

    // Simple one line host check.
    int hostNum;

    for(hostNum = 0; hostNum < MAX_SIMPLE_HOSTS; hostNum++) {
        CDP_SIMPLE_HOST_SIZE = 1;
        CDP_SIMPLE_HOST_LEN[hostNum].resize(CDP_SIMPLE_HOST_SIZE);
        CDP_SIMPLE_HOST_LEN[hostNum].at(0) = strlen(CDP_SIMPLE_HOST[hostNum]);
        initialiseCdpHttpData(&cdpSimpleHostData[hostNum], &cdpSimpleHostTimer[hostNum], CDP_SIMPLE_HOST_PROTOCOL[hostNum],
                              &CDP_SIMPLE_HOST[hostNum], NULL, NULL, NULL,
                              CDP_SIMPLE_HOST_SIZE, 0, 0, 0,
                              &CDP_SIMPLE_HOST_LEN[hostNum], NULL, NULL, NULL);
        int checkSimpleHostRegistered = ipoque_pace_cdp_register_protocol(cd->ipq, 8 + hostNum, cdpHttpConnection, &cdpSimpleHostData[hostNum], 0, 0, malloc_32bit_safe_ext, free_32bit_safe, NULL);

        if(checkSimpleHostRegistered != 0) {
            LOG4CXX_FATAL(loggerClassify, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The " << CDP_SIMPLE_HOST[hostNum] << " custom protocol was not set");
            LOG4CXX_FATAL(loggerConsole, "CDP INFO PROTOCOL configureCustomProtocolsAndGroups: The " << CDP_SIMPLE_HOST[hostNum] << " custom protocol was not set");
            exit(6);
        }

        // DEBUG PRINT DO NOT DELETE
        //else {
        //struct cdpHostDataStruct *cdpHostData =  &cdpSimpleHostData[hostNum];
        //std::vector<size_t> *CDP_HTTP_DEFAULT_LEN = cdpHostData->ptrtoCDP_HTTP_DEFAULT_LEN ;
        //LOG4CXX_INFO(loggerClassify, "CDP INFO PROTOCOL SIMPLE HOST: hostNum " << hostNum << ": Protocol Number " << CDP_SIMPLE_HOST_PROTOCOL[hostNum] << ": Hostname " << CDP_SIMPLE_HOST[hostNum] << "(" << *(cdpHostData->ptrtoCDP_HTTP_DEFAULT) << ")"
        //<< ": Size " << CDP_SIMPLE_HOST_SIZE<< "(" << cdpHostData->iCDP_HTTP_DEFAULT_SIZE<< ")"
        //<< ": Len " << CDP_SIMPLE_HOST_LEN[hostNum].at(0)<< "(" << cdpHostData->ptrtoCDP_HTTP_DEFAULT_LEN->at(0) << ")" << "(" << CDP_HTTP_DEFAULT_LEN->at(0) << ")"
        //<< ": protocol Number " << 8+hostNum << "(" << cdpHostData->cdpType << ")"
        //);
        //}
    }
}
void classifyStartPrintOnceError(const char *msg, int *threadIndex) {
    if(*threadIndex == (evaluatedArguments.packetBufferSourceCount - 1)) {
        LOG4CXX_ERROR(loggerClassify, msg);
    }
}
void classifyStartPrintOnce(const char *msg, int *threadIndex) {
    if(*threadIndex == (evaluatedArguments.packetBufferSourceCount - 1)) {
        LOG4CXX_INFO(loggerClassify, msg);
    }
}

/*
 * starts the classify thread and creates and configures the IPOQUE module.
 *
 */
classify_data classify_start(int pktbufNum, ServiceProvider *serviceProvider) {
    static int print_once;
    char printBuf[100];
    print_once = 0;
    classify_data cd;
    IPOQUE_PROTOCOL_BITMASK protocols;
    cd = (struct classify_data_struct *) calloc(1, sizeof(struct classify_data_struct));
    cd->ipqNormalConnectionTimeout = evaluatedArguments.ipqConnectionNormalTimeout;
    // efitleo : Multiple Timeout Queues
    cd->ipqShortConnectionTimeout =  evaluatedArguments.ipqConnectionShortTimeout;
    cd->ipqLongConnectionTimeout = evaluatedArguments.ipqConnectionLongTimeout;
    cd->ipq = ipoque_init_detection_module(IPQ_TICK_RESOLUTION, classify_malloc, 0);
    ipoque_pace_version_t paceVersion;
    getIpoquePaceVersion(&paceVersion);
    ipoque_pace_api_version_t paceApiVersion;
    getIpoquePaceAPIVersion(&paceApiVersion);
    //enum ipoque_pace_licensing_loading_result res = IPOQUE_LICENSE_LOAD_FAILED;
    //checkIpoquePaceLicense(cd, &res);
    cd->clientFinder = new ClientFinder();
    cd->uaBuffer = new char[UA_MAX_LENGTH + 1]; //+1 for the termination char
    ipoque_set_rdt_correlation(cd->ipq, 1);
    // Set up flowsLastProduced so we wait until the next ROP period until we copy
    timeval t;
    gettimeofday(&t, NULL);
    cd->flowsLastProduced = t.tv_sec - (t.tv_sec % evaluatedArguments.outputReportingPeriod * 60);
    //13A Backward compatibility
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_LICENSE_EXCEEDED);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_IGMP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_ICMP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_HALFLIFE2); //Source-Engine
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_XBOX);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_WORLDOFWARCRAFT); //WoW
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_OPERAMINI);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SSH);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_UNENCRYPED_JABBER); //XMPP
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_MAIL_IMAP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_MAIL_POP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_MAIL_SMTP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_NTP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_DHCPV6);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_DHCP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_STUN);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SSDP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_DNS);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_FTP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SPOTIFY);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_FUNSHION);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_QQLIVE);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_PPLIVE);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_PPSTREAM);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_USENET);  //NNTP
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SIP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_DIRECTCONNECT);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_GNUTELLA);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_BITTORRENT);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_HTTP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_WAP_WSP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_WAP_WTP_WSP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_WAP_WTLS);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_RTP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_RTSP);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SSL); // email & other secure comms depend on this
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_SSTP); // VPN over SSL
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_FLASH); //RTMP
    // Required for Service-provider
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_PANDORA);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_NETFLIX);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_YAHOO);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_MSN);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_VIBER);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_JABBER_APPLICATION_NIMBUZZ);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_DIRECT_DOWNLOAD_LINK);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_HTTP_APPLICATION_GOOGLE_TALK);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_GOOGLE);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_APPLEJUICE);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_ADOBE_CONNECT);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_OSCAR);
    IPOQUE_ADD_PROTOCOL_TO_BITMASK(protocols, IPOQUE_PROTOCOL_UNKNOWN);
    ipoque_set_protocol_detection_bitmask2(cd->ipq, &protocols);
    // FOR DEBUG
    // IPOQUE_BITMASK_SET_ALL(protocols);
    // ipoque_set_protocol_detection_bitmask2(cd->ipq, &protocols);
    // DEBUG END
    LOG4CXX_DEBUG(loggerConsole, "Finished adding in Custom Protocols");
    LOG4CXX_INFO(loggerClassify, "Finished adding in Custom Protocols");
    ipoque_set_plain_tunnel_decapsulation_level(cd->ipq, 50);

    // Set the HOST array depth search here.
    if(evaluatedArguments.cdpDecodeHostsLevel.size() == 0) {
        snprintf(printBuf, sizeof(printBuf), "CDP INFO: Custom Protocol Host Decode Level not set");
        classifyStartPrintOnceError(printBuf, &pktbufNum);
    }

    snprintf(printBuf, sizeof(printBuf), "CDP INFO: %d entries in properties file for Custom Protocol Host Decode Levels", (int) evaluatedArguments.cdpDecodeHostsLevel.size());
    classifyStartPrintOnce(printBuf, &pktbufNum);
    int idx = 0;

    for(list<int>::iterator itr = evaluatedArguments.cdpDecodeHostsLevel.begin(); itr != evaluatedArguments.cdpDecodeHostsLevel.end(); ++itr) {
        if(idx < IPOQUE_MAX_HTTP_CUSTOM_PROTOCOLS) {
            cdpHostDecodeDepth[idx] = *itr;
            snprintf(printBuf, sizeof(printBuf), "CDP INFO: Custom Protocol Host Decode Level for %s = %d", CDP_PROTOCOL_HTTP[idx], cdpHostDecodeDepth[idx]);
            classifyStartPrintOnce(printBuf, &pktbufNum);
            idx++;
        } else {
            snprintf(printBuf, sizeof(printBuf), "CDP INFO: No matchig Custom Protocol for property \'customProtocols_decodeLevelForHosts\' level %d", *itr);
            classifyStartPrintOnceError(printBuf, &pktbufNum);
        }
    }

    //cdpHostDecodeDepth[CDP_PROTOCOL_SPEEDTEST] = 1;
    //cdpHostDecodeDepth[CDP_PROTOCOL_WEATHER] = 2;
    //cdpHostDecodeDepth[CDP_PROTOCOL_MAPS] = 4;
    //cdpHostDecodeDepth[CDP_PROTOCOL_NEWS] = 1;
    //cdpHostDecodeDepth[CDP_PROTOCOL_ADVERTISEMENTS] = 3;
    //cdpHostDecodeDepth[CDP_PROTOCOL_SW_UPDATES] = 3;
    //cdpHostDecodeDepth[CDP_PROTOCOL_PHOTO_SHARING] = 2;
    configureCustomProtocolsAndGroups(cd, serviceProvider, pktbufNum);
    init_flow_hash_table(cd);
    init_subscriber_hash_table(cd);
    ipoque_pace_set_client_server_indication_mode(cd->ipq, IPOQUE_CLIENT_SERVER_INDICATION_ENABLED); //enable client server indication
    bzero(protocol_counters, (CAAP_MAX_PROTOCOLS + 1) * sizeof(u64));
    LOG4CXX_INFO(loggerClassify, "Starting Classification engine : IPOQUE Connection (Short/Normal/Long) Timeout = " <<  cd->ipqShortConnectionTimeout << "/" << cd->ipqNormalConnectionTimeout << "/" <<  cd->ipqLongConnectionTimeout << "/" << " [seconds]");
    LOG4CXX_DEBUG(loggerConsole, "Starting Classification engine : IPOQUE Connection (Short/Normal/Long) Timeout = " <<  cd->ipqShortConnectionTimeout << "/" << cd->ipqNormalConnectionTimeout << "/" <<  cd->ipqLongConnectionTimeout << "/" << " [seconds]");
    clearFlowCounters();
    clearTimeoutClassCounters();

    // THE NON Default string arrays
    // Idea was that these would be used to hold contents of an XML formatted files which could ne read at application startup
    if(evaluatedArguments.cdpDecodeExtraHosts) {
        cdpNonDefaultArrayEnabled = 1;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using EXTRA HOST information is Enabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    } else {
        cdpNonDefaultArrayEnabled = 0;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using EXTRA HOST information is Disabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    }

    // THE URL DECODE string arrays.
    if(evaluatedArguments.cdpcdpDecodeURL) {
        cdpURLdecodeEnabled = 1;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using URL information is Enabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    } else {
        cdpURLdecodeEnabled = 0;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using URL information is Disabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    }

    // THE USER AGENT DECODE string arrays.
    if(evaluatedArguments.cdpDecodeUserAgent) {
        cdpUserAgentDecodeEnabled = 1;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using USER AGENT information is Enabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    } else {
        cdpUserAgentDecodeEnabled = 0;
        snprintf(printBuf, sizeof(printBuf), "CDP INFO:(classify start): Decode Custom Protocols using USER AGENT information is Disabled");
        classifyStartPrintOnce(printBuf, &pktbufNum);
    }

    if(evaluatedArguments.fileOutputFormat.compare("legacy") == 0) {
        snprintf(printBuf, sizeof(printBuf), "LEGACY File output format selected");
        classifyStartPrintOnce(printBuf, &pktbufNum);
        pectFileOutputFormat_isPect = 0;
    } else if(evaluatedArguments.fileOutputFormat.compare("pect") == 0) {
        snprintf(printBuf, sizeof(printBuf), "PECT File output format selected");
        classifyStartPrintOnce(printBuf, &pktbufNum);
        pectFileOutputFormat_isPect = 1;
    } else { //unknown
        snprintf(printBuf, sizeof(printBuf), "UNKNOWN File output format: LEGACY will be selected");
        classifyStartPrintOnce(printBuf, &pktbufNum);
        pectFileOutputFormat_isPect = 0;
    }

    if(loggerClassifyCDPTimers->isDebugEnabled()) {
        LOG4CXX_INFO(loggerClassify, "Enabling CDP TIMERS for QUEUE " << pktbufNum);
        cdpTimersEnabled = 1;
    } else {
        cdpTimersEnabled = 0;
    }

    u64 numberFlowsSupported = (u64)(ipq_hash_size / cd->ipoqueTOHTotalSlotSize);
    u32 newIpoqueFlowSize = ipoque_pace_get_sizeof_flow_data(cd->ipq);
    LOG4CXX_INFO(loggerClassify, "FLOW CAPACITY For QUEUE " << pktbufNum << ": IPOQUE Hash size = " << ipq_hash_size << " Bytes"
                 << ": Flow Data size (ipoque_init/ipoque_now/user/total) = " << cd->ipoqueFlowSize << "/" << newIpoqueFlowSize << "/" << sizeof(struct flow_data) << "/" << cd->ipoqueTOHTotalSlotSize << " Bytes"
                 << ": => # Flows Supported (from ipoque/calculated) = " << IPOQUE_TOH_ELEMENTS(cd->connection_toh) << "/" << numberFlowsSupported);

    if(print_once == (evaluatedArguments.packetBufferSourceCount - 1)) {
        if(loggerFlowIntegrity->isDebugEnabled()) {
			test_flowID_intergity_header();
		}
        LOG4CXX_INFO(loggerBroadcast, "Packet Capture PreProcessor Started - " << pcp_version);
    }


    print_once++;
    return (cd);
}

/**
 * Deletes various variables.
 */
void classify_end(classify_data cd, unsigned int pbNum) {
    //efitleo: EQEV-14145: Attempt to solve problem of sikn streams not closing;
    //                     Added more logging
    LOG4CXX_INFO(loggerPcpGlue, "classify cleanup ... Starting " << pbNum);
    delete [] cd->uaBuffer;
    delete cd->clientFinder;
    LOG4CXX_INFO(loggerPcpGlue, "classify cleanup ... cleaning custom groups " << pbNum);

    if(custom_group_system.size() > 0) {
        custom_group_system.clear();
    }

    // dispose of the various ipoque data structures
    LOG4CXX_INFO(loggerPcpGlue, "classify cleanup ... cleaning ipoque data structures " << pbNum);
    free_ipoquePace_memory(cd);
    LOG4CXX_INFO(loggerPcpGlue, "classify cleanup ... cleaning classify data structure " << pbNum);
    free(cd);
    LOG4CXX_INFO(loggerPcpGlue, "classify cleanup ... Finished " << pbNum);
}

/*
 * calculates number seconds in epoch to last 00 seconds last ROP boundary time
 */
void calculateBoundryTime(double *theTime,  unsigned long long *ropBoundryTime) {
    // as unsigned long long  is an int, there should be no decmal palces
    unsigned long long numMinSinceEpoch = (unsigned long long)(*theTime / 60);
    *ropBoundryTime = numMinSinceEpoch * 60; // *ropStartTime in seconds
}
/*
 * Check if the Protocol , Application or Sub protocol (PAS) has changed since last packet
 *
 * @param flow_data *
 * @param int protocol
 * @param int subprotocol
 * @param int application_id
 * @param int *PAS_changed
 */
void check_PAS_Changed(flow_data *flow_data, unsigned int protocol, unsigned int application, unsigned int sub_protocol, int *PAS_changed) {
    *PAS_changed = 0;

    if(flow_data != NULL) {
        if((flow_data->protocol != protocol) && (protocol != UINT_MAX)) {
            *PAS_changed = 1;
        }

        if((flow_data->application != application) && (application != UINT_MAX)) {
            *PAS_changed = 1;
        }

        if((flow_data->sub_protocol != sub_protocol) && (sub_protocol != UINT_MAX)) {
            *PAS_changed = 1;
        }
    }
}

/**
 * Get the group associated with a protocol.
 *
 * @param classify_data
 * @param flow_data *
 * @param protocol
 * @param subprotocol
 * @param application_id
 * @param ServiceProvider *sp
 *
 */
void obtainProtocolGroup(classify_data cd, flow_data *flow_data, unsigned int protocol, unsigned int subprotocol, unsigned int application_id, ServiceProvider *sp) {
    // reset the group to zero incase the protocol has changed and thus requires it to be in a new group.
    // Note: Un doing this change "reset group to zero" in version 37-A8:
    //       Groups that depended on SSL for detection by IPOQUE were not getting grouped correctly, specifically those related to stocks, gaming and emial
    //       reckon that the grouping was set in the first few packets for protocol SSL, reseting group to zero meant that flows was grouped as tunnel or generic incorrectly.
    //       Checked system group for presence of RTP protocol (reason change was put in in the first place)
    //       All looks OK: Reckon that fixed by correct initialisation and " custom_group_Itr = custom_group_system.end()" in obtainProtocolGroup method.
    //flow_data->group = IPOQUE_GROUP_GENERIC;
    int the_PAS_has_changed = 0;
    check_PAS_Changed(flow_data, protocol, application_id, subprotocol, &the_PAS_has_changed);

    if(the_PAS_has_changed) {
        unsigned int last_group = flow_data->group;
        std::tr1::unordered_map<unsigned int, unsigned int>::iterator custom_group_Itr;
        custom_group_Itr = custom_group_system.end();
        custom_group_Itr = custom_group_system.find(protocol);

        if(custom_group_Itr != custom_group_system.end()) {
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 5; // SYSTEM is IPOQUE_NUMBER_OF_GROUPS + 5
            return;
        }

        if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 1)) { // speed test
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 1;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 2)) { //weather cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 2;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 3)) { //maps cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 3;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 4)) { //News cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 4;
        } else if(protocol == (IPOQUE_PROTOCOL_USENET)) { //NEWS NTTP
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 4;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 5)) { //advertisement cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 6;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 6)) { //software_update cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 7;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 7)) { //photo_sharing cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 8;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 8)) { //LLMNR cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 5;             // SYSTEM is IPOQUE_NUMBER_OF_GROUPS + 5
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 9)) { //flurry cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 6;              // advertisement  group
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 10)) { //andomedia cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 6;               // advertisement  group
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 11)) { //admob cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 6;              // advertisement  group
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 12)) { //symantec cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 7;              // software_update  group
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 13)) { //mcafee cdp
            flow_data->group = IPOQUE_NUMBER_OF_GROUPS + 7;              // software_update  group
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 14)) { //teamlava cdp
            flow_data->group = IPOQUE_GROUP_GAMING;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 15)) { // SpeedyShare cdp is a file sharing /P2P; but put it in generic as Service Provider want to distinguish it seperately
            flow_data->group = IPOQUE_GROUP_GENERIC;
        } else if(protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 16)) { // Slacker cdp ; Internet radio => Streaming or audio
            flow_data->group = IPOQUE_GROUP_STREAMING;
        } else {
            if((application_id != UINT_MAX) && (application_id < ((unsigned int) IPOQUE_NUMBER_OF_APPLICATIONS))) {
                flow_data->group =  ipoque_pace_get_application_group(cd->ipq, (u32) application_id);
            }

            if(flow_data->group <= 1) { // can't group by application ; IPOQUE_APPLICATION_NOT_DETECTED == 1
                if((subprotocol != UINT_MAX) && (subprotocol <= ((unsigned int) IPOQUE_MAX_SUPPORTED_SUB_PROTOCOLS))) {
                    flow_data->group = ipoque_pace_get_current_group(cd->ipq, (u16) protocol, (u16) subprotocol);
                } else {
                    flow_data->group = ipoque_pace_get_default_group(cd->ipq, (u16) protocol);
                }
            }
        }

        // set SP based on group
        if(last_group != flow_data->group) {
            sp->getGroupServiceProvider(flow_data, protocol, application_id) ;
        }
    }
}

/**
 * Get the URI Extension from the URL in the flow.
 *
 * @param classify_data
 * @param extension
 *
 * If the TCP Flow was part of a HTTP Transfer,
 * get the last part of the URL, i.e. html, mp3, flv.
 * The length of the URI extension must be between 2 and 10 chars.
 */
void extractUriExtension(classify_data cd, flow_data *flow_data) {
    //if(strcmp(flow_data->uriExtension, EMPTY_INT_STRING) == 0 && ipoque_detection_is_http_connection(cd->ipq)) {
    if(flow_data->uri_extension_not_set && flow_data->isHttpConnection) {
        // If the uriExtension is not populated yet, and we're a HTTP connection
        unsigned char *url = NULL;
        u16 urllen = 0;
        int URL_LENGTH = 3000;
        // Initialise url and urllen with the call to IPOQUE.
        ipoque_detection_get_http_request_url(cd->ipq, &url, &urllen);

        // Check for URL abnormalities.
        if(url == NULL || urllen > URL_LENGTH) {
            return;
        }

        // Extract the URI Extension from the URL.
        // Find the position of the dot, by moving forward through the URL.
        int dotPosition = 0;
        int urlLength = (int)(urllen - (u16)1);

        while(dotPosition <= urlLength) {
            if(url[dotPosition] == '?' || dotPosition == urlLength) {
                // We've hit a query string character, or There's no dot in the URL, just return;
                return;
            } else if(url[dotPosition] == '.' && islower(url[dotPosition + 1])) {
                // We have arrived at a dot, and the next character, after the dot, is a lowercase letter, satisfactory criteria.
                dotPosition++;
                break;
            } else {
                // Nothing of interest found, increment counter.
                dotPosition++;
            }
        }

        // Add the chars in front of the dot to the extension char array.
        int i;

        for(i = 0; dotPosition <= urlLength + 1 && (i < MAX_URI_EXTENSION_LENGTH); i++) {
            if(i < MAX_URI_EXTENSION_LENGTH && isalnum(url[dotPosition]) && url[dotPosition] != '\0' && url[dotPosition] != '?') {
                // We are inside the length of the URI, we're at an alphanumeric char, not a the NULL terminator and not at a question mark.
                flow_data->uriExtension[i] = url[dotPosition];
            } else {
                flow_data->uriExtension[i] = '\0';
                break;
            }

            dotPosition++;
        }

        flow_data->uriExtension[MAX_URI_EXTENSION_LENGTH - 1] = '\0';
        int uriExtensionLen = i;

        // Check that URI temp is not null and between the sizes specified by the IWD.
        if((uriExtensionLen >= MIN_URI_EXTENSION_LENGTH) && (uriExtensionLen <= MAX_URI_EXTENSION_LENGTH)) {
            LOG4CXX_TRACE(loggerClassify, "URI Extension: " << flow_data->uriExtension);
            flow_data->uri_extension_not_set = 0;
        } else {
            flow_data->uriExtension[0] = '\\';
            flow_data->uriExtension[1] = 'N';
            flow_data->uriExtension[2] = '\0';
        }
    }

    return;
}

/**
 * Get the number of bytes of payload data received in a TCP flow, less the headers.
 *
 * @param classify_data
 * @param extension
 * @param isTcpPacket
 *
 * From IWD:
 * DATA RECEIVED, Data Bytes, bytes, 0 - 2147483647, TCP payload (without IP and other headers).
 */

void extractDataReceived(classify_data cd, flow_data *flow_data, bool isTcpPacket) {
    if(isTcpPacket) {
        u16 dataReceived = ipoque_detection_get_payload_length(cd->ipq);

        if(dataReceived > MIN_DATA_RECEIVED_PER_PACKET && dataReceived <= MAX_DATA_DECEIVED_PER_PACKET) {
            flow_data->dataReceived += dataReceived;
        }
    }
}

/*
 * Updates a session and locks that session. Also locks the main map
 */
void incrementFlowCounters(struct ipoque_detection_module_struct *ipqStruct, int queue_num, u8 new_element, flow_data *flow_data, unsigned int protocol, unsigned int application, unsigned int sub_protocol,
                           u_int32_t theIPForHashSearch, const struct PectPacketHeader *pectHeader, const PacketDirection_t direction,
                           const struct flow_latency_struct *latency, int *checkServiceProvider) {
    flow_data->fourTuple = pectHeader->fourTuple;
    const pcap_pkthdr *pcapHeader = &(pectHeader->pcapHeader);

    if(flow_data != NULL) {
        // Generic increments/assignments
        flow_data->bytes += pcapHeader->caplen;
        flow_data->tpTotalBytes += pcapHeader->caplen;

        if((flow_data->protocol != protocol) && (protocol != UINT_MAX)) {
            flow_data->protocol = protocol;
            *checkServiceProvider = 1;
        }

        if((flow_data->application != application) && (application != UINT_MAX)) {
            flow_data->application = application;
            *checkServiceProvider = 1;
        }

        if((flow_data->sub_protocol != sub_protocol) && (sub_protocol != UINT_MAX)) {
            flow_data->sub_protocol = sub_protocol;
            *checkServiceProvider = 1;

            if((pectFileOutputFormat_isPect) || (loggerCaptoolExtendedOutput->isDebugEnabled()))  {
                getSubProtocolString(ipqStruct, (u16) protocol, (u16) sub_protocol, flow_data->sub_protocol_str);
            }
        }

        flow_data->queueNumber = queue_num;

        // Check packet size
        if(pcapHeader->len > flow_data->maxPacketLength) {
            flow_data->maxPacketLength = pcapHeader->len;
        }

        // Direction specific increments/assignments
        switch(direction) {
            case HEADING_TO_INTERNET:
                flow_data->packetsUp++;
                flow_data->ueToInternetDataBytes += pectHeader->userPacketSize;

                // Heading to internet, synack/ack is just available: Client initiated connection (client latency)
                if(flow_data->clientLatency == UINT_MAX && latency->diff_synack_ack_possible) {
                    flow_data->clientLatency = latency->diff_synack_ack;
                }

                // Heading to internet, syn/synack is just available: Server initiated connection (client latency)
                if(flow_data->clientLatency == UINT_MAX && latency->diff_syn_synack_possible) {
                    flow_data->clientLatency = latency->diff_syn_synack;
                }

                flow_data->ueMaxReceiverWindowSize = std::max(flow_data->ueMaxReceiverWindowSize, pectHeader->windowsSize);//package sent by ue
                break;

            case HEADING_TO_USER_EQUIPMENT:
                flow_data->packetsDown++;
                flow_data->internetToUeDataBytes += pectHeader->userPacketSize;

                // Heading to client, synack/ack is just available: Server initiated connection (server latency)
                if(flow_data->serverLatency == UINT_MAX && latency->diff_synack_ack_possible) {
                    flow_data->serverLatency = latency->diff_synack_ack;
                }

                // Heading to client, syn/synack is just available: Client initiated connection (server latency)
                if(flow_data->serverLatency == UINT_MAX && latency->diff_syn_synack_possible) {
                    flow_data->serverLatency = latency->diff_syn_synack;
                }

                flow_data->serverMaxReceiverWindowSize = std::max(flow_data->serverMaxReceiverWindowSize, pectHeader->windowsSize); //package sent by server
                break;

            default:
                LOG4CXX_WARN(loggerClassify,
                             "Unknown packet direction, unable to increment appropriate counters for UE IP " << std::hex << theIPForHashSearch);
                break;
        }

        // Increments that depend if this is a new element or not
        double packetTime = (double) pcapHeader->ts.tv_sec + (double) pcapHeader->ts.tv_usec / 1e6;

        switch(new_element) {
            case 0: // Not a new element
                if(packetTime < flow_data->firstPacketTime) {
                    flow_data->firstPacketTime = std::min(flow_data->firstPacketTime, packetTime);  // Handle out of order packets
                    // ENABLE THIS When ROP counter sorted. o/e ROP counter may be incorrect
                    // getFirstPacketRopBoundryTime(flow_data);  // recalculate
                    //TODO  recalculate rop counter for out of order packet.
                } else {
                    flow_data->firstPacketTime = std::min(flow_data->firstPacketTime, packetTime);  // Handle out of order packets
                }

                flow_data->firstPacketTimeInRop = std::min(flow_data->firstPacketTimeInRop, packetTime); //firstPacketTimeInRop set to DOUBLE_MAX per ROP
                flow_data->lastPacketTime = std::max(flow_data->lastPacketTime, packetTime);
                flow_data->lastPacketTime_us = std::max(flow_data->lastPacketTime_us, pectHeader->packetTime_uS) ;
                break;

            default:
                flow_data->firstPacketTime = packetTime;
                flow_data->firstPacketTimeInRop = packetTime;
                flow_data->lastPacketTime = packetTime;
                flow_data->lastPacketTime_us = pectHeader->packetTime_uS;
                getFirstPacketRopBoundryTime(flow_data);
                break;
        }

        if((pectHeader->isTcpPacket) || (flow_data->isTcpFlow)) {
            tpTimer(flow_data, &(pectHeader->packetTime_uS), pectHeader->packetDirection);
        }

        flow_data->durationThisRop = flow_data->lastPacketTime - flow_data->firstPacketTimeInRop ;
    }
}

void prepareFileWriterROP(const struct PectPacketHeader *pectHeader, classify_data cd, int queue_num) {
    // Do the copy if we need to
    size_t packetTimeLastMinute = pectHeader->pcapHeader.ts.tv_sec
                                  - (pectHeader->pcapHeader.ts.tv_sec
                                     % (evaluatedArguments.outputReportingPeriod * 60));

    if(packetTimeLastMinute != cd->flowsLastProduced) {
        struct timeval start, stop;
        gettimeofday(&start, NULL);
        FileWriterMapManager *manager = FileWriterMapManager::getInstance();
        FileWriterMap *map = manager->getMap(queue_num);
        FileWriterMap::IpqHashForEachCallbackStruct_t callbackStruct;
        callbackStruct.map = map;
        callbackStruct.tv = pectHeader->pcapHeader.ts;
        map->lockMap();
        ipoque_to_hash_foreach(cd->connection_toh, FileWriterMap::ipqHashForEachCallback, &callbackStruct);
        map->unlockMap();
        //LOG4CXX_INFO(loggerClassify, "prepareFileWriterROP: Queue " << queue_num << " copied [" << map->mapStatistics.flowsCopied << "/" << map->mapStatistics.totalFlows << "]" << ": packetTimeLastMinute = " << packetTimeLastMinute << ": cd->flowsLastProduced = " << cd->flowsLastProduced);
        cd->flowsLastProduced = packetTimeLastMinute;
        manager->produceMap(queue_num);
        gettimeofday(&stop, NULL);
        unsigned long long diff = ((stop.tv_sec - start.tv_sec) * 1000) + ((stop.tv_usec - start.tv_usec) / 1000);

        //efitleo :  Multiple Timeout Queues
        if(loggerClassify->isDebugEnabled()) {
            LOG4CXX_DEBUG(loggerClassify, "prepareFileWriterROP: Queue " << queue_num << " copied [" << map->mapStatistics.flowsCopied << "/"
                          << map->mapStatistics.totalFlows << "] in " << diff << " milliseconds"
                          << ": Subscriber Hash Stats: Num Elements (Currently Used / Max Used / Max Size) " << IPOQUE_TOH_QUEUE_LEN(cd->subscriber_toh)
                          << "/" << IPOQUE_TOH_QUEUE_MAX_LEN(cd->subscriber_toh) << "/" << IPOQUE_TOH_ELEMENTS(cd->subscriber_toh)
                          << ": Connection Hash Stats: Num Elements (Currently Used / Max Used / Max Size) " << IPOQUE_TOH_QUEUE_LEN(cd->connection_toh) << "/"
                          << IPOQUE_TOH_QUEUE_MAX_LEN(cd->connection_toh) << "/" << IPOQUE_TOH_ELEMENTS(cd->connection_toh) << ": Flow Timeout Class: (# Short / # Medium / # Long / # Unknown) "
                          <<  map->mapStatistics.numShortTimeout << "/" <<  map->mapStatistics.numMediumTimeout << "/" <<  map->mapStatistics.numLongTimeout
                          << "/" <<  map->mapStatistics.numUnknownTimeout);
        } else {
            LOG4CXX_INFO(loggerClassify, "prepareFileWriterROP: Queue " << queue_num << " copied [" << map->mapStatistics.flowsCopied << "/"
                         << IPOQUE_TOH_QUEUE_LEN(cd->connection_toh) << "(" << map->mapStatistics.totalFlows << ")] in " << diff << " milliseconds ");
        }

        if(loggerClassify->isTraceEnabled()) {
            LOG4CXX_TRACE(loggerClassify, "THOURGHPUT Seq map stats: Queue[" << queue_num << "] UE Maxed[" << map->mapStatistics.ueSeqMapMaxedCount << "] Inet Maxed["
                          << map->mapStatistics.inetSeqMapMaxedCount << "]");
        }

        map->resetMapStatistics();
        //TODO: CALL function dump_hash_table(cd) here to print all flows in hash table; Currently prints to screen. Must print to log under "trace" logging
    }
}

void putURLinHost(classify_data cd, struct flow_data *flow_data, const char *theTitle) {
    unsigned char *url = NULL;
    unsigned char *url_buffer = NULL;
    u16 url_len = 0;
    /* get the HTTP URL information */
    ipoque_detection_get_http_request_url(cd->ipq, &url, &url_len);

    /* if URL is available,  */
    if(url != NULL) {
        url_buffer = url;

        for(int idx1 = 0; idx1 < url_len; idx1++) {
            if((*url_buffer == ' ')  || (*url_buffer == '\t')  || (*url_buffer == '\r') || (*url_buffer == '\n')) {
                *url_buffer = '_';
            }

            url_buffer++;
        }

        if(url_len >= MAX_HOST_NAME_SIZE) {
            url_len = MAX_HOST_NAME_SIZE - 1;
        }

        memcpy(flow_data->host, theTitle, strlen(theTitle));
        const char *theURL = "URL:\0";
        memcpy(flow_data->host + strlen(theTitle), theURL, strlen(theURL));
        memcpy(flow_data->host + strlen(theTitle) + strlen(theURL), url, url_len);
        size_t  hostLen = strlen(theTitle) + strlen(theURL) + url_len ;
        flow_data->host[hostLen] = '\0';
    } else {
        memcpy(flow_data->host, theTitle, strlen(theTitle));
        const char *theURL = "URL=NULL:\0";
        memcpy(flow_data->host + strlen(theTitle), theURL, strlen(theURL));
        size_t hostLen =  strlen(theTitle) +  strlen(theURL) + url_len ;
        flow_data->host[hostLen] = '\0';
    }
}

/**
 * Provides processing to the packets collected using the PCAP library (classification and stats).
 */
void classify(classify_data cd, int queue_num, const struct PectPacketHeader *pectHeader, const u_char *packet, ServiceProvider *serviceProvider) {
    prepareFileWriterROP(pectHeader, cd, queue_num);
    const pcap_pkthdr *header = &(pectHeader->pcapHeader);
    //unsigned int ipoqueFlowSize = ipoque_pace_get_sizeof_flow_data(cd->ipq);
    unsigned int sub_protocol = UINT_MAX;
    unsigned int application = UINT_MAX; // no applciation detected
    unsigned int protocol = UINT_MAX;
    u8 new_element = 0;
    struct ipoque_flow_struct *flow = NULL;
    struct flow_data *flow_data = NULL;
    u32 timestamp = ((u32) header->ts.tv_sec) * IPQ_TICK_RESOLUTION
                    + (u32)header->ts.tv_usec / (1000000 / IPQ_TICK_RESOLUTION);
    //collect the type in order to ensure the size of the packet is adjusted correctly
    const struct ether *ethernet = (struct ether *) packet;
    u16 type = ethernet->type;
    //collect the additional information tacked onto the packet when it gets written to the packet buffer
    u_int32_t theUEIPForHashSearch = pectHeader->fourTuple.ueIP;
    PacketDirection_t packetDirection =  pectHeader->packetDirection;
    struct iphdr *iph = (struct iphdr *)(&packet[sizeof(struct ether)]);
    int size = header->caplen - (int) sizeof(struct ether);
    int check_service_provider = 0;

    // If the packet is VLAN tagged
    if(type == htons(ETH_P_8021Q)) {
        // TODO: replace use of ether struct in favour of the if_ether.h definition: ethhdr
        iph = (struct iphdr *)(&packet[sizeof(struct ether) + 4]);
        size -= 4;
    }

    if(size > 0) {
        if(cd->connection_toh != NULL) {
            ipoque_to_hash_set_timestamp(cd->connection_toh, timestamp);
        } else {
            struct in_addr ueipToSearchFor;
            ueipToSearchFor.s_addr = htonl(theUEIPForHashSearch);
            LOG4CXX_INFO(loggerClassify,
                         "CONNECTION TIME ORDERED HASH: Set timestamp NOT executed for ueip =  " << inet_ntoa(ueipToSearchFor));
            LOG4CXX_DEBUG(loggerConsole,
                          "CONNECTION TIME ORDERED HASH: Set timestamp NOT executed for ueip =  " << inet_ntoa(ueipToSearchFor));
        }

        /*
         * EMILAWL:
         *
         * IPOQUE tracks the flows, we have our user data placed after their flow data.
         * When we get the flow pointer we first put it into IPOQUES format,
         * if IPOQUE tells us that we have a new flow then we reset the memory before further processing
         * we then run the required IPOQUE library calls and get the classification for the current packet
         * finally we update the users info with incrementFlowCounters
         * before this function we cast to our data type and update the fields as required.
         */
        flow = NULL;
        flow = (struct ipoque_flow_struct *) ipoque_get_current_flow_decapsulate(cd->ipq, cd->connection_toh, iph,
                (u16) size, &new_element);
        check_service_provider = 0;
		
        if(flow != NULL) {
            check_service_provider = 0;

            if(cdpTimersEnabled) {
                cdpAdvertsTimer.queueNum = queue_num;
                cdpMapsTimer.queueNum = queue_num;
                cdpNewsTimer.queueNum = queue_num;
                cdpPhotoTimer.queueNum = queue_num;
                cdpSWuTimer.queueNum = queue_num;
                cdpSpeedTimer.queueNum = queue_num;
                cdpWeatherTimer.queueNum = queue_num;
                cdpLlmnrTimer.queueNum = queue_num;
                int hostNum;

                for(hostNum = 0; hostNum < MAX_SIMPLE_HOSTS; hostNum++) {
                    cdpSimpleHostTimer[hostNum].queueNum = queue_num;
                }
            }

            if(new_element != 0) {
                hashTableCtrs.totalNumNewFlows[queue_num]++;
                bzero(flow, cd->ipoqueTOHTotalSlotSize);
                flow_data = (struct flow_data *)((char *) flow + cd->ipoqueFlowSize);
                flow_data->init();
                flow_data->hashKey = pectHeader->fourTuple.ueIP;
                hashTableCtrs.numFlowsAdded[queue_num]++;
                hashTableCtrs.numFlowsAddedThisROP[queue_num]++;

                // efitleo :  Multiple Timeout Queues : disable this ... to avoid confusion & it serves no purpose
                //if(loggerClassify->isTraceEnabled()) { // efitleo; all log messages are at level TRACE in flowTimeoutClass; So save a function call or two by this message
                //	flowTimeoutClass(cd);
                //}

                if(cdpTimersEnabled) {
                    cdpAdvertsTimer.numberOfFlowsChecked[queue_num]++;
                    cdpMapsTimer.numberOfFlowsChecked[queue_num]++;
                    cdpNewsTimer.numberOfFlowsChecked[queue_num]++;
                    cdpPhotoTimer.numberOfFlowsChecked[queue_num]++;
                    cdpSWuTimer.numberOfFlowsChecked[queue_num]++;
                    cdpSpeedTimer.numberOfFlowsChecked[queue_num]++;
                    cdpWeatherTimer.numberOfFlowsChecked[queue_num]++;
                    cdpLlmnrTimer.numberOfFlowsChecked[queue_num]++;
                    int hostNum;

                    for(hostNum = 0; hostNum < MAX_SIMPLE_HOSTS; hostNum++) {
                        cdpSimpleHostTimer[hostNum].numberOfFlowsChecked[queue_num]++; ;
                    }
                }

                //cdpAdvertsData.ptrToFlowDataStruct = flow_data;
                //cdpMapsData.ptrToFlowDataStruct = flow_data;
                //cdpNewsData.ptrToFlowDataStruct = flow_data;
                //cdpPhotoData.ptrToFlowDataStruct = flow_data;
                //cdpSWuData.ptrToFlowDataStruct = flow_data;
                //cdpSpeedData.ptrToFlowDataStruct = flow_data;
                //cdpWeatherData.ptrToFlowDataStruct = flow_data;
            } else {
                flow_data = (struct flow_data *)((char *) flow + cd->ipoqueFlowSize);
                
            }

            if(cd->subscriber_toh != NULL) {
                ipoque_to_hash_set_timestamp(cd->subscriber_toh, timestamp);
            } else {
                struct in_addr ueipToSearchFor;
                //TODO clean up network/host order
                ueipToSearchFor.s_addr = htonl(theUEIPForHashSearch);
                LOG4CXX_DEBUG(loggerClassify,
                              "SUBSCRIBER TIME ORDERED HASH: Set timestamp NOT executed for ueip = " << inet_ntoa(ueipToSearchFor));
            }

            //initCdpDetectionData(cd->ipq,flow_data);
            cd->fourTuple = pectHeader->fourTuple;  //need to be set here for Custom Protocol detection LLMNR
            uint8_t *iph_p;
            iph_p = (uint8_t *) iph;
            protocol = ipoque_detection_process_packet_fastpath(cd->ipq, flow, iph_p,
                       ((unsigned short)(header->caplen - (int) sizeof(struct ether))), timestamp);

            if(protocol == IPOQUE_DETECTION_FASTPATH_NOT_USED) {
                struct ipoque_id_struct *src = NULL;
                struct ipoque_id_struct *dst = NULL;
                src = (struct ipoque_id_struct *) ipq_get_id((u8 *) & (pectHeader->userPacketIPHeader->saddr), 0, cd);
                dst = (struct ipoque_id_struct *) ipq_get_id((u8 *) & (pectHeader->userPacketIPHeader->daddr), 0, cd);
                protocol = ipoque_detection_process_packet_slowpath(cd->ipq, src, dst);
                sub_protocol = ipoque_detection_get_protocol_subtype(cd->ipq);
                application = ipoque_pace_get_application_id(cd->ipq);
                // efitleo :  Multiple Timeout Queues; hash insert function is in ipq_get_id() So this need to go here. (ref intergation manual)
                flow_data->flowTimeoutClass = getFlowTimeoutClass(cd, queue_num);

                if(flow_data->flowTimeoutClass < 0) {
                    struct in_addr ueipToSearchFor;
                    ueipToSearchFor.s_addr = htonl(theUEIPForHashSearch);
                    LOG4CXX_ERROR(loggerClassify, "TIMEOUT: Unable to set the flow Timeout class for flow with ueip = " << inet_ntoa(ueipToSearchFor));
                }

                /* if(loggerClassify->isTraceEnabled()) {
                	   char buf[20];
                	   snprintf(buf,sizeof(buf), "TIMEOUT: %d ",flow_data->flowTimeoutClass);
                	   struct PectIP4Tuple theFourTupleForPrint = pectHeader->fourTuple;
                	   debugPrintIPInfo((const char *) buf, &(theFourTupleForPrint));
                } */
            }
            if(loggerFlowIntegrity->isDebugEnabled()) {
				test_flowID_intergity(cd, iph, (u16) size, flow_data, pectHeader,  &new_element,  flow );
			}
			if(loggerFlowIntegrity->isTraceEnabled()) {
				helper_print_packet_details_and_flow_details_to_log(iph, &(pectHeader->pcapHeader), packet, pectHeader,flow_data, flow, cd, 1);
			}
            flow_data->isHttpConnection = ipoque_detection_is_http_connection(cd->ipq);  //returns > 0 for HTTP connection; 0 for non HTTP connection

            if(flow_data->isHttpConnection) {
                unsigned char *host = NULL;      // max = 128
                unsigned char *content = NULL;   // max = 256
                unsigned char *content_buffer = NULL;
                unsigned char *host_buffer = NULL;
                unsigned char *userAgent = NULL;
                u16 hostLength = 0;
                u16 contentLength = 0;
                u16 userAgentLength = 0;
                ipoque_detection_get_http_host_user_and_content_type(cd->ipq, &host, &hostLength, &content, &contentLength, &userAgent, &userAgentLength);

                if(flow_data->hostNotSet && host != NULL) {
                    size_t  hostLenSoFar = 0;

                    if((loggerClassifyHostname->isDebugEnabled()) || (loggerClassifyHostname->isTraceEnabled())) {
                        struct PectIP4Tuple theFourTupleForPrint = pectHeader->fourTuple;

                        if((protocol != IPOQUE_PROTOCOL_HTTP) && (protocol <= MAX_SUPPORTED_PROTOCOLS)) {
                            //debugPrintIPInfo((const char *)"CLASSIFY: HOSTNAME\0", &(theFourTupleForPrint));
                            //debugPrintProtocolInfo((const char *)"CLASSIFY: HOSTNAME\0", host, hostLength, protocol);
                            hashTableCtrs.numFlowsHttpDependentHostName[queue_num]++;
                            const char *theTitle = "HTTPD_\0";
                            memcpy(flow_data->host, theTitle, strlen(theTitle));
                            memcpy(flow_data->host + strlen(theTitle), IPOQUE_protocol_short_str[protocol], strlen(IPOQUE_protocol_short_str[protocol]));
                            const char *theSpacer = "_\0";
                            hostLenSoFar = strlen(theTitle) + strlen(IPOQUE_protocol_short_str[protocol]);
                            memcpy(flow_data->host + hostLenSoFar, theSpacer, strlen(theSpacer));
                            hostLenSoFar = strlen(theTitle) + strlen(IPOQUE_protocol_short_str[protocol]) + strlen(theSpacer);
                        } else {
                            hashTableCtrs.numFlowsHttpHostName[queue_num]++;
                            const char *theTitle = "HTTP_http_\0";
                            memcpy(flow_data->host, theTitle, strlen(theTitle));
                            hostLenSoFar = strlen(theTitle);
                        }

                        if(flow_data->hostnameAddedToStats_HttpNoHostName) { // if its been added to the other HTTP counter
                            hashTableCtrs.numFlowsHttpNoHostName[queue_num]--;
                            flow_data->hostnameAddedToStats_HttpNoHostName = 0;
                        }

                        if(flow_data->hostnameAddedToStats_NonHttpNoHostName) { // if its been added to the other non HTTP counter
                            hashTableCtrs.numFlowsNonHttpNoHostName[queue_num]--;
                            flow_data->hostnameAddedToStats_NonHttpNoHostName = 0;
                        }
                    }

                    host_buffer = host;

                    for(int idx1 = 0; idx1 < hostLength; idx1++) {
                        if((*host_buffer == ' ')  || (*host_buffer == '\t')  || (*host_buffer == '\r') || (*host_buffer == '\n')) {
                            *host_buffer = '_';
                        }

                        host_buffer++;
                    }

                    if(hostLength >= MAX_HOST_NAME_SIZE) {
                        hostLength = MAX_HOST_NAME_SIZE - 1;
                    }

                    memcpy(flow_data->host + hostLenSoFar, host, hostLength);
                    flow_data->host[hostLength + hostLenSoFar] = '\0';
                    flow_data->hostNotSet = false;
                } else { // Host is NULL
                    if((loggerClassifyHostname->isDebugEnabled()) || (loggerClassifyHostname->isTraceEnabled())) {
                        if(flow_data->hostNotSet) {
                            //debugPrintURLInfo((const char *)"CLASSIFY: HTTP: URL\0",cd->ipq);
                            if(!flow_data->hostnameAddedToStats_HttpNoHostName) {
                                hashTableCtrs.numFlowsHttpNoHostName[queue_num]++;
                                flow_data->hostnameAddedToStats_HttpNoHostName = 1;

                                if(flow_data->hostnameAddedToStats_NonHttpNoHostName) { // if its been added to the other non HTTP counter
                                    hashTableCtrs.numFlowsNonHttpNoHostName[queue_num]--;
                                    flow_data->hostnameAddedToStats_NonHttpNoHostName = 0;
                                }
                            }

                            putURLinHost(cd, flow_data, (const char *)"HTTP_NO_HOST:\0");
                        }
                    }
                }

                if(flow_data->contentTypeNotSet && content != NULL) {
                    content_buffer = content;

                    for(int idx2 = 0; idx2 < contentLength; idx2++) {
                        if((*content_buffer == ' ')  || (*content_buffer == '\t')  || (*content_buffer == '\r') || (*content_buffer == '\n')) {
                            *content_buffer = '_';
                        }

                        content_buffer++;
                    }

                    if(contentLength >= MAX_CONTENT_TYPE_SIZE) {
                        contentLength = MAX_CONTENT_TYPE_SIZE - 1;
                    }

                    memcpy(flow_data->contentType, content, contentLength);
                    flow_data->contentType[contentLength] = '\0';
                    flow_data->contentTypeNotSet = false;
                }

                // flow_data->userAgentNotSet initialised to a positive number. decrement each time search fails; Only check limited number of times
                if(flow_data->userAgentNotSet && userAgent != NULL && userAgentLength > 0) {
                    int result = -1;
                    result = cd->clientFinder->findClientFromUserAgentMemSearch(userAgent, userAgentLength, flow_data->host);

                    if(result >= 0) {
                        //LOG4CXX_INFO(loggerClassify, "CLIENT FINDER: Match index (userAgentNotSet) = " << flow_data->userAgentNotSet );
                        flow_data->client = result;
                        flow_data->userAgentNotSet = 0;
                        check_service_provider = 1;
                    } else {
                        flow_data->userAgentNotSet--;
                    }

                    //fail safe
                    if(flow_data->userAgentNotSet < 0) {
                        flow_data->userAgentNotSet = 0;
                    }
                }
            } else {
                if((loggerClassifyHostname->isDebugEnabled()) || (loggerClassifyHostname->isTraceEnabled())) {
                    if(flow_data->hostNotSet) {
                        if(!flow_data->hostnameAddedToStats_NonHttpNoHostName) {
                            hashTableCtrs.numFlowsNonHttpNoHostName[queue_num]++;
                            flow_data->hostnameAddedToStats_NonHttpNoHostName = 1;
                        }

                        putURLinHost(cd, flow_data, (const char *)"NON_HTTP_NO_HOST:\0");
                    }
                }
            }

            extractUriExtension(cd, flow_data);
            obtainProtocolGroup(cd, flow_data, protocol, sub_protocol, application, serviceProvider);
            extractDataReceived(cd, flow_data, pectHeader->isTcpPacket);
            struct ipoque_pace_client_server_indication_host_status hostSrc;
            struct ipoque_pace_client_server_indication_host_status hostDst;

            if(0 == ipoque_pace_get_host_client_server_indication(cd->ipq, &hostSrc, &hostDst)) { //if it's valid update flow data
                if(pectHeader->packetDirection == HEADING_TO_INTERNET) {
                    flow_data->ueHost = hostSrc;
                    flow_data->serverHost = hostDst;
                } else {
                    flow_data->ueHost = hostDst;
                    flow_data->serverHost = hostSrc;
                }
            }

            const struct flow_latency_struct *latency = ipoque_detection_get_flow_latency_result(cd->ipq, flow);
            flow_data->queueNumber = queue_num; // also set in incrementFlowCounters

            if((pectHeader->isTcpPacket) || (flow_data->isTcpFlow)) {
                if(new_element != 0) {
                    flow_data->isTcpFlow = true;
                    pktLossInitialiseMaps(flow_data, pectHeader->fourTuple);

                    if(loggerPacketLoss->isTraceEnabled())
                        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS: Classify: INITIALISE NEW FLOW new_element (u8->int) =  " << (int) new_element
                                     << ": ueIP: port " << pectHeader->fourTuple.ueIP << ": " << pectHeader->fourTuple.uePort
                                     << ": Server: port " << pectHeader->fourTuple.serverIP << ": " << pectHeader->fourTuple.serverPort);
                }

                calculateTCPPacketLoss(flow_data, protocol, pectHeader, packetDirection, packet, &new_element, queue_num);
            }

            if(loggerClassify->isDebugEnabled() && packetDirection != -1 && flow_data->tunnelId.teids[packetDirection] != DEFAULT_FTEID && flow_data->tunnelId.teids[packetDirection] != pectHeader->teid_d) {
                LOG4CXX_DEBUG(loggerClassify, "Flow TEID_D changing mid-flow [" << flow_data->tunnelId.teids[packetDirection] << "->" << pectHeader->teid_d);
            }

            flow_data->tunnelId.teids[packetDirection] = pectHeader->teid_d;    // Store the TEID appropriately
            incrementFlowCounters(cd->ipq, queue_num, new_element, flow_data, protocol, application, sub_protocol, flow_data->hashKey,
                                  pectHeader, packetDirection, latency, &check_service_provider);

            if((loggerClassify->isTraceEnabled())) {
                //if((loggerClassify->isInfoEnabled())) {
                serviceProvider->printServiceProviderInfo(flow_data, (const char *) "PRINT INFO BEFORE", &check_service_provider);
            }

            if(check_service_provider) {
                serviceProvider->getServiceProvider(flow_data, &check_service_provider);

                if((loggerClassify->isTraceEnabled())) {
                    //if((loggerClassify->isInfoEnabled())) {
                    serviceProvider->printServiceProviderInfo(flow_data, (const char *) "PRINT INFO AFTER", &check_service_provider);
                }
            }
        }
    }
}
