// todo Add Ericsson C/C++ code file header.

// Local Includes
#include "flow.h"
#include "UE_map.hpp"
#include "classify.h"

// System Includes
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <list>
#include <time.h>
#include <boost/tr1/unordered_map.hpp>

using std::cout;
using std::cin;
using std::endl;
using std::hex;

extern int kRopDurationInMinutes;
//FileWriterFlowList file_writer_flows[MAX_NUM_FLOWS_SUPPORTED];
//FileWriterFlowList13A file_writer_flows_13A[MAX_NUM_FLOWS_SUPPORTED];
//ClassifierMapMutex classifierMutexLockArray[MAX_NUM_FLOWS_SUPPORTED];
extern EArgs evaluatedArguments;
//extern HashTableStatisticsStruct hashTableCtrs;


bool operator<(const timeval &lhs, const timeval &rhs) {
    // true if lhs seconds are less, or if seconds are equal and lhs nsec are less
    return (lhs.tv_sec < rhs.tv_sec || (lhs.tv_sec == rhs.tv_sec && lhs.tv_usec < rhs.tv_usec));
}

bool operator>(const timeval &lhs, const timeval &rhs) {
    // true if lhs seconds are more, or if seconds are equal and lhs nsec are more
    return (lhs.tv_sec > rhs.tv_sec || (lhs.tv_sec == rhs.tv_sec && lhs.tv_usec > rhs.tv_usec));
}

/*
 * Create a new entry in the UE tracker map.
 */
int insertNewUeIpAndFlowIntoHash(int queue_num, UEFlowMap_t &UE_IP_map, u_int32_t UE_addr, flow_data *flow) {
    /*
     * Make the new map,
     * Populate the UE map,
     * Add the flow for the current classification.
     */
    FlowList_t *theMapOfFlows = new FlowList_t();
    UE_IP_map[UE_addr] = theMapOfFlows;
    theMapOfFlows->push_back(flow);
    return 0;
}

/**
 * Look in the UE map and find out if you have to make a new entry or not
 * If you do add both the UE IP and the Flow.
 * If its not a new UE IP, only add the flow to is known flows if its a new flow.
 */
int insertIntoUeFlowTracker(int queue_num, u8 new_element, flow_data *flow, UEFlowMap_t &theMapToSearch,
                            u_int32_t UE_addr, const struct timeval &packetTime) {
    //classifierMutexLockArray[queue_num].lockMapMutex();
    //copy_map_to_buffer_every_minute(queue_num, theMapToSearch, packetTime);
    FlowList_t *foundList;
    UEFlowMap_t::iterator UE_it = theMapToSearch.find(UE_addr);

    if(new_element != 0) {
        if(UE_it != theMapToSearch.end()) {
            foundList = UE_it->second;
            foundList->push_back(flow);
        } else {
            insertNewUeIpAndFlowIntoHash(queue_num, theMapToSearch, UE_addr, flow);
        }
    }

    //classifierMutexLockArray[queue_num].unlockMapMutex();
    return 0;
}


void calculateTotalUniqueBytesAcknowledged(const flow_data *fd, unsigned long long *totalBytes) {
    *totalBytes = 0;
    unsigned long long totalByetsNotAcknowledged_ue, totalByetsNotAcknowledged_inet;
    unsigned long long totalBytes_ue, totalBytes_inet;
    totalByetsNotAcknowledged_inet = 0;
    totalByetsNotAcknowledged_ue = 0;
    totalBytes_inet = 0;
    totalBytes_ue = 0;

    if((fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] == 0) && (fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_INTERNET] == 0)) {
        return;
    }

    if((fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] >  fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT])
            && (fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]  > 0)
            && (fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]  > 0)) {
        totalByetsNotAcknowledged_ue = fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] -  fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
    }

    if((fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_INTERNET] > fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET])
            && (fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_INTERNET]  > 0)
            && (fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET]  > 0)) {
        totalByetsNotAcknowledged_inet = (fd->tcpPktLossInfo.highExpectedSeqNum[PKT_LOSS_HEADING_TO_INTERNET] -  fd->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET]);
    }

    if((fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > 0) &&
            (fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > totalByetsNotAcknowledged_ue)) {
        totalBytes_ue = fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - totalByetsNotAcknowledged_ue;
    }

    if((fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_INTERNET] > 0) &&
            (fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_INTERNET] > totalByetsNotAcknowledged_inet)) {
        totalBytes_inet = fd->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_INTERNET] - totalByetsNotAcknowledged_inet;
    }

    *totalBytes = totalBytes_ue + totalBytes_inet;
}

void calculateUniqueBytesAcknowledged(const flow_data *fd, unsigned long long *totalBytes, int direction) {
    *totalBytes = 0;
    uint32_t totalByetsNotAcknowledged;
    totalByetsNotAcknowledged = 0;

    if(fd->tcpPktLossInfo.tpUniqueBytes[direction] == 0) {
        return;
    }

    if((fd->tcpPktLossInfo.highExpectedSeqNum[direction] >  fd->tcpPktLossInfo.highAck[direction])
            && (fd->tcpPktLossInfo.highExpectedSeqNum[direction]  > 0)
            && (fd->tcpPktLossInfo.highAck[direction]  > 0)) {
        totalByetsNotAcknowledged = fd->tcpPktLossInfo.highExpectedSeqNum[direction] -  fd->tcpPktLossInfo.highAck[direction];
    }

    if((fd->tcpPktLossInfo.tpUniqueBytes[direction] > 0) &&
            fd->tcpPktLossInfo.tpUniqueBytes[direction] > totalByetsNotAcknowledged) {
        *totalBytes = fd->tcpPktLossInfo.tpUniqueBytes[direction] - totalByetsNotAcknowledged;
    } else {
        *totalBytes = 0;
    }

    if((loggerThroughput->isTraceEnabled())) {
        int bufSize = 2000;
        char buf[bufSize];
        snprintf(buf, bufSize, "Throughput Metrics calculateUniqueBytesAcknowledged: tpUniqueBytes = %llu, highSeq = %u, highAck = %u, totalByetsNotAcknowledged = %u, totalBytes [%d] = %llu, \n",
                 fd->tcpPktLossInfo.tpUniqueBytes[direction],
                 fd->tcpPktLossInfo.highSeq[direction],
                 fd->tcpPktLossInfo.highAck[direction],
                 totalByetsNotAcknowledged,
                 direction, *totalBytes);
        LOG4CXX_TRACE(loggerThroughput, buf);
    }
}
/**
 * A function that calculate the per-ROP fields of flow_data.
 * It calculates:
 *     Session Throughput,
 *     Throughput.
 *
 * @param flow_data
 */
void calculateFlowDataFields(flow_data *fd) {
    // ----- Session Throughput Start -----
    /* From IWD:
     * SESSION THROUGHPUT, Throughput, bits per second, 0 to 2^32 -1, IP-level throughput
     * (including parallel IP traffic of the same subscriber)
     */
    unsigned long ipBytes = fd->ueToInternetDataBytes + fd->internetToUeDataBytes;

    if((fd->tpDurationTotal + fd->tpBurstDurationTotal) > 0) {
        // Multiplying by eight here to get to the bits per second that session throughput is measured in.
        // fd->tpDuration is duration * PKTLOSS_RESOLUTION in packetloss.cc. So multiply numerator by PKTLOSS_RESOLUTION
        fd->sessionThroughput = (unsigned long)(((ipBytes * 8) * PKTLOSS_RESOLUTION) / (fd->tpDurationTotal + fd->tpBurstDurationTotal));

        if(fd->sessionThroughput > MAX_THROUGHPUT) {
            fd->sessionThroughput = MAX_THROUGHPUT;
        } else if(fd->sessionThroughput < MIN_THROUGHPUT) {
            fd->sessionThroughput = MIN_THROUGHPUT;
        }
    } else {
        fd->sessionThroughput = MIN_THROUGHPUT;
    }

    // ----- Session Throughput End -----
    // ----- Throughput Start -----
    /*
     * From IWD:
     * THROUGHPUT, Throughput, bits per second, 0..2^32 - 1, TCP payload-level throughput.
     */
    unsigned long long duration;
    unsigned long long totalBytes;
    // First Throughput based on bytes heading in both directions
    duration = (fd->tpDurationTotal + fd->tpBurstDurationTotal);

    if(duration > 0) {
        // Multiplying by eight here to get to the bits per second that session throughput is measured in.
        // fd->tpDuration is duration * PKTLOSS_RESOLUTION in packetloss.cc. So multiply numerator by PKTLOSS_RESOLUTION
        calculateTotalUniqueBytesAcknowledged(fd, &totalBytes);
        fd->throughput = (unsigned long)((totalBytes * 8 * PKTLOSS_RESOLUTION) / duration);

        if(fd->throughput > MAX_THROUGHPUT) {
            fd->throughput = MAX_THROUGHPUT;
        } else if(fd->throughput < MIN_THROUGHPUT) {
            fd->throughput = MIN_THROUGHPUT;
        }
    } else {
        fd->throughput = MIN_THROUGHPUT;
    }

    // Now seperate Up and down directions
    duration = (fd->tpDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + fd->tpBurstDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);

    if(duration > 0) {
        calculateUniqueBytesAcknowledged(fd, &totalBytes, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
        fd->throughput_heading_to_ue = (unsigned long)((totalBytes * 8 * PKTLOSS_RESOLUTION) / duration);

        if(fd->throughput_heading_to_ue > MAX_THROUGHPUT) {
            fd->throughput_heading_to_ue = MAX_THROUGHPUT;
        } else if(fd->throughput_heading_to_ue < MIN_THROUGHPUT) {
            fd->throughput_heading_to_ue = MIN_THROUGHPUT;
        }
    } else {
        fd->throughput_heading_to_ue = MIN_THROUGHPUT;
    }

    duration = (fd->tpDuration[PKT_LOSS_HEADING_TO_INTERNET] + fd->tpBurstDuration[PKT_LOSS_HEADING_TO_INTERNET]);

    if(duration > 0) {
        calculateUniqueBytesAcknowledged(fd, &totalBytes, PKT_LOSS_HEADING_TO_INTERNET);
        fd->throughput_heading_to_inet = (unsigned long)((totalBytes * 8 * PKTLOSS_RESOLUTION) / duration);

        if(fd->throughput_heading_to_inet > MAX_THROUGHPUT) {
            fd->throughput_heading_to_inet = MAX_THROUGHPUT;
        } else if(fd->throughput_heading_to_inet < MIN_THROUGHPUT) {
            fd->throughput_heading_to_inet = MIN_THROUGHPUT;
        }
    } else {
        fd->throughput_heading_to_inet = MIN_THROUGHPUT;
    }

    // ----- Throughput End -----
}

