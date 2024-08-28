/*
 * throughput.cc
 *
 *  Created on: 7 Jan 2014
 *      Author: efitleo
 */
#include "classify.h"
#include "flow.h"
#include "logger.hpp"

extern EArgs evaluatedArguments;
extern const unsigned short throughputThresholdFactor;
extern const unsigned long long throughputDefaultThreshold;


/*
 * set the PAUSE vs DELAY timeout value based on the following Algorithm
 * IF(RTT is available for this flow)
 *  timeOut_value  = Biggest of 1 Second or  6 x RTT
 * else
 *  timeOut_value  = 1 second
 *
 * Why 6 ?
 * Well the RTT measured by the IPOQUE function call is only 1/2 the RTT really (syn - synAck or synAck to ACK)
 *
 */
void tpSetThreshold(flow_data *flow_data, int direction) {
    // Note IPQ_TICK_RESOLUTION is used to define the clientLatency and serverLatency
    switch(direction) {
        case PKT_LOSS_HEADING_TO_INTERNET:
            if(flow_data->clientLatency != UINT_MAX) {
                flow_data->tpThreshold[direction] = (unsigned long long)((throughputThresholdFactor) * flow_data->clientLatency);

                if(flow_data->tpThreshold[direction] < throughputDefaultThreshold) {
                    flow_data->tpThreshold[direction] = throughputDefaultThreshold;
                }
            } else {
                flow_data->tpThreshold[direction] = throughputDefaultThreshold;
            }

            break;

        case PKT_LOSS_HEADING_TO_USER_EQUIPMENT:
            if(flow_data->serverLatency != UINT_MAX) {
                flow_data->tpThreshold[direction] = (unsigned long long)((throughputThresholdFactor) * flow_data->serverLatency);

                if(flow_data->tpThreshold[direction] < throughputDefaultThreshold) {
                    flow_data->tpThreshold[direction] = throughputDefaultThreshold;
                }
            } else {
                flow_data->tpThreshold[direction] = throughputDefaultThreshold;
            }

            break;

        default:
            LOG4CXX_WARN(loggerThroughput, "Throughput Metrics : Unknown packet direction  in tpSetThreshold, setting threshold to default ");
            flow_data->tpThreshold[direction] =  throughputDefaultThreshold;
            break;
    }
}

// to account for any errors in packet time, use tpLastPktTimeOfLastBurst
void  tpGetLastPacketTime(flow_data *flow_data, unsigned long long *returnedLastPacketTime_us, int direction) {
    *returnedLastPacketTime_us = flow_data->tpLastPktTimeOfLastBurst[direction];
}

/*
 * tpSetLastPacketTime_burstStarted called by tpDuration when a burst has started to keep a running total
 * Set this to highest ACK if available. o/w highest Seq, or LastPacketTime_us
 */
void  tpSetLastPacketTime_burstStarted(flow_data *flow_data, const unsigned long long *lastPacketTime_us, int direction) {
    if((flow_data->tpTimeLastBurstStarted[direction] > 0) && (flow_data->tpDurationStopwatchStarted[direction] == 1)) {
        if((flow_data->tcpPktLossInfo.highAckTime[direction] > 0) && (flow_data->tcpPktLossInfo.highAckTime[direction] > flow_data->tpTimeLastBurstStarted[direction])) {
            flow_data->tpLastPktTimeOfLastBurst[direction] = flow_data->tcpPktLossInfo.highAckTime[direction];
        } else if((flow_data->tcpPktLossInfo.highSeqTime[direction] > 0) && (flow_data->tcpPktLossInfo.highSeqTime[direction] > flow_data->tpTimeLastBurstStarted[direction])) {
            flow_data->tpLastPktTimeOfLastBurst[direction] = flow_data->tcpPktLossInfo.highSeqTime[direction];
        } else {
            flow_data->tpLastPktTimeOfLastBurst[direction] = *lastPacketTime_us;
        }
    } else {
        flow_data->tpLastPktTimeOfLastBurst[direction] = *lastPacketTime_us;
    }
}

/*
 *  Set this to highest ACK time if available o/w set to packet time
 *  This is organised by the values passed into LastPacketTime_us
 */
void  tpSetLastPacketTime(flow_data *flow_data, const unsigned long long *lastPacketTime_us, int direction) {
    flow_data->tpLastPktTimeOfLastBurst[direction] = *lastPacketTime_us;
}
/*
 * Call to return the time from Highest ACK if available/ o/w highest Seq time
 *
 */
void getLastAckTime(flow_data *flow_data, unsigned long long *lat, int direction, int *isDUPReTx) {
    unsigned long long lastAckTime;
    lastAckTime = 0;
    int isDupReTransmit;
    // Careful here to use direction as defined in packet loss
    checkBurstFinished(flow_data, direction, &isDupReTransmit);

    // Need to be non zero.
    if(flow_data->tpAckLastPacketTime[direction] != 0) {
        lastAckTime = flow_data->tpAckLastPacketTime[direction];
    }

    *lat = lastAckTime;
    *isDUPReTx = isDupReTransmit;
}
/*
 * Calculates the last ROP boundary time in uS
 */
void getTPLastRopBoundryTime(flow_data *flow_data,  const unsigned long long *packetTime_uS) {
    flow_data->tpLastRopBoundryTime = *packetTime_uS - (*packetTime_uS % (60 * PKTLOSS_RESOLUTION));
}

/*
 * Used to print useful information for logs files for individual Throughput UL and DL
 */
void printTPMetrics(flow_data *flow_data, const unsigned long long packetTime_uS, int direction) {
    if((loggerThroughput->isDebugEnabled()) || (loggerThroughput->isTraceEnabled())) {
        uint64_t numBytesNotAck;
        numBytesNotAck = 0;

        if((flow_data->tcpPktLossInfo.highSeq[direction] > flow_data->tcpPktLossInfo.highAck[direction]) &&
                (flow_data->tcpPktLossInfo.highSeq[direction] > 0) &&
                (flow_data->tcpPktLossInfo.highAck[direction] > 0)) {
            numBytesNotAck = (flow_data->tcpPktLossInfo.highSeq[direction] - flow_data->tcpPktLossInfo.highAck[direction]);
        }

        LOG4CXX_DEBUG(loggerThroughput, "Throughput Metrics printTPMetrics : DIRECTION = " << direction << endl
                      << "Throughput Metrics printTPMetrics: tpLastRopBoundryTime = " << flow_data->tpLastRopBoundryTime << endl
                      << "Throughput Metrics printTPMetrics: packetTime_uS = " << packetTime_uS << endl
                      << "Throughput Metrics printTPMetrics: tpDurationStopwatchStarted [this direction] = " << flow_data->tpDurationStopwatchStarted[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpTimeLastBurstStarted [this direction] = " << flow_data->tpTimeLastBurstStarted[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpAckLastPacketTime [this direction] = " << flow_data->tpAckLastPacketTime[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpBurstDuration [this direction] = " << flow_data->tpBurstDuration[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpDuration [this direction] = " << flow_data->tpDuration[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpOutOfOrderPackets[this direction] = " << flow_data->tpOutOfOrderPackets[direction] << endl
                      << "Throughput Metrics printTPMetrics: tpUniqueBytes[this direction] = " << flow_data->tcpPktLossInfo.tpUniqueBytes[direction]
                      << " : tcp_flow->pktCount (total packets incl ReTx) = " <<   flow_data->tcpPktLossInfo.pktCount[direction] << endl
                      << "Throughput Metrics printTPMetrics: tp Num Packets not acknowleged[this direction] = " << numBytesNotAck << endl
                      << "Throughput Metrics printTPMetrics: tp Total Bytes Acknowledges[this direction] = " << (flow_data->tcpPktLossInfo.tpUniqueBytes[direction] - numBytesNotAck));
    }
}
/*
 * Used to print useful information for logs files for combined Throughput
 */
void printTPMetricsTotal(flow_data *flow_data, const unsigned long long packetTime_uS) {
    if((loggerThroughput->isDebugEnabled()) || (loggerThroughput->isTraceEnabled())) {
        uint64_t numBytesNotAck[2];
        numBytesNotAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 0;
        numBytesNotAck[PKT_LOSS_HEADING_TO_INTERNET] = 0;

        if((flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) &&
                (flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > 0) &&
                (flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > 0)) {
            numBytesNotAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = (flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
        }

        if((flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_INTERNET] > flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET]) &&
                (flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_INTERNET] > 0) &&
                (flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET] > 0)) {
            numBytesNotAck[PKT_LOSS_HEADING_TO_INTERNET] = (flow_data->tcpPktLossInfo.highSeq[PKT_LOSS_HEADING_TO_INTERNET] -  flow_data->tcpPktLossInfo.highAck[PKT_LOSS_HEADING_TO_INTERNET]);
        }

        LOG4CXX_DEBUG(loggerThroughput, "Throughput Metrics printTPMetricsTotal: \n"
                      << "Throughput Metrics printTPMetricsTotal: tpLastRopBoundryTime = " << flow_data->tpLastRopBoundryTime << endl
                      << "Throughput Metrics printTPMetricsTotal: packetTime_uS = " << packetTime_uS << endl
                      << "Throughput Metrics printTPMetricsTotal: tpDurationStopwatchStarted HEADING_TO_USER_EQUIPMENT = " << flow_data->tpDurationStopwatchStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpDurationStopwatchStarted PKT_LOSS_HEADING_TO_INTERNET = " << flow_data->tpDurationStopwatchStarted[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpTimeLastBurstStarted HEADING_TO_USER_EQUIPMENT = " << flow_data->tpTimeLastBurstStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpTimeLastBurstStarted HEADING_TO_INTERNET = " << flow_data->tpTimeLastBurstStarted[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpTimeLastBurstStartedTotal = " << flow_data->tpTimeLastBurstStartedTotal << endl
                      << "Throughput Metrics printTPMetricsTotal: tpAckLastPacketTime HEADING_TO_USER_EQUIPMENT = " << flow_data->tpAckLastPacketTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpAckLastPacketTime HEADING_TO_INTERNET = " << flow_data->tpAckLastPacketTime[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpBurstDurationTotal  = " << flow_data->tpBurstDurationTotal << endl
                      << "Throughput Metrics printTPMetricsTotal: tpDuration total currently = " << flow_data->tpDurationTotal << endl
                      << "Throughput Metrics printTPMetricsTotal: tpDuration total [Reportes is (tpDurationTotal + tpBurstDurationTotal)] = " << flow_data->tpDurationTotal + flow_data->tpBurstDurationTotal << endl
                      << "Throughput Metrics printTPMetricsTotal: tpOutOfOrderPackets HEADING_TO_USER_EQUIPMENT = " << flow_data->tpOutOfOrderPackets[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpOutOfOrderPackets HEADING_TO_INTERNET = " << flow_data->tpOutOfOrderPackets[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tpUniqueBytes HEADING_TO_USER_EQUIPMENT = " << flow_data->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                      << ": tcp_flow->pktCount (total packets incl ReTx) = " <<   flow_data->tcpPktLossInfo.pktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics : tpUniqueBytes HEADING_TO_INTERNET = " << flow_data->tcpPktLossInfo.tpUniqueBytes[PKT_LOSS_HEADING_TO_INTERNET]
                      << ": tcp_flow->pktCount (total packets incl ReTx) = " <<   flow_data->tcpPktLossInfo.pktCount[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tp Num Packets not acknowleged HEADING_TO_USER_EQUIPMENT= " << numBytesNotAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] << endl
                      << "Throughput Metrics printTPMetricsTotal: tp Num Packets not acknowleged HEADING_TO_INTERNET= " <<  numBytesNotAck[PKT_LOSS_HEADING_TO_INTERNET] << endl
                      << "Throughput Metrics printTPMetricsTotal: tp Total Bytes Acknowledged = "
                      << ((flow_data->tcpPktLossInfo.tpUniqueBytes[0] + flow_data->tcpPktLossInfo.tpUniqueBytes[1]) - (numBytesNotAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + numBytesNotAck[PKT_LOSS_HEADING_TO_INTERNET])));
    }
}

/*
 * Function to return the opposite packet direction to the one entered;
 * Based on packet direction
 */
int getOtherDirection(int direction) {
    if(direction == PKT_LOSS_HEADING_TO_INTERNET) {
        return PKT_LOSS_HEADING_TO_USER_EQUIPMENT;
    } else if(direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        return PKT_LOSS_HEADING_TO_INTERNET;
    } else {
        LOG4CXX_ERROR(loggerThroughput, "Throughput Metrics : Unknown packet direction " << direction);
        return direction; // dont change it  if we cant figure the direction out
    }
}

/*
 * Checks for Bytes in opposite direction before performing  TP calculations
 */
void tpStopParallelFlows(flow_data *flow_data, const unsigned long long *allStopLastAckTime, int direction) {
    // To account for parallel running bytes [in both directions], must have both stop watches at 0 before doing total calcualtion
    if((flow_data->tpDurationStopwatchStarted[0] == 0) && (flow_data->tpDurationStopwatchStarted[1] == 0)) {
        if(flow_data->tpTimeLastBurstStartedTotal > 0) {
            if(*allStopLastAckTime >= flow_data->tpTimeLastBurstStartedTotal) {
                flow_data->tpBurstDurationTotal = (*allStopLastAckTime - flow_data->tpTimeLastBurstStartedTotal);
                flow_data->tpDurationTotal = flow_data->tpDurationTotal + flow_data->tpBurstDurationTotal;

                if((loggerThroughput->isTraceEnabled())) {
                    LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpStopParallelFlows: all Stop Last Ack Time for Bursts in BOTH directions Greater than Last Burst Started time (normal condition)");
                    printTPMetricsTotal(flow_data, *allStopLastAckTime);
                }
            } else {
                LOG4CXX_WARN(loggerThroughput, "Throughput Metrics tpStopParallelFlows: all Stop Last Ack Time Greater THAN tpTimeLastBurstStartedTotal : direction = " << direction
                             << ", tpTimeLastBurstStartedTotal = " << flow_data->tpTimeLastBurstStartedTotal
                             << ", allStopLastAckTime = " << *allStopLastAckTime
                             << ", tpDurationTotal = " << flow_data->tpDurationTotal
                             << ", tpBurstDurationTotal = " << flow_data->tpBurstDurationTotal);
            }
        } else {
            LOG4CXX_WARN(loggerThroughput, "Throughput Metrics Stopping Parallel Flows:  Last Burst Started Total Time is ZERO : direction = " << direction
                         << ", tpTimeLastBurstStartedTotal = " << flow_data->tpTimeLastBurstStartedTotal
                         << ", allStopLastAckTime = " << *allStopLastAckTime
                         << ", tpDurationTotal = " << flow_data->tpDurationTotal
                         << ", tpBurstDurationTotal = " << flow_data->tpBurstDurationTotal);
        }

        flow_data->tpBurstDurationTotal = 0;
        flow_data->tpTimeLastBurstStartedTotal = 0;
    }
}

/*
 * Called when the data bust is ended due to a time out  [TCP Flow is paused > threshold time.]
 */
void tpEndBurstTimeout(flow_data *flow_data, int direction, unsigned long long *theLastAckTime) {
    //if ack received for last packet
    if(*theLastAckTime > 0) {
        flow_data->tpBurstDuration[direction] = (*theLastAckTime - flow_data->tpTimeLastBurstStarted[direction]);
        flow_data->tpDuration[direction] = flow_data->tpDuration[direction] + flow_data->tpBurstDuration[direction];

        if((loggerThroughput->isTraceEnabled())) {
            LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpEndBurstTimeout: ACK TIME Greater Than 0 for Flow (normal condition) DIRECTION = " << direction);
            printTPMetrics(flow_data, *theLastAckTime, direction);
        }

        flow_data->resetPerBurst(direction);
        // Note tpSetLastPAcketTime not called here, as it is not required.
        // tpEndBurstTimeout called from either tpDuration {when new burst starting} or @ ROP time.
        // Either case, we don't want to set lastBustTime to these times. Leave it at it previous value.
        // To account for parallel running bytes [in both directions], must have both stop watches at 0 before doing total calcualtion
        tpStopParallelFlows(flow_data, theLastAckTime, direction);
    } else { // theLastAckTime < = 0
        LOG4CXX_WARN(loggerThroughput, "Throughput Metrics tpEndBurstTimeout: END BURST TIMEOUT: The LAST ACK TIME is ZERO; Cannot time out flow: direction = " << direction
                     << ": UEip = " << flow_data->fourTuple.ueIP
                     << ": uePort = " << flow_data->fourTuple.uePort
                     << ": serverIP = " << flow_data->fourTuple.serverIP
                     << ": serverPort = " << flow_data->fourTuple.serverPort
                     << ": tpDurationStopwatchStarted = " << flow_data->tpDurationStopwatchStarted[direction]
                     << ": tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                     << ": tpAckLastPacketTime [this direction] = " << flow_data->tpAckLastPacketTime[direction]);
    }
}

/*
 * Called when the data bust is ended due to a normal end in data [ not timeout]
 */
void tpEndBurst(flow_data *flow_data, const unsigned long long *packetTime_uS, int direction, unsigned long long *theLastAckTime, int isDupReTxOnly) {
    //if ack received for last packet
    if(*theLastAckTime > 0) {
        if(*theLastAckTime >= flow_data->tpTimeLastBurstStarted[direction]) {
            flow_data->tpBurstDuration[direction] = (*theLastAckTime - flow_data->tpTimeLastBurstStarted[direction]);
            flow_data->tpDuration[direction] = flow_data->tpDuration[direction] + flow_data->tpBurstDuration[direction];

            if((loggerThroughput->isTraceEnabled())) {
                LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpEndBurst: ACK TIME Greater Than LAST BURST STARTED TIME for Flow (normal condition): direction = " << direction);
                printTPMetrics(flow_data, *packetTime_uS, direction);
            }

            flow_data->resetPerBurst(direction);
            tpSetLastPacketTime(flow_data, theLastAckTime, direction);
            // To account for parallel running bytes [in both directions], must have both stop watches at 0 before doing total calcualtion
            tpStopParallelFlows(flow_data, theLastAckTime, direction);
        } else { // *theLastAckTime < tpTimeLastBurstStarted; so Use  the packet time to calc duration and stop flow
            // Check [in checkBurstFinished ] if time of last Ack of previous burst is same as this Ack
            //  i.e no new packets acknowledged , these must be Duplicate ReTx received
            if(!isDupReTxOnly) { //inuclde the time for burst calculations; use packet time
                flow_data->tpBurstDuration[direction] = (*packetTime_uS - flow_data->tpTimeLastBurstStarted[direction]);
                flow_data->tpBurstDurationTotal = (*packetTime_uS - flow_data->tpTimeLastBurstStartedTotal);
                LOG4CXX_WARN(loggerThroughput, "Throughput Metrics tpEndBurst: ACK TIME Less Than LAST BURST STARTED TIME for Flow : direction = " << direction
                             << ": UEip = " << flow_data->fourTuple.ueIP
                             << ": uePort = " << flow_data->fourTuple.uePort
                             << ": serverIP = " << flow_data->fourTuple.serverIP
                             << ": serverPort = " << flow_data->fourTuple.serverPort
                             << ": tpDurationStopwatchStarted = " << flow_data->tpDurationStopwatchStarted[direction]
                             << ": tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                             << ": tpAckLastPacketTime [this direction] = " << flow_data->tpAckLastPacketTime[direction]);
                flow_data->resetPerBurst(direction);
                tpSetLastPacketTime(flow_data, packetTime_uS, direction);
                // To account for parallel running bytes [in both directions], must have both stop watches at 0 before doing total calcualtion
                tpStopParallelFlows(flow_data, packetTime_uS, direction);

                if((loggerThroughput->isTraceEnabled())) {
                    printTPMetrics(flow_data, *packetTime_uS, direction);
                    printTPMetricsTotal(flow_data, *packetTime_uS);
                }
            } else { //  its a DupReTX don't include the time.
                // Switch last burst started  to other flow, as this one is not to be counted.
                int otherDirn = getOtherDirection(direction);
                flow_data->tpTimeLastBurstStartedTotal = flow_data->tpTimeLastBurstStarted[otherDirn];
                flow_data->resetPerBurst(direction);

                //tpSetLastPacketTime & tpStopParallelFlows not neeeded here as it a duplicate ReTx
                if((loggerThroughput->isTraceEnabled())) {
                    LOG4CXX_INFO(loggerThroughput, "Throughput Metrics tpEndBurst: ACK TIME SAME AS PREVIOUS ACK TIME: NO NEW PACKTES In THIS BURST [Dup ReTx]  DIRECTION = " << direction
                                 << ": UEip = " << flow_data->fourTuple.ueIP
                                 << ": uePort = " << flow_data->fourTuple.uePort
                                 << ": serverIP = " << flow_data->fourTuple.serverIP
                                 << ": serverPort = " << flow_data->fourTuple.serverPort
                                 << " getOtherDirection(direction) = " << getOtherDirection(direction)
                                 << " tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                                 << " tpTimeLastBurstStarted [Other Direction] = " << flow_data->tpTimeLastBurstStarted[otherDirn]
                                 << " packetTime_uS = " << *packetTime_uS
                                 << " flow_data->tpTimeLastBurstStartedTotal = " << flow_data->tpTimeLastBurstStartedTotal);
                    printTPMetrics(flow_data, *packetTime_uS, direction);
                    printTPMetricsTotal(flow_data, *packetTime_uS);
                } //END isTraceEnabled
            } //END isDupReTxOnly
        } // END theLastAckTime < tpTimeLastBurstStarted;
    } // END  theLastAckTime > 0
    else { // if not ACK for last packet. then continue to log duration.
        flow_data->tpBurstDuration[direction] = (*packetTime_uS - flow_data->tpTimeLastBurstStarted[direction]);
        flow_data->tpBurstDurationTotal = (*packetTime_uS - flow_data->tpTimeLastBurstStartedTotal);
    }
}

/*
 * Boundary ROP time in uS
 */
void getFirstPacketRopBoundryTime(flow_data *flow_data) {
    unsigned long long firstPacketTime_us = (unsigned long long)((double) flow_data->firstPacketTime * (double) PKTLOSS_RESOLUTION);
    flow_data->firstPacketRopBoundryTime = firstPacketTime_us - (firstPacketTime_us % (60 * PKTLOSS_RESOLUTION));
}


/*
 * Used to timeout the burst if the TCP flow is paused for > threshold
 */
void tpTimeoutBurst(flow_data *flow_data, unsigned long long *lastPacketTime_us, const unsigned long long *currentPacketTime_uS, int direction, int ropBoundary) {
    if(*lastPacketTime_us <= 0) { // first burst in Flow
        return;
    }

    // ensure we don't run this needlessly
    if((*currentPacketTime_uS - *lastPacketTime_us) < flow_data->tpThreshold[direction]) {
        return;
    }

    if((loggerThroughput->isDebugEnabled())) {
        if(flow_data->tpDurationStopwatchStarted[direction] == 1) {
            int bufSize = 2000;
            char buf[5][bufSize];
            unsigned long long diff = (*currentPacketTime_uS - *lastPacketTime_us);
            snprintf(buf[0], bufSize, "Throughput Metrics tpTimeoutBurst: CHECKING TIME OUT :\n");
            snprintf(buf[1], bufSize, "Throughput Metrics tpTimeoutBurst: ropBoundary = %d:  direction = % d, currentPacketTime_uS = %llu, lastPacketTime_us = %llu, tpDurationStopwatchStarted = %d\n", ropBoundary, direction, *currentPacketTime_uS, *lastPacketTime_us, flow_data->tpDurationStopwatchStarted[direction]);
            snprintf(buf[2], bufSize, "Throughput Metrics tpTimeoutBurst: flow_data->tcpPktLossInfo.highSeqTime[direction] = %llu \n", (unsigned long long) flow_data->tcpPktLossInfo.highSeqTime[direction]);
            snprintf(buf[3], bufSize, "Throughput Metrics tpTimeoutBurst:  diff = %llu,  flow_data->tpThreshold = %llu, \n", diff, flow_data->tpThreshold[direction]);
            snprintf(buf[4], bufSize, "Throughput Metrics tpTimeoutBurst:  flow_data->serverLatency = %u,  flow_data->clientLatency= %u, \n", flow_data->serverLatency, flow_data->clientLatency);
            LOG4CXX_DEBUG(loggerThroughput, buf[0] << buf[1] << buf[2] << buf[3] << buf[4]);
        }
    }

    if(*currentPacketTime_uS >= *lastPacketTime_us) {
        if((*currentPacketTime_uS - *lastPacketTime_us) > flow_data->tpThreshold[direction])  {
            if(flow_data->tpDurationStopwatchStarted[direction] == 1) {
                // timeout the last burst
                if((loggerThroughput->isDebugEnabled())) {
                    int bufSize = 2000;
                    char buf[5][bufSize];
                    unsigned long long diff = (*currentPacketTime_uS - *lastPacketTime_us);
                    snprintf(buf[0], bufSize, "Throughput Metrics tpTimeoutBurst: OPERATING TIME OUT :\n");
                    snprintf(buf[0], bufSize, "Throughput Metrics tpTimeoutBurst: ropBoundary = %d:  direction = % d, currentPacketTime_uS = %llu, lastPacketTime_us = %llu, tpDurationStopwatchStarted = %d\n", ropBoundary, direction, *currentPacketTime_uS, *lastPacketTime_us, flow_data->tpDurationStopwatchStarted[direction]);
                    snprintf(buf[0], bufSize, "Throughput Metrics tpTimeoutBurst:  diff = %llu,  flow_data->tpThreshold = %llu, \n", diff, flow_data->tpThreshold[direction]);
                    snprintf(buf[0], bufSize, "Throughput Metrics tpTimeoutBurst:  flow_data->serverLatency = %u,  flow_data->clientLatency= %u, \n", flow_data->serverLatency, flow_data->clientLatency);
                    LOG4CXX_DEBUG(loggerThroughput, buf[0] << buf[1] << buf[2] << buf[3] << buf[4]);
                }

                // Also theLastAckTime_us set to  tpLastPktTimeOfLastBurst
                tpEndBurstTimeout(flow_data, direction, lastPacketTime_us);
            }
        }
    } else { //(*lastPacketTime_us > *currentPacketTime_uS)
        // if the difference is small then ignore it as it probably just the time it took to copy the flow buffer
        if((*lastPacketTime_us - *currentPacketTime_uS) > flow_data->tpThreshold[direction]) {
            LOG4CXX_WARN(loggerThroughput, "Throughput Metrics tpTimeoutBurst: Unable to Timeout Burst : current packet time is less that last packet time: DIRECTION = " << direction
                         << " currentPacketTime_uS = " << *currentPacketTime_uS
                         << " lastPacketTime_us  = " << *lastPacketTime_us
                         << " highSeqTime = " << flow_data->tcpPktLossInfo.highSeqTime[direction]
                         << " highAckTime = " << flow_data->tcpPktLossInfo.highAckTime[direction]);
        }
    }
}
void tpDuration(flow_data *flow_data, const unsigned long long *packetTime_uS, int direction) {
    if(*packetTime_uS < flow_data->tpLastRopBoundryTime)  {
        flow_data->tpOutOfOrderPackets[direction]++;
    }

    tpSetThreshold(flow_data, direction);

    // Conditions for timeout are
    // 1. tpDurationStopwatchStarted == 1
    // 2. lastPacketTime_us > 0
    // 3. Current packetTime_uS -  lastPacketTime_us > threshold .. checked in tpTimeoutBurst
    //
    // payload need not be > 0 as in congestion packets, payload ==0 and this could be the firt packet after time out.
    if(flow_data->tpDurationStopwatchStarted[direction] == 1) {
        // time out previous flow before starting a new one.
        unsigned long long lastPacketTime_us;
        tpGetLastPacketTime(flow_data, &lastPacketTime_us, direction);

        if(lastPacketTime_us > 0) {
            tpTimeoutBurst(flow_data, &lastPacketTime_us, packetTime_uS, direction, 0);
        }
    }

    if(flow_data->tcpPktLossInfo.payload[direction] > 0) {
        tpSetLastPacketTime_burstStarted(flow_data, packetTime_uS, direction); // keep a runnning total of last packet time for time out

        if((loggerThroughput->isTraceEnabled())) {
            if(!flow_data->printOnce) {
                LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpDuration: NON ZERO PAYLOAD (normal condition): DIRECTION  = " << direction
                              << " tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                              << " payload = " << flow_data->tcpPktLossInfo.payload[direction]
                              << " tpDurationStopwatchStarted = " << flow_data->tpDurationStopwatchStarted[direction]
                              << " tpUniqueBytes = " << flow_data->tcpPktLossInfo.tpUniqueBytes[direction]);
                flow_data->printOnce = 1;
            }
        }

        if(flow_data->tpDurationStopwatchStarted[direction] == 0) {
            flow_data->tpTimeLastBurstStarted[direction] = *packetTime_uS;

            if(flow_data->tpTimeLastBurstStartedTotal == 0) {
                flow_data->tpTimeLastBurstStartedTotal = *packetTime_uS;
            }

            flow_data->tpDurationStopwatchStarted[direction] = 1;

            if((loggerThroughput->isTraceEnabled())) {
                LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpDuration: NON ZERO PAYLOAD-> NEW BURST (normal condition): DIRECTION = " << direction
                              << " tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                              << " tpDurationStopwatchStarted = " << flow_data->tpDurationStopwatchStarted[direction]);
            }
        }

        if(*packetTime_uS < flow_data->tpTimeLastBurstStarted[direction]) { // out of order packets
            if((loggerThroughput->isTraceEnabled())) {
                LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpDuration: NON ZERO PAYLOAD -> OUT OF ORDER PACKET Resetting Brust started time: DIRECTION = " << direction
                              << " packetTime_uS = " << *packetTime_uS
                              << " tpTimeLastBurstStarted = " << flow_data->tpTimeLastBurstStarted[direction]
                              << " tpDurationStopwatchStarted = " << flow_data->tpDurationStopwatchStarted[direction]);
            }

            flow_data->tpTimeLastBurstStarted[direction] = *packetTime_uS;
        }

        // keep a running total for ROP reporting purposes
        flow_data->tpBurstDuration[direction] = (*packetTime_uS - flow_data->tpTimeLastBurstStarted[direction]);
        flow_data->tpBurstDurationTotal = (*packetTime_uS - flow_data->tpTimeLastBurstStartedTotal);
    } else { // flow_data->tcpPktLossInfo.payload[direction] <= 0
        if(flow_data->tpDurationStopwatchStarted[direction] == 1) { // we have started a BURST PERIOD
            if((loggerThroughput->isTraceEnabled())) {
                LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics tpDuration: ZERO PAYLOAD (normal condition): DIRECTION = " << direction
                              << " payload = " << flow_data->tcpPktLossInfo.payload[direction]
                              << " tpUniqueBytes " << flow_data->tcpPktLossInfo.tpUniqueBytes[direction]);
            }

            unsigned long long theLastAckTime;
            int isItDupReTxOnly = 0;  // set to 1 if last burst was duplicate Re transmits only
            getLastAckTime(flow_data, &theLastAckTime, direction, &isItDupReTxOnly);
            tpEndBurst(flow_data, packetTime_uS, direction, &theLastAckTime, isItDupReTxOnly);
        }
    }
}



/*
 * Calculates the duration for throughput based on if there is tcpPayload
 */
void tpTimer(flow_data *flow_data, const unsigned long long *packetTime_uS, PacketDirection_t pktDirection) {
    getTPLastRopBoundryTime(flow_data, packetTime_uS);

    if(pktDirection == HEADING_TO_INTERNET) {
        tpDuration(flow_data, packetTime_uS, PKT_LOSS_HEADING_TO_INTERNET);
    } else {
        tpDuration(flow_data, packetTime_uS, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
    }
}

void getRopCounter(unsigned long long *tpRopCtr, const unsigned long long *curPktTime_uS,  unsigned long long *theFirstPacketRopBoundryTime) {
    int tpRopDurInMinutes = evaluatedArguments.outputReportingPeriod;
    unsigned long long top = (*curPktTime_uS - *theFirstPacketRopBoundryTime);
    unsigned long long bottom = (unsigned long long) tpRopDurInMinutes * (unsigned long long) 60 * (unsigned long long) PKTLOSS_RESOLUTION;
    *tpRopCtr = (unsigned long long) top / (unsigned long long) bottom; // returns no fraction part
    *tpRopCtr = *tpRopCtr - 1; // rops start at 0 not 1
}

void handleThroughPutStats(flow_data *thisFlow, const unsigned long long *curPktTime_uS) {
    // efitleo: handle Throughput
    if(thisFlow->isTcpFlow == true) { // need to stop timer
        unsigned long long lastPacketTime_us;
        unsigned long long tpRopCtr = 0;

        for(int i = 0; i < 2; i++) {
            tpGetLastPacketTime(thisFlow, &lastPacketTime_us, i);

            if(loggerThroughput->isTraceEnabled()) {
                if(thisFlow->tpDurationStopwatchStarted[i] == 1) {
                    int bufSize = 2000;
                    char buf[bufSize];
                    getRopCounter(&tpRopCtr, curPktTime_uS, &(thisFlow->firstPacketRopBoundryTime));
                    snprintf(buf, bufSize, "Throughput Metrics: update_flows_buffer: direction = %d,tpDurationStopwatchStarted = %d, rop_counter (calc) = %llu, rop_counter (inc) = %u, current packet time = %llu, lastPacketTime_us = %llu \n", i, thisFlow->tpDurationStopwatchStarted[i], tpRopCtr,  thisFlow->ropCounter, *curPktTime_uS, lastPacketTime_us);
                    LOG4CXX_DEBUG(loggerThroughput, buf);
                }
            }

            if(lastPacketTime_us > 0) { //lastPacketTime_us = 0 on new flow
                tpTimeoutBurst(thisFlow, &lastPacketTime_us, curPktTime_uS, i, 1);
            }
        }
    }
}

