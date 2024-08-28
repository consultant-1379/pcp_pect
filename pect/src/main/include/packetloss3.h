/*
 * packetLoss.h
 *
 *  Created on: Sept 2013
 *      Author: Awal
 */

#ifndef PACKETLOSS_H_
#define PACKETLOSS_H_

// System includes
#include <algorithm>
#include <list>
#include <netinet/tcp.h>

// Local includes
#include "packetbuffer.h"
#include "flow.h"
#include "pcp_check.hpp"
#include "logger.hpp"
#include <boost/tr1/unordered_map.hpp>
#include <boost/assert.hpp>


#define PKT_LOSS_HEADING_TO_USER_EQUIPMENT 1
#define PKT_LOSS_HEADING_TO_INTERNET 0
#define PACKET_LOSS_MIN_PACKETS 1000
#define PKTLOSS_RESOLUTION 1000000
#define PKTLOSS_RATE_RESOLUTION 100000
// PACKET_LOSS_PACKET_THRESHOLD is # unique TCP packets below which PCK Loss will not be calculated.
#define PACKET_LOSS_PACKET_THRESHOLD_UE_TO_INET (10)
#define PACKET_LOSS_PACKET_THRESHOLD_INET_TO_UE (100)


using namespace std;

using std::ostream;
using std::stringstream;
using std::endl;
using std::list;
using std::cout;



struct packetLossStatisticsStruct {
    unsigned long tcpPackets;
    unsigned long totalPackets;
    uint32_t ueToInternetpktLoss;
    uint32_t internetToUEpktLoss;
    uint32_t maxLoss_ueToInternet;
    uint32_t maxLoss_internetToUE;

    void reset() {
        ueToInternetpktLoss = 0;
        internetToUEpktLoss = 0;
        tcpPackets = 0;
        totalPackets = 0;
        maxLoss_ueToInternet = 0;
        maxLoss_internetToUE = 0;
    }


} ;

struct pktLossDataeq {
    size_t operator()(const u_int32_t &x) const {
        return std::hash<u_int32_t>()((u_int32_t) x);
    }

    bool operator()(const u_int32_t f1, const u_int32_t f2) const {
        return (f1 == f2);
    }
};

typedef std::tr1::unordered_map<u_int32_t, int16_t> expectedSeqNumReceived_ueMAP;
typedef std::tr1::unordered_map<u_int32_t, int16_t> expectedSeqNumReceived_inetMAP;

struct pktLossInfo {
    //const int16_t SEQ_LIST_SIZE = 100; //200  MAX is 255 as it defiend as int16_t
    static const unsigned int SEQ_LIST_SIZE_UE = 250;  // SET for MEM efficiency; Sets bucket count to 256: ALT set to 126
    static const unsigned int SEQ_LIST_SIZE_INET = 63; // SET for MEM efficiency; Sets bucket count to 64: ALT set to 126
   
    
    PectIP4Tuple fourTuple;

    uint32_t   pktCount[2];
    uint32_t   uniquePktCount[2];

    int isRTOStarted[2];
    uint32_t   recovered[2];
    uint32_t   recoveredOrig[2];

    uint32_t   rtoAffectedPkt[2];
    uint32_t   retxLocal[2];
    uint32_t   dupAckLocal[2];
    uint32_t   dupRetxCount_RTO[2];

    uint32_t   retxCount[2];
    uint32_t   dupAckInARow[2];
    uint32_t   fastReTxCount[2];
    uint32_t   expSeq[2];

    uint32_t   highSeq[2];
    uint32_t   lastAck[2];
    uint32_t   highAck[2];
    uint32_t   highExpectedSeqNum[2];
    //EQEV-10887
    // FOR DEBUG 
    // uint32_t currentSeqNum[2];
    // FOR DEBUG uint32_t uniqueRetxCount[2];
    // FOR DEBUG unsigned long long totalReTxBytes[2];
    // FOR DEBUG unsigned long long totalBytes[2];
    uint32_t dupRetxCount_non_RTO[2];
    uint32_t highReTxSeq[2];
    //EQEV-10887 END

    //double avgRTTEst[2];
    //double rtoEst[2];

    uint64_t lastPktTime;
    uint64_t lastPrintPktTime;

    uint64_t lastAckTime[2];
    uint64_t highSeqTime[2];
    uint64_t highAckTime[2];

    // SYN based RTT
    uint64_t syn1Time;
    uint64_t syn2Time;
    uint64_t synAckTime;

    //uint64_t refTime;

    uint32_t   synSrc;
    uint32_t   synSeq;
    uint32_t   synAck;

    int synRttFound;


    int16_t queueNumber;

    int16_t resetPerRop;
    unsigned int isGoodData[2]; //0 means No 1 means yes

    unsigned long long tpUniqueBytes[2];
    
    unsigned long payload[2];
    unsigned int sizeofEachMapEntry;

    unsigned int numTimesSeqMap_inet_maxed;
    unsigned int numTimesSeqMap_ue_maxed;
    uint32_t lowestSeqNumInMap[2];

    expectedSeqNumReceived_ueMAP *expectedSeqNumReceived_ue;
    expectedSeqNumReceived_inetMAP *expectedSeqNumReceived_inet ;

    // Bzero was found to be causing massive memory leaks
    void init_pktLossInfo() {
        queueNumber = -1;
        pktCount[0] = 0;
        pktCount[1] = 0;
        isRTOStarted[0] = 0;
        isRTOStarted[1] = 0;
        recovered[0] = 0;
        recovered[1] = 0;
        recoveredOrig[0] = 0;
        recoveredOrig[1] = 0;
        rtoAffectedPkt[0] = 0;
        rtoAffectedPkt[1] = 0;
        retxLocal[0] = 0;
        retxLocal[1] = 0;
        dupAckLocal[0] = 0;
        dupAckLocal[1] = 0;
        dupRetxCount_RTO[0] = 0;
        dupRetxCount_RTO[1] = 0;
        retxCount[0] = 0;
        retxCount[1] = 0;
        dupAckInARow[0] = 0;
        dupAckInARow[1] = 0;
        fastReTxCount[0] = 0;
        fastReTxCount[1] = 0;
        expSeq[0] = 0;
        expSeq[1] = 0;
        highSeq[0] = 0;
        highSeq[1] = 0;
        lastAck[0] = 0;
        lastAck[1] = 0;
        highAck[0] = 0;
        highAck[1] = 0;
        lastPktTime = 0;
        lastPrintPktTime = 0;
        lastAckTime[0] = 0;
        lastAckTime[1] = 0;
        highSeqTime[0] = 0;
        highSeqTime[1] = 0;
        highAckTime[0] = 0;
        highAckTime[1] = 0;
        syn1Time = 0;
        syn2Time = 0;
        synAckTime = 0;
        synSrc = 0;
        synSeq = 0;
        synAck = 0;
        synRttFound = 0;
        tpUniqueBytes[0] = 0;
        tpUniqueBytes[1] = 0;
        payload[0] = 0;
        payload[1] = 0;
        highExpectedSeqNum[0] = 0;
        highExpectedSeqNum[1] = 0;
        numTimesSeqMap_inet_maxed = 0;
        numTimesSeqMap_ue_maxed = 0;
        sizeofEachMapEntry = (unsigned int)(sizeof(u_int32_t) + sizeof(int16_t));
        lowestSeqNumInMap[0] = 0;
        lowestSeqNumInMap[1] = 0;
        uniquePktCount[0] = 0;
        uniquePktCount[1] = 0;
        isGoodData[0] = UINT_MAX;
        isGoodData[1] = UINT_MAX;
        // EQEV-10887
        // currentSeqNum[0] = 0;
        // currentSeqNum[1] = 0;
        // totalReTxBytes[0] = 0;
        // totalReTxBytes[1] = 0;
        // totalBytes[0] = 0;
        // totalBytes[1] = 0;
        // uniqueRetxCount[0] = 0;
        // uniqueRetxCount[1] = 0;
        dupRetxCount_non_RTO[0] = 0;
        dupRetxCount_non_RTO[1] = 0;
        highReTxSeq[0] = 0;
        highReTxSeq[1] = 0;
        //EQEV-10887 END
    }

    // Bzero was found to be causing massive memory leaks
    void resetPerRopPktLossInfo() {
        queueNumber = -1;
    }

    void printInitValues() {
        LOG4CXX_INFO(loggerClassify,  " TCP FLOW INIT VALUES "
                     << pktCount[0] << ": "
                     << pktCount[1] << ": "
                     << isRTOStarted[0] << ": "
                     << isRTOStarted[1] << ": "
                     << recovered[0] << ": "
                     << recovered[1] << ": "
                     << recoveredOrig[0] << ": "
                     << recoveredOrig[1] << ": "
                     << rtoAffectedPkt[0] << ": "
                     << rtoAffectedPkt[1] << ": "
                     << retxLocal[0] << ": "
                     << retxLocal[1] << ": "
                     << dupAckLocal[0] << ": "
                     << dupAckLocal[1] << ": "
                     << dupRetxCount_RTO[0] << ": "
                     << dupRetxCount_RTO[1] << ": "
                     << retxCount[0] << ": "
                     << retxCount[1] << ": "
                     << dupAckInARow[0] << ": "
                     << dupAckInARow[1] << ": "
                     << fastReTxCount[0] << ": "
                     << fastReTxCount[1] << ": "
                     << expSeq[0] << ": "
                     << expSeq[1] << ": "
                     << highSeq[0] << ": "
                     << highSeq[1] << ": "
                     << lastAck[0] << ": "
                     << lastAck[1] << ": "
                     << highAck[0] << ": "
                     << highAck[1] << ": "
                     << lastPktTime << ": "
                     << lastPrintPktTime << ": "
                     << lastAckTime[0] << ": "
                     << lastAckTime[1] << ": "
                     << highSeqTime[0] << ": "
                     << highSeqTime[1] << ": "
                     << syn1Time << ": "
                     << syn2Time << ": "
                     << synAckTime << ": "
                     << synSrc << ": "
                     << synSeq << ": "
                     << synAck << ": "
                     << synRttFound);
    }

    void cleanupMaps() {
        if(expectedSeqNumReceived_ue != NULL) {
            expectedSeqNumReceived_ue->clear();
            delete expectedSeqNumReceived_ue;
            expectedSeqNumReceived_ue = NULL;
        }

        if(expectedSeqNumReceived_ue != NULL) {
            expectedSeqNumReceived_inet->clear();
            delete expectedSeqNumReceived_inet;
            expectedSeqNumReceived_inet = NULL;
        }
    }

};



#endif /* PACKETLOSS_H_ */
