#include "flow.h"
#include "logger.hpp"
#include "classify.h"

#include <arpa/inet.h>
#include <iomanip>
#include <netinet/in.h>
#include <boost/foreach.hpp>

using std::hex;
using std::stringstream;
using std::string;
using std::endl;

packetLossStatisticsStruct pktLossCtrs ;
extern pthread_mutex_t packetLossMutex;
extern ClassifierMapMutex classifierMutexLockArray[];
extern EArgs evaluatedArguments;
extern HashTableStatisticsStruct hashTableCtrs;
extern unsigned int TESTING_PACKET_LOSS_SA;



void resetPerROPCounters(pktLossInfo *tcp_flow) {
    if(tcp_flow->resetPerRop)  {
        //EQEV-6445 Conversation 9 dec-13 now flow based...don't reset
        tcp_flow->resetPerRopPktLossInfo();
    }
}

void initCounters(pktLossInfo *tcp_flow) {
    tcp_flow->init_pktLossInfo();
}

uint32_t  minU32(uint32_t a, uint32_t b) {
    if(a < b) {
        return a;
    } else {
        return b;
    }
}
/*
 * Handle these conditions.
 *  DupReTX > Retx
 * ReTx - # Dup ReTX > # Unique Packets
 * ReTx - # Dup ReTX == # Unique Packets
 * Low Packet count // using  tcp_flow->tpUniqueBytes[direction] to set the threshold
 *
 * Return 0 for problem, return 1 for all OK
 *
 */
unsigned int pktLossCheckDataIntegrity(pktLossInfo *tcp_flow, int direction) {
    if(direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        if(tcp_flow->uniquePktCount[direction] < (uint32_t) PACKET_LOSS_PACKET_THRESHOLD_INET_TO_UE) {
            return 0;
        }

        if(tcp_flow->uniquePktCount[direction] < evaluatedArguments.packetLossUserThreshold_INET_to_UE) {
            return 0;
        }
    }

    if(direction == PKT_LOSS_HEADING_TO_INTERNET) {
        if(tcp_flow->uniquePktCount[direction] < (uint32_t) PACKET_LOSS_PACKET_THRESHOLD_UE_TO_INET) {
            return 0;
        }

        if(tcp_flow->uniquePktCount[direction] < evaluatedArguments.packetLossUserThreshold_UE_to_INET) {
            return 0;
        }
    }
       
            
    if(tcp_flow->dupRetxCount_RTO[direction] > tcp_flow->retxCount[direction]) {
        return 0;
    }
    
    if(tcp_flow->dupRetxCount_non_RTO[direction] > tcp_flow->retxCount[direction]) {
        return 0;
    }

    int64_t check_uniqueReTx_count = (int64_t) (tcp_flow->retxCount[direction] - (tcp_flow->dupRetxCount_non_RTO[direction] + tcp_flow->dupRetxCount_RTO[direction]));
         
    if(check_uniqueReTx_count < 0) {
        return 0;
    }

    if(check_uniqueReTx_count > tcp_flow->uniquePktCount[direction]) {
        return 0;
    }

    return 1;
}

void pktLossGetExpectedSeqNumMapSize_ue(flow_data *fd, unsigned long *mapSizeBytes) {
    if(fd->isTcpFlow == true) {
        *mapSizeBytes = (((unsigned long) fd->tcpPktLossInfo.expectedSeqNumReceived_ue->bucket_count() * fd->tcpPktLossInfo.sizeofEachMapEntry));
    }
}

void pktLossGetExpectedSeqNumMapSize_inet(flow_data *fd, unsigned long *mapSizeBytes) {
    if(fd->isTcpFlow == true) {
        *mapSizeBytes = (((unsigned long) fd->tcpPktLossInfo.expectedSeqNumReceived_inet->bucket_count() * fd->tcpPktLossInfo.sizeofEachMapEntry));
    }
}

/*
 * Utility function to print the header infor for printPktLossRateInfo frunction
 */
void printPktLossRateInfo_Header() {
    //if(loggerPacketLoss->isInfoEnabled()) {
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled()) || TESTING_PACKET_LOSS_SA) {
        LOG4CXX_INFO(loggerFileWriter, "PACKET LOSS: printPktLossRateInfo "
                     << "," << "UE IP " << "," << "UE Port"
                     << "," << "Server IP" << "," << "Server Port"
                     << "," << "Pkt Count (total) UE->INET"
                     << "," << "Unique Pkt Count UE->INET"
                     << "," << "ReTx Count(total) UE->INET"
                     << "," << "Dup ReTx Count (RTO) UE->INET"
                     << "," << "Dup ReTx Count (NON RTO) UE->INET"
                     << "," << "Fast ReTx Count UE->INET"
                     << "," << "Is Good Data UE->INET"
                     << "," << "pkt Loss Ratio UE->INET x PKTLOSS_RATE_RESOLUTION"
                     << "," << "pkt Loss Ratio UE->INET"
                     << "," << "Pkt Count (total) INET->UE"
                     << "," << "Unique Pkt Count INET->UE "
                     << "," << "ReTx Count(total) INET->UE"
                     << "," << "Dup ReTx Count (RTO) INET->UE"
                     << "," << "Dup ReTx Count (NON RTO) INET->UE"
                     << "," << "Fast ReTx Count INET->UE"
                     << "," << "Is Good Data INET->UE"
                     << "," << "pkt Loss Ratio INET->UE x PKTLOSS_RATE_RESOLUTION"
                     << "," << "pkt Loss Ratio INET->UE");
    }
}
/*
 * Utility function to print the extended packet loss info per ROP
 */
void printPktLossRateInfo(flow_data *fd) {
    //if(loggerPacketLoss->isInfoEnabled()) {
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled()) || TESTING_PACKET_LOSS_SA) {
        pktLossInfo *tcp_flow;
        // EQEV-10887 FOR DEBUG: unsigned long long totalPayloadBytes_ue, totalPayloadBytes_inet;
        tcp_flow = &(fd->tcpPktLossInfo);
        // get ADDR for printing only
        struct in_addr ueIPIn;
        struct in_addr serverIPIn;
        ueIPIn.s_addr = htonl((fd->fourTuple.ueIP));
        serverIPIn.s_addr = htonl((fd->fourTuple.serverIP));
        char ueIPBuf[40];
        char serverIPBuf[40];
        inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
        inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
        uint32_t pktLossRate [2];
        getPacketLossRate(fd, 1);
        pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = fd->internetToUeLossRate ;
        pktLossRate [PKT_LOSS_HEADING_TO_INTERNET] = fd->ueToInternetLossRate ;
        char printPktLoss_internetToUeLossRate[MAX_PKT_LOSS_STRING_LENGTH];
        char printPktLoss_ueToInternetLossRate[MAX_PKT_LOSS_STRING_LENGTH];
        getPacketLossValueAsString(fd->ueToInternetLossRate, printPktLoss_ueToInternetLossRate);
        getPacketLossValueAsString(fd->internetToUeLossRate, printPktLoss_internetToUeLossRate);
        
        // EQEV-10887 FOR DEBUG: calculateUniqueBytesAcknowledged(fd, &totalPayloadBytes_ue, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
        // EQEV-10887 FOR DEBUG: calculateUniqueBytesAcknowledged(fd, &totalPayloadBytes_inet, PKT_LOSS_HEADING_TO_INTERNET);
        LOG4CXX_INFO(loggerFileWriter, "PACKET LOSS: printPktLossRateInfo "
                     << "," << ueIPBuf << "," << fd->fourTuple.uePort
                     << "," << serverIPBuf << "," << fd->fourTuple.serverPort
                     << "," << tcp_flow->pktCount[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->retxCount[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_INTERNET]  // NON RTO DUPLICATE ReTX Count
                     << "," << tcp_flow->fastReTxCount[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << pktLossRate [PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << printPktLoss_ueToInternetLossRate
                     << "," << tcp_flow->pktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->retxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]  // RTO DUPLICATE ReTX Count
                     << "," << tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]  // NON RTO DUPLICATE ReTX Count
                     << "," << tcp_flow->fastReTxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << printPktLoss_internetToUeLossRate
                     /*
                    // EQEV-10887 FOR DEBUG
                     << ","
                     << "," << tcp_flow->currentSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->payload[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]                       
                     << ","
                     
                     << "," << tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << "," << (tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT])  // should be equal to tpUniqueBytes
                     << "," << tcp_flow->tpUniqueBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                     << ","
                     << "," << totalPayloadBytes_ue
                     << ","
                     << "," << tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_INTERNET]
                     << "," << tcp_flow->uniqueRetxCount[PKT_LOSS_HEADING_TO_INTERNET]
                     */
                     );
    }
}  //tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT], tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);

/*
 * Utility function to print the expectedSeqNumReceived_ue size in Bytes and number of entries.
 * Put here as fd is initialised by malloc, which does not understand classes, and hence has no understanding of method classes
 */
void printPktLossMapInfo_ue(flow_data *fd, int loc, char *testName,  PectIP4Tuple fourTuple) {
    if(fd->isTcpFlow == true) {
        unsigned long mapSizeBytes_ue;
        pktLossGetExpectedSeqNumMapSize_ue(fd, &mapSizeBytes_ue);
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS MAPS " << testName << " :" << loc
                     << ": ueIP: port " << fourTuple.ueIP << ": " << fourTuple.uePort
                     << ": Server: port " << fourTuple.serverIP << ": " << fourTuple.serverPort
                     << ": Bucket Count ue = " << fd->tcpPktLossInfo.expectedSeqNumReceived_ue->bucket_count()
                     << ": mapSizeBytes_ue = " << mapSizeBytes_ue
                     << ": expectedSeqNumReceived_ue->size()  = " << fd->tcpPktLossInfo.expectedSeqNumReceived_ue->size());
    }
}
/*
 * Utility function to print the expectedSeqNumReceived_inet size in Bytes and number of entries.
 * Put here as fd is initialised by malloc, which does not understand classes, and hence has no understanding of method classes
 */
void printPktLossMapInfo_inet(flow_data *fd, int loc, char *testName,  PectIP4Tuple fourTuple) {
    if(fd->isTcpFlow == true) {
        unsigned long mapSizeBytes_inet;
        pktLossGetExpectedSeqNumMapSize_inet(fd, &mapSizeBytes_inet);
        LOG4CXX_INFO(loggerPacketLoss, "PACKET LOSS MAPS " << testName << " :" << loc
                     << ": ueIP: port " << fourTuple.ueIP << ": " << fourTuple.uePort
                     << ": Server: port " << fourTuple.serverIP << ": " << fourTuple.serverPort
                     << ": Bucket Count inet = " << fd->tcpPktLossInfo.expectedSeqNumReceived_inet->bucket_count()
                     << ": mapSizeBytes_inet = " << mapSizeBytes_inet
                     << ": expectedSeqNumReceived_inet->size()  = " << fd->tcpPktLossInfo.expectedSeqNumReceived_inet->size());
    }
}
/*
 * Function to initialise expectedSeqNumReceived_inet expectedSeqNumReceived_ue MAPS.
 * Put here as fd is initialised by malloc, which does not understand classes, and hence has no understanding of method classes
 */
void pktLossInitialiseMaps(flow_data *fd,  PectIP4Tuple fourTuple) {
    if(fd->isTcpFlow == true) {
        char testName[50] = "pktLoss InitialiseMaps\0";
        fd->tcpPktLossInfo.sizeofEachMapEntry = (unsigned int)(sizeof(u_int32_t) + sizeof(bool));
        fd->tcpPktLossInfo.expectedSeqNumReceived_inet = new std::tr1::unordered_map<u_int32_t, int16_t> ();
        fd->tcpPktLossInfo.expectedSeqNumReceived_ue = new std::tr1::unordered_map<u_int32_t, int16_t> ();
        fd->tcpPktLossInfo.expectedSeqNumReceived_inet->rehash((unsigned long)ceil((((float) fd->tcpPktLossInfo.expectedSeqNumReceived_inet->size() + fd->tcpPktLossInfo.SEQ_LIST_SIZE_INET)) /  fd->tcpPktLossInfo.expectedSeqNumReceived_inet->max_load_factor()) + 1);
        fd->tcpPktLossInfo.expectedSeqNumReceived_ue->rehash((unsigned long)ceil((((float) fd->tcpPktLossInfo.expectedSeqNumReceived_ue->size() + fd->tcpPktLossInfo.SEQ_LIST_SIZE_UE)) /  fd->tcpPktLossInfo.expectedSeqNumReceived_ue->max_load_factor()) + 1);

        if((loggerPacketLoss->isTraceEnabled())) {
            printPktLossMapInfo_ue(fd, 0, testName,  fourTuple);
            printPktLossMapInfo_inet(fd, 0, testName,  fourTuple);
        }
    }
}


// note, calling fd->tcpPktLossInfo.cleanupMaps() does not actually free the memory. Not sure Why. Maybe a C vs C++ thing
//       Whereby fd is initialised by malloc, and the method cleanupMaps is a struct method
//       So calling cleanupMaps() from the classify side means nothing, as the SeqNumber maps are pointing to NULL or something random.

void pktLossCleanupMaps(flow_data *fd) {
    if(fd->isTcpFlow == true) {
        fd->tcpPktLossInfo.expectedSeqNumReceived_ue->clear();
        delete fd->tcpPktLossInfo.expectedSeqNumReceived_ue;
        fd->tcpPktLossInfo.expectedSeqNumReceived_ue = NULL;
        fd->tcpPktLossInfo.expectedSeqNumReceived_inet->clear();
        delete fd->tcpPktLossInfo.expectedSeqNumReceived_inet;
        fd->tcpPktLossInfo.expectedSeqNumReceived_inet = NULL;
    }
}
void getUnigueBytesCount(flow_data *flow_data, int direction, unsigned long long *uniqueBytesCount) {
    pktLossInfo *tcp_flow;
    tcp_flow = &(flow_data->tcpPktLossInfo);
    *uniqueBytesCount = tcp_flow->tpUniqueBytes[direction];
}

void setUniqueBytesCount(pktLossInfo *tcp_flow, int direction, uint32_t tcpPayloadSize) {
    if(tcpPayloadSize > 0) {
        tcp_flow->tpUniqueBytes[direction] = tcp_flow->tpUniqueBytes[direction] +  tcpPayloadSize;
        tcp_flow->uniquePktCount[direction]++;
    }
}
/*
 * Check if the burst is finished by check if highest Acknowledged packet = highest Sent packet
 * Also check if is a burst of DupReTx's
 */
void checkBurstFinished(flow_data *flow_data, int direction, int *isDupReTX) {
    pktLossInfo *tcp_flow;
    tcp_flow = &(flow_data->tcpPktLossInfo);
    *isDupReTX = 0;

    // highExpectedSeqNum = highSeq + payload, which is the ACK number we expect if the burst is finished.;
    //                                         this is set when the hightest Seq number was processed by packetloss module,
    //                                         as payload will always be zeo now, cos check burstFinished called at the end of a burst {defined by payload =0}
    if(tcp_flow->highAck[direction] == (tcp_flow->highExpectedSeqNum[direction])) {
        flow_data->tpAckLastPacketTime[direction] = ((uint64_t) tcp_flow->highAckTime[direction]);

        // ack time not belonging to this burst
        if(flow_data->tpAckLastPacketTime[direction] < flow_data->tpTimeLastBurstStarted[direction]) {
            flow_data->tpAckLastPacketTime[direction] = 0;
        }

        if((loggerThroughput->isTraceEnabled())) {
            LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics : checkBurstFinished highAck = highExpectedSeqNum (normal condition): Direction = " << direction
                          << ": UE IP : " << flow_data->fourTuple.ueIP << ": " << flow_data->fourTuple.uePort
                          << ": INTERNET IP : " << flow_data->fourTuple.serverIP << ": " << flow_data->fourTuple.serverPort
                          << ": tcp_flow->highAck = " <<   tcp_flow->highAck[direction]
                          << ": tcp_flow->highExpectedSeqNum = " <<   tcp_flow->highExpectedSeqNum[direction]
                          << ": tcp_flow->payload = " <<   tcp_flow->payload[direction]
                          << ": tcp_flow->pktCount = " <<   tcp_flow->pktCount[direction]
                          << ": tcp_flow->highAckTime = " <<   tcp_flow->highAckTime[direction]
                          << ": flow_data->tpAckLastPacketTime = " <<   flow_data->tpAckLastPacketTime[direction]
                          << ": flow_data->tpTimeLastBurstStarted[direction] =  " << flow_data->tpTimeLastBurstStarted[direction]
                          << ": isDupReTX = " <<  *isDupReTX
                          << ": Unique Bytes (Cumulative)= " <<  tcp_flow->tpUniqueBytes[direction]);
        }
    } else {
        flow_data->tpAckLastPacketTime[direction] = 0;

        if((loggerThroughput->isTraceEnabled())) {
            LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics : checkBurstFinished highAck NOT = highExpectedSeqNum  Burst Not finished yet: Direction = " << direction
                          << ": UE IP : " << flow_data->fourTuple.ueIP << ": " << flow_data->fourTuple.uePort
                          << ": INTERNET IP : " << flow_data->fourTuple.serverIP << ": " << flow_data->fourTuple.serverPort
                          << ": tcp_flow->highAck = " <<   tcp_flow->highAck[direction]
                          << ": tcp_flow->highExpectedSeqNum = " <<   tcp_flow->highExpectedSeqNum[direction]
                          << ": tcp_flow->payload = " <<   tcp_flow->payload[direction]
                          << ": tcp_flow->pktCount = " <<   tcp_flow->pktCount[direction]
                          << ": tcp_flow->highAckTime = " <<   tcp_flow->highAckTime[direction]
                          << ": flow_data->tpAckLastPacketTime = " <<   flow_data->tpAckLastPacketTime[direction]
                          << ": flow_data->tpTimeLastBurstStarted[direction] =  " << flow_data->tpTimeLastBurstStarted[direction]
                          << ": isDupReTX = " <<  *isDupReTX
                          << ": Unique Bytes (Cumulative)= " <<  tcp_flow->tpUniqueBytes[direction]);
        }
    }
}

void addElementToMap(std::tr1::unordered_map<u_int32_t, int16_t> &myMap, uint32_t seqNo, int16_t val) {
    myMap[seqNo] = val;
}

int16_t isPacketSent(pktLossInfo *tcp_flow, uint32_t expSeqNum,  int direction) {
    if(direction == (int) PKT_LOSS_HEADING_TO_INTERNET) {
        std::tr1::unordered_map<u_int32_t, int16_t>::iterator itr = tcp_flow->expectedSeqNumReceived_inet->find(expSeqNum);

        if(itr != tcp_flow->expectedSeqNumReceived_inet->end()) {
            return itr->second;
        }
    }

    if(direction == (int) PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        std::tr1::unordered_map<u_int32_t, int16_t>::iterator itr = tcp_flow->expectedSeqNumReceived_ue->find(expSeqNum);

        if(itr != tcp_flow->expectedSeqNumReceived_ue->end()) {
            return itr->second;
        }
    }

    return -1;
}

void printSeqMapContents(std::tr1::unordered_map<u_int32_t, int16_t> &myMap) {
    //if(loggerPacketLoss->isInfoEnabled()) {
    if(loggerPacketLoss->isTraceEnabled()) {
        uint32_t lowest = UINT_MAX, highest = 0;
        std::tr1::unordered_map<u_int32_t, int16_t>::iterator elementItr = myMap.begin();

        while(elementItr != myMap.end()) {
            if(elementItr->first > highest) {
                highest = elementItr->first;
            }

            if(elementItr->first < lowest) {
                lowest = elementItr->first;
            }

            LOG4CXX_INFO(loggerPacketLoss, "printSeqMapContents; Seq Num " <<  elementItr->first << " Value = " << elementItr->second);
            ++elementItr;
        }

        LOG4CXX_INFO(loggerPacketLoss, "printSeqMapContents; lowest = " <<  lowest << " highest = " << highest << " Map Size = " << myMap.size());
    }
}
/*
 * Utility function to remove elemets from sequence History map below threshold value
*/
void deleteElementsFromMap(std::tr1::unordered_map<u_int32_t, int16_t> &myMap, uint32_t *theLowestSeqNumInMap, uint32_t theHighestSeqNumInMap, uint32_t theMapThresholdSeqNum) {
    uint32_t  newLowestSeqNumber = UINT_MAX;
    std::tr1::unordered_map<u_int32_t, int16_t>::iterator elementItr = myMap.begin();
    int count = 0 , count_0 = 0, count_1 = 0;

    while(elementItr != myMap.end()) {
        // NEED NOT ADD CHECK for  elementItr->second == 1
        // Reason: Not all seq Numbers need an individual ACK as ACK# = 501 ACKs all bytes up to byte 500, so Seq # 201, 301,401 are ACK'd by ACK# = 501
        if((elementItr->first < theMapThresholdSeqNum)) {
            //if(loggerPacketLoss->isInfoEnabled()) {
            if(loggerPacketLoss->isTraceEnabled()) {
                LOG4CXX_INFO(loggerPacketLoss, "deleteElementsFromMap; Seq# less than MAX    ; Seq Num " <<  elementItr->first << " Value = " << (int16_t) elementItr->second << ": DELETED");

                if((int16_t) elementItr->second == 1) {
                    count_1++;
                } else {
                    count_0++;
                }

                count++;
            }

            myMap.erase(elementItr++);
        } else if(elementItr->first > theHighestSeqNumInMap) {
            //if(loggerPacketLoss->isInfoEnabled()) {
            if(loggerPacketLoss->isTraceEnabled()) {
                LOG4CXX_INFO(loggerPacketLoss, "deleteElementsFromMap; Seq# greater than MAX; Seq Num " <<  elementItr->first << " Value = " << elementItr->second << ": DELETED");
            }

            myMap.erase(elementItr++);
        } else {
            // reset the lowest Seq Number in the map taking account for fact that Packet sent not acknowledges will not be deleted
            if(elementItr->first < newLowestSeqNumber) {
                newLowestSeqNumber = elementItr->first;
            }

            //if(loggerPacketLoss->isInfoEnabled()) {
            if(loggerPacketLoss->isTraceEnabled()) {
                LOG4CXX_INFO(loggerPacketLoss, "deleteElementsFromMap;                       ; Seq Num " <<  elementItr->first
                             << " Value = " << elementItr->second
                             << " [newLowestSeqNumber = " << newLowestSeqNumber << "]: NOT DELETED");
            }

            ++elementItr;
        }
    }

    *theLowestSeqNumInMap = newLowestSeqNumber;

    if(loggerPacketLoss->isTraceEnabled()) {
        //if(loggerPacketLoss->isInfoEnabled()) {
        LOG4CXX_INFO(loggerPacketLoss, "deleteElementsFromMap; Deleted " <<  count << " elements from map [" << myMap.size()
                     << "] : Num 0's Deleted = " << count_0
                     << ": Num 1's Deleted = " << count_1
                     << ": newLowestSeqNumber = " << *theLowestSeqNumInMap);
    }
}
/*
 * Utility function to get determine the sequence number threshold to use when cleaning th sequence history maps
*/
void getMapCleaningThreshold(pktLossInfo *tcp_flow, uint32_t expSeqNum,  int direction, uint32_t *thresholdValue) {
    uint32_t diff, tempThresholdValue ;

    if(expSeqNum >  tcp_flow->lowestSeqNumInMap[direction]) {
        diff = (uint32_t)(expSeqNum - tcp_flow->lowestSeqNumInMap[direction]);
        tempThresholdValue =  diff / 2;
        *thresholdValue +=  tempThresholdValue + tcp_flow->lowestSeqNumInMap[direction];

        if(loggerPacketLoss->isTraceEnabled()) {
            //if(loggerPacketLoss->isInfoEnabled()) {
            LOG4CXX_INFO(loggerPacketLoss, "getMapCleaningThreshold; Setting Cleaning threshold: Direction = " << direction
                         << ": UEIP = "  << tcp_flow->fourTuple.ueIP <<  ": PORT = " << tcp_flow->fourTuple.uePort
                         << ": SERVE IP = "  << tcp_flow->fourTuple.serverIP <<  ": PORT = " << tcp_flow->fourTuple.serverPort
                         << ": Highest Seq Number [expSeqNum] = "  << expSeqNum
                         << ": Lowest Seq Number  = " << tcp_flow->lowestSeqNumInMap[direction]
                         << ": *thresholdValue  = " << *thresholdValue);
        }
    } else {
        LOG4CXX_TRACE(loggerPacketLoss, "getMapCleaningThreshold; Can not determine cleaning threshold for Seq Map, Setting to Lowest Seq Number: Direction = " << direction
                      << ": UEIP = "  << tcp_flow->fourTuple.ueIP <<  ": PORT = " << tcp_flow->fourTuple.uePort
                      << ": SERVE IP = "  << tcp_flow->fourTuple.serverIP <<  ": PORT = " << tcp_flow->fourTuple.serverPort
                      << ": Highest Seq Number [expSeqNum] = "  << expSeqNum
                      << ": Lowest Seq Number  = " << tcp_flow->lowestSeqNumInMap[direction]);
        *thresholdValue =  tcp_flow->lowestSeqNumInMap[direction];
    }
}
// 0 means packet sent, 1 means Ack received
void setPacketSent(pktLossInfo *tcp_flow, uint32_t expSeqNum,  int direction, uint16_t value) {
    if(expSeqNum < tcp_flow->lowestSeqNumInMap[direction]) {
        tcp_flow->lowestSeqNumInMap[direction] = expSeqNum;
    }

    if(direction == (int) PKT_LOSS_HEADING_TO_INTERNET) {
        if((unsigned int) tcp_flow->expectedSeqNumReceived_inet->size() >= (unsigned int) tcp_flow->SEQ_LIST_SIZE_INET) {
            std::tr1::unordered_map<u_int32_t, int16_t>::iterator firstElement = tcp_flow->expectedSeqNumReceived_inet->begin();
            tcp_flow->expectedSeqNumReceived_inet->erase(firstElement);
            uint32_t mapThresholdSeqNum = 0;
            getMapCleaningThreshold(tcp_flow, expSeqNum, direction , &mapThresholdSeqNum);
            deleteElementsFromMap(*(tcp_flow->expectedSeqNumReceived_inet), &(tcp_flow->lowestSeqNumInMap[direction]), expSeqNum, mapThresholdSeqNum);

            //printSeqMapContents(*(tcp_flow->expectedSeqNumReceived_inet));
            if(loggerPacketLoss->isTraceEnabled()) {
                //if(loggerPacketLoss->isInfoEnabled()) {
                tcp_flow->numTimesSeqMap_inet_maxed++;
            }
        }

        addElementToMap(*(tcp_flow->expectedSeqNumReceived_inet), expSeqNum, value);
    }

    if(direction == (int) PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
        if((unsigned int) tcp_flow->expectedSeqNumReceived_ue->size() >= (unsigned int) tcp_flow->SEQ_LIST_SIZE_UE) {
            std::tr1::unordered_map<u_int32_t, int16_t>::iterator firstElement = tcp_flow->expectedSeqNumReceived_ue->begin();
            tcp_flow->expectedSeqNumReceived_ue->erase(firstElement);
            uint32_t mapThresholdSeqNum = 0;
            getMapCleaningThreshold(tcp_flow, expSeqNum, direction , &mapThresholdSeqNum);
            deleteElementsFromMap(*(tcp_flow->expectedSeqNumReceived_ue), &(tcp_flow->lowestSeqNumInMap[direction]), expSeqNum, mapThresholdSeqNum);

            //printSeqMapContents(*(tcp_flow->expectedSeqNumReceived_ue));
            if(loggerPacketLoss->isTraceEnabled()) {
                //if(loggerPacketLoss->isInfoEnabled()) {
                tcp_flow->numTimesSeqMap_ue_maxed++;
            }
        }

        addElementToMap(*(tcp_flow->expectedSeqNumReceived_ue), expSeqNum, value);
    }
}

// gets the highest expectd sequence number , allowing for unsigned int 32 roll over
void getHighExpectedSeqNum(pktLossInfo *tcp_flow, uint32_t  theCurrSeqNum, uint32_t theTcpPayloadSize, int direction) {
    //efitleo: pow(2,32) is to handle sequence number roll over case
    if((theCurrSeqNum + theTcpPayloadSize) % (unsigned long)pow(2, 32) == (theCurrSeqNum + theTcpPayloadSize)) {
        tcp_flow->highExpectedSeqNum[direction] = theCurrSeqNum + theTcpPayloadSize;
    } else {
        tcp_flow->highExpectedSeqNum[direction] = (uint32_t)((theCurrSeqNum + theTcpPayloadSize) % (unsigned long)pow(2, 32));
    }
}


void handleTCPPacketHeadingToUE(const struct tcphdr *tcp, uint32_t tcpPayloadSize, pktLossInfo *tcp_flow, const unsigned long long *currPktTime) {
    tcp_flow->payload[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcpPayloadSize;
    uint32_t  currSeqNum, currAckNum, expectedSeqNum;
    currSeqNum = ntohl(tcp->seq);
    currAckNum = ntohl(tcp->ack_seq);
    expectedSeqNum = currSeqNum + tcpPayloadSize;
	//EQEV-10887 tcp_flow->currentSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
	
    if(*currPktTime > tcp_flow->lastPktTime) {
        tcp_flow->lastPktTime = *currPktTime;
    }

    // handle syn for rtt calculation
    if(tcp->syn) { // first packet has syn bit set.
        if(tcp_flow->syn1Time != 0 && tcp_flow->synSeq + 1 == ntohl(tcp->ack_seq)) {
            tcp_flow->syn2Time = *currPktTime;
        }
    }

    // process RTO event : ReTransmission Time out 
    // efitleo: expectedSeqNum = currSeqNum + tcpPayloadSize is the sequence number of the next expected packet
    //          getSeqAndTime returns the seqTime for the next expected packet in this case. If !=0 then we have already received it.
    //          So it a re-transmission of a already re-transmitted packet.

    if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] == 1) {
        if((currSeqNum < tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) && (isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT) >= 0)) {  // need to check if retx
            tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
        }

        // efitleo:  Retransmitted packet if the sequence number is smaller than the highest seen sequence number and last highest sequence number packet was seen at least 20ms before
        if(currSeqNum < tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] &&
                (*currPktTime - tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) >= (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
            tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
            tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        }

        // if hightest ACK < Highest Seq (recoveredOrig) and this packet has not been sent, then this is now the highest packets sent during this RTO
        if((tcp_flow->highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] <= tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) && (isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT)  == -1)) {  // need to check if not retx
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        }
    }

    // handle data for direction PKT_LOSS_HEADING_TO_USER_EQUIPMENT
    // new pkt
    if((currSeqNum > tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] || tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] < tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT])  && (tcpPayloadSize > 0)) {
        tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = *currPktTime;
        getHighExpectedSeqNum(tcp_flow, currSeqNum, tcpPayloadSize, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
        setUniqueBytesCount(tcp_flow, PKT_LOSS_HEADING_TO_USER_EQUIPMENT, tcpPayloadSize);
        setPacketSent(tcp_flow, expectedSeqNum , PKT_LOSS_HEADING_TO_USER_EQUIPMENT, 0);

        if((loggerPacketLoss->isTraceEnabled())) {
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_USER_EQUIPMENT NEW PKT "
                          << ": expectedSeqNum = " << expectedSeqNum << ": Value = " << isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT));
        }
    } // retx: efitleo: ReTransmitted packet
    else if(currSeqNum <= tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] && tcpPayloadSize > 0) {
        // FAst re-transmits //efitleo: was >= 2
        if(tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > 2 && currSeqNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] &&
                *currPktTime - tcp_flow->lastAckTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] < (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->fastReTxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] ++;
        }

        // do retx/dupretx count algo:
        // efitleo:  newly Retransmitted packet if the sequence number is smaller than the highest seen sequence number [above in "else if"] and last highest sequence number packet was seen at least 20ms before
        tcp_flow->retxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
        // EQEV-10887 FOR DEBUG:  tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + tcpPayloadSize;
        
        if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] == 0 &&
                (*currPktTime - tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) >= (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 1;
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
            tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
            tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 1;
            tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 0;
            tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        }
        else  { //RTO Not started for flow and its a re-transmitted packet due to RTT or Fast ReTX
			if(tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] <  tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] ) {  // currSeqNum 4294967295 -> 1 rollover case
				 /* // EQEV-10887 FOR DEBUG
				 LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_USER_EQUIPMENT: EXPECTED SEQ # (Rollover) " 
																						   << ": currSeqNum SEQ # = :" << currSeqNum  
																						   << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] 
																						   << ": highSeq = " << tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
																						   ); 
				*/ 
				tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 0;
			}
			if(currSeqNum > tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] ) {
				//LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_USER_EQUIPMENT: HIGHEST RETX SEQ  : currSeqNum SEQ # = :" << currSeqNum  << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] ); 
				tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
			} 
			else { // it aready been re-transmitted (Duplicate ReTx Non RTO)
				/* // EQEV-10887 FOR DEBUG
				LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_USER_EQUIPMENT: DUP ReTx Non RTO RETX SEQ " 
																						   << ": currSeqNum SEQ # = :" << currSeqNum  
																						   << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] 
																						   << ": highSeq = " << tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
																						   ); 
				*/
				tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
			}
		}
    }
    else if (tcpPayloadSize == 0) {// ACK PACKET
		  if(loggerPacketLoss->isTraceEnabled()) {
			  /* // EQEV-10887 FOR DEBUG
			  LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_USER_EQUIPMENT SEQ NUMBER with TCP Payload =0 (probably ACK packet) "
							  << ": currSeqNum = " << currSeqNum 
							  << ": expectedSeqNum = " << expectedSeqNum 
							  << ": tcp_flow->highSeq = " <<  tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
							  << ": tcp_flow->expSeq (= (the previous currSeqNum) + tcpPayloadSize  = " <<  tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
		     */
		  }
	}
    else { // unknown condition
		  LOG4CXX_ERROR(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_USER_EQUIPMENT UNKNOWN SEQ NUMBER "
                          << ": currSeqNum = " << currSeqNum 
                          << ": highSeq = " <<  tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]
                          << ": tcp_flow->expSeq (= (the previous currSeqNum) + tcpPayloadSize  = " <<  tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
	}

    //efitleo: pow(2,32) is to handle sequence number roll over case
    if((currSeqNum + tcpPayloadSize) % (unsigned long)pow(2, 32) == (currSeqNum + tcpPayloadSize)) {
        tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum + tcpPayloadSize;
    } else {
        tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = (uint32_t)((currSeqNum + tcpPayloadSize) % (unsigned long)pow(2, 32));
    }

    if(tcpPayloadSize > 0) {
        tcp_flow->pktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
        // EQEV-10887 FOR DEBUG: tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + tcpPayloadSize;
    }

    // handle ack for direction PKT_LOSS_HEADING_TO_USER_EQUIPMENT
    // efitleo: If Internet Side pkt PKT_LOSS_HEADING_TO_USER_EQUIPMENT acknowlede's a packet of seq num = value in the ACK field, then let the UE side Know [pkt PKT_LOSS_HEADING_TO_INTERNET] that we have received that lot of packets.
    if(tcp->ack) { //efitleo: If ACK FIELD is VALID
        // process RTO event
        if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_INTERNET] == 1) {
            // tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] is seq number of last acknowledged packet. So if currAckNum > tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] then this is a newly acknowleded packet
            if(currAckNum > tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET]) {
                tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_INTERNET] +=  
                    minU32(tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_INTERNET], tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_INTERNET]); //total number of retetransmissions for this packet
                tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_INTERNET] = 0;
            } else if(currAckNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_INTERNET] && currAckNum >= tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_INTERNET]) {
                tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_INTERNET]++;
            }
        }

        // calculate fast retx
        if(currAckNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_INTERNET]) {
            tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_INTERNET]++;
        } else {
            tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_INTERNET] = 0;
        }

        // regular ack packet
        if((currAckNum > tcp_flow->highAck[PKT_LOSS_HEADING_TO_INTERNET]) || (tcp_flow->lastAck[PKT_LOSS_HEADING_TO_INTERNET] - currAckNum > 0)) {
            tcp_flow->highAck[PKT_LOSS_HEADING_TO_INTERNET] = currAckNum;
            tcp_flow->highAckTime[PKT_LOSS_HEADING_TO_INTERNET] = *currPktTime;

            // Find the packet and if pesent Ack it
            if(isPacketSent(tcp_flow, currAckNum, PKT_LOSS_HEADING_TO_INTERNET) != -1) {  // -1 is not found
                setPacketSent(tcp_flow, currAckNum , PKT_LOSS_HEADING_TO_INTERNET, 1);

                if(loggerPacketLoss->isTraceEnabled()) {
                    LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_INTERNET ACK PACKET "
                                  << ": currAckNum = " << currAckNum << ": Value = " << isPacketSent(tcp_flow, currAckNum, PKT_LOSS_HEADING_TO_INTERNET));
                }
            }
        }

        tcp_flow->lastAck[PKT_LOSS_HEADING_TO_INTERNET] = currAckNum;
        tcp_flow->lastAckTime[PKT_LOSS_HEADING_TO_INTERNET] = *currPktTime;
    }
}


void handleTCPPacketHeadingToInternet(const struct tcphdr *tcp, uint32_t tcpPayloadSize, pktLossInfo *tcp_flow, const unsigned long long *currPktTime) {
    tcp_flow->payload[PKT_LOSS_HEADING_TO_INTERNET] = tcpPayloadSize;
    uint32_t currSeqNum, currAckNum, expectedSeqNum;
    currSeqNum = ntohl(tcp->seq);
    currAckNum = ntohl(tcp->ack_seq);
    expectedSeqNum = currSeqNum + tcpPayloadSize;
    //EQEV-10887 tcp_flow->currentSeqNum[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
	

    if(*currPktTime > tcp_flow->lastPktTime) {
        tcp_flow->lastPktTime = *currPktTime;
    }

    // handle ack for direction PKT_LOSS_HEADING_TO_INTERNET
    // efitleo: If UE Side acknowlede's a packet of seq num = value in the ACK field, then let the INTERNET side Know that we have received that lot of packets.

    if(tcp->ack) {  //ack bit set indicates acknowledgement field is Valid
        // process RTO event Re-transmiision TimeOut Event
        if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] == 1) {
            // newly recovered packet
            if(currAckNum > tcp_flow->recovered[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
                tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] +=
                    minU32(tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT], tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
                tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 0;
            } else if(currAckNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] &&
                      currAckNum >= tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
                tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
            }
        }

        // calculate duplicate acks for possible fast retx
        if(currAckNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
            tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
        } else {
            tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = 0;
        }

        // calculate rtt based on syn : efitleo syn1Time set  when first packet in tcp_flow is processed
        if(tcp_flow->syn1Time != 0 && tcp_flow->synRttFound == 0 &&
                tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + 1 == ntohl(tcp->ack_seq)) {
            tcp_flow->synAckTime = *currPktTime;
            tcp_flow->synRttFound = 1;
        }

        // regular ack packet
        if((currAckNum > tcp_flow->highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) ||
                (tcp_flow->lastAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - currAckNum > 0)) {
            tcp_flow->highAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currAckNum;
            tcp_flow->highAckTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = *currPktTime;
			
            // Find the packet and if pesent Ack it
            if(isPacketSent(tcp_flow, currAckNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT) != -1) {  // -1 is not found
                setPacketSent(tcp_flow, currAckNum , PKT_LOSS_HEADING_TO_USER_EQUIPMENT, 1);

                if(loggerPacketLoss->isTraceEnabled()) {
                    LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_USER_EQUIPMENT ACK PACKET "
                                  << ": currAckNum = " << currAckNum << ": Value = " << isPacketSent(tcp_flow, currAckNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT));
                }
            }
        }

        tcp_flow->lastAck[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currAckNum;
        tcp_flow->lastAckTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = *currPktTime;
    }

    // handle data for direction PKT_LOSS_HEADING_TO_INTERNET
    // process RTO event
    if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_INTERNET] == 1) {
        // efitleo: expectedSeqNum = currSeqNum + tcpPayloadSize is the sequence number of the next expected packet
        //          isPacketSent returns the 1 if packet sent and ack received ,0 if packet sent and not ACK, -1 if not sent. If >=0 then we have already sent it.
        //          So it a re-transmission of a already re-transmitted packet.
        if((currSeqNum < tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET]) && (isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET) >= 0)) {   // need to check if retx
            tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_INTERNET]++;
        }

        // efitleo:  Retransmitted packet if the sequence number is smaller than the highest seen sequence number (= tcp_flow->recovered) and last highest sequence number packet was seen at least 20ms before
        if(currSeqNum < tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] &&
                (*currPktTime - tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_INTERNET]) >= (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET];
            tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET];
            tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        }

        if((tcp_flow->highAck[PKT_LOSS_HEADING_TO_INTERNET] <= tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_INTERNET]) && (isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET) == -1)) {    // need to check if not ret
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        }
    }

    // handle data for direction PKT_LOSS_HEADING_TO_INTERNET
    // new pkt
    if((currSeqNum > tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] || tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET] < tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET]) && (tcpPayloadSize > 0)) {
        tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_INTERNET] = *currPktTime;
        getHighExpectedSeqNum(tcp_flow, currSeqNum, tcpPayloadSize, PKT_LOSS_HEADING_TO_INTERNET);
        setUniqueBytesCount(tcp_flow, PKT_LOSS_HEADING_TO_INTERNET, tcpPayloadSize);
        setPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET, 0);
		//LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS  TX : currSeqNum SEQ # = :" << currSeqNum  << ": expectedSeqNum = " << expectedSeqNum << ": tx_state = 0 "   ); 
        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_INTERNET NEW PKT "
                          << ": expectedSeqNum = " << expectedSeqNum << ": Value = " << isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET));
        }
    } // retx
    else if(currSeqNum <= tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] && tcpPayloadSize > 0) {
        // FAst Re Tranmit //efitleo: was >= 2
        if(tcp_flow->dupAckInARow[PKT_LOSS_HEADING_TO_INTERNET] > 2 && currSeqNum == tcp_flow->lastAck[PKT_LOSS_HEADING_TO_INTERNET] &&
                *currPktTime - tcp_flow->lastAckTime[PKT_LOSS_HEADING_TO_INTERNET] < (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->fastReTxCount[PKT_LOSS_HEADING_TO_INTERNET] ++;
        }

        // do retx/dupretx count algo
        // efitleo:  newly Retransmitted packet if the sequence number is smaller than the highest seen sequence number [above in "else if"] and last highest sequence number packet was seen at least 20ms before
        tcp_flow->retxCount[PKT_LOSS_HEADING_TO_INTERNET]++;
        // EQEV-10887 FOR DEBUG:  tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->totalReTxBytes[PKT_LOSS_HEADING_TO_INTERNET] + tcpPayloadSize;        
        // EQEV-10887 FOR DEBUG: int16_t tx_state = isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET);
	    // EQEV-10887 FOR DEBUG: if (tx_state == 0) tcp_flow->uniqueRetxCount[PKT_LOSS_HEADING_TO_INTERNET]++;
	    
        if(tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_INTERNET] == 0 &&
                (*currPktTime - tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_INTERNET]) >= (0.02 * PKTLOSS_RESOLUTION)) {
            tcp_flow->isRTOStarted[PKT_LOSS_HEADING_TO_INTERNET] = 1;
            tcp_flow->recovered[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET];
            tcp_flow->recoveredOrig[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET];
            tcp_flow->retxLocal[PKT_LOSS_HEADING_TO_INTERNET] = 1;
            tcp_flow->dupAckLocal[PKT_LOSS_HEADING_TO_INTERNET] = 0;
            tcp_flow->rtoAffectedPkt[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        }
        else  { //RTO Not started for flow and its a re-transmitted packet due to RTT or Fast ReTX
			if(tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] <  tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] ) {  // currSeqNum 4294967295 -> 1 rollover case
				 /* // EQEV-10887 FOR DEBUG
				 LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_USER_EQUIPMENT: EXPECTED SEQ # (Rollover) " 
																						   << ": currSeqNum SEQ # = :" << currSeqNum  
																						   << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] 
																						   << ": highSeq = " << tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] 
																						   ); 
				*/
				tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] = 0;
			}
			if(currSeqNum > tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] ) {
				//LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_INTERNET: HIGHEST RETX SEQ  : currSeqNum SEQ # = :" << currSeqNum  << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] ); 
				tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
			} 
			else { // it aready been re-transmitted (Duplicate ReTx Non RTO)
				/* // EQEV-10887 FOR DEBUG
				LOG4CXX_INFO(loggerPacketLoss, " PACKET LOSS PKT_LOSS_HEADING_TO_INTERNET: DUP ReTx Non RTO RETX SEQ "
																						   << ": currSeqNum SEQ # = :" << currSeqNum  
																						   << ": highReTxSeq = " << tcp_flow->highReTxSeq[PKT_LOSS_HEADING_TO_INTERNET] 
																						   << ": highSeq = " << tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET]
																						   ); 
			    */
				tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_INTERNET]++;
			}
		}
    }
    else if  (tcpPayloadSize == 0) {// ACK PACKET 
		if(loggerPacketLoss->isTraceEnabled()) {
			  /* // EQEV-10887 FOR DEBUG
			  LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_INTERNET SEQ NUMBER with TCP Payload =0 (probably ACK packet) "
							  << ": currSeqNum = " << currSeqNum 
							  << ": expectedSeqNum = " << expectedSeqNum 
							  << ": tcp_flow->highSeq = " <<  tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET]
							  << ": tcp_flow->expSeq (= (the previous currSeqNum) + tcpPayloadSize  = " <<  tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET]);
			  */
		}
	}
    else{ // unknown condition
		  LOG4CXX_ERROR(loggerPacketLoss, " PACKET LOSS: PKT_LOSS_HEADING_TO_INTERNET UNKNOWN SEQ NUMBER "
                          << ": currSeqNum = " << currSeqNum 
                          << ": expectedSeqNum = " << expectedSeqNum 
                          << ": tcp_flow->highSeq = " <<  tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET]
                          << ": tcp_flow->expSeq (= (the previous currSeqNum) + tcpPayloadSize  = " <<  tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET]);
	}

    //efitleo: pow(2,32) is to handle sequence number roll over case
    if((currSeqNum + tcpPayloadSize) % (unsigned long)pow(2, 32) == (currSeqNum + tcpPayloadSize)) {
        tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum + tcpPayloadSize;
    } else {
        tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET] = (uint32_t)((currSeqNum + tcpPayloadSize) % (unsigned long)pow(2, 32));
    }

    if(tcpPayloadSize > 0) {
        tcp_flow->pktCount[PKT_LOSS_HEADING_TO_INTERNET]++;
        // EQEV-10887 FOR DEBUG: tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_INTERNET] + tcpPayloadSize;
    }
}


void handleNewFlow(const struct tcphdr *tcp, uint32_t  tcpPayloadSize, int pkt_loss_direction, pktLossInfo *tcp_flow, const unsigned long long *currPktTime) {
    uint32_t currSeqNum, currAckNum, expectedSeqNum;
    currSeqNum = ntohl(tcp->seq);
    currAckNum = ntohl(tcp->ack_seq);
    expectedSeqNum = currSeqNum + tcpPayloadSize;
	
    if(*currPktTime > tcp_flow->lastPktTime) {
        tcp_flow->lastPktTime = *currPktTime;
    }

    // handle syn for rtt
    if(tcp->syn) {
        tcp_flow->syn1Time = *currPktTime;
        tcp_flow->synSrc = tcp->source;
        tcp_flow->synSeq = currSeqNum;
        tcp_flow->synAck = currAckNum;
    }

    if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
		//EQEV-10887 tcp_flow->currentSeqNum[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        tcp_flow->payload[PKT_LOSS_HEADING_TO_INTERNET] = tcpPayloadSize;
        if(tcpPayloadSize > 0) {
			tcp_flow->pktCount[PKT_LOSS_HEADING_TO_INTERNET]++;
			// EQEV-10887 FOR DEBUG:  tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_INTERNET] = tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_INTERNET] + tcpPayloadSize;
		}
        tcp_flow->highSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum;
        tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_INTERNET] = *currPktTime;
        getHighExpectedSeqNum(tcp_flow, currSeqNum, tcpPayloadSize, PKT_LOSS_HEADING_TO_INTERNET);
        setUniqueBytesCount(tcp_flow, PKT_LOSS_HEADING_TO_INTERNET, tcpPayloadSize);
        
        if(tcp->syn) {
            tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum + 1;
        } else {
            tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET] = currSeqNum + tcpPayloadSize;
        }
		expectedSeqNum = tcp_flow->expSeq[PKT_LOSS_HEADING_TO_INTERNET];
		
        setPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET, 0);
        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: NEW FLOW PKT_LOSS_HEADING_TO_INTERNET  : UE IP --> " << tcp_flow->fourTuple.ueIP  << ":" << tcp_flow->fourTuple.uePort
                          << ": INTERNET IP --> " << tcp_flow->fourTuple.serverIP << ":" << tcp_flow->fourTuple.serverPort);
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: NEW FLOW PKT_LOSS_HEADING_TO_INTERNET  : "
                          << ": expectedSeqNum = " << expectedSeqNum << ": Value = " << isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_INTERNET));
        }
    } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
		//EQEV-10887 tcp_flow->currentSeqNum[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        tcp_flow->payload[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcpPayloadSize;
        if(tcpPayloadSize > 0) {
			tcp_flow->pktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]++;
			// EQEV-10887 FOR DEBUG: tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = tcp_flow->totalBytes[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + tcpPayloadSize;
		}
        tcp_flow->highSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum;
        tcp_flow->highSeqTime[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = *currPktTime;
        getHighExpectedSeqNum(tcp_flow, currSeqNum, tcpPayloadSize, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
        setUniqueBytesCount(tcp_flow, PKT_LOSS_HEADING_TO_USER_EQUIPMENT, tcpPayloadSize);
        
        if(tcp->syn) {
            tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum + 1;
        } else {
            tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = currSeqNum + tcpPayloadSize;
        }
        
        expectedSeqNum = tcp_flow->expSeq[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
        setPacketSent(tcp_flow, expectedSeqNum , PKT_LOSS_HEADING_TO_USER_EQUIPMENT, 0);

        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: NEW FLOW PKT_LOSS_HEADING_TO_USER_EQUIPMENT  : UE IP --> " << tcp_flow->fourTuple.ueIP  << ":" << tcp_flow->fourTuple.uePort
                          << ": INTERNET IP --> " << tcp_flow->fourTuple.serverIP << ":" << tcp_flow->fourTuple.serverPort);
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: NEW FLOW PKT_LOSS_HEADING_TO_USER_EQUIPMENT  : "
                          << ": expectedSeqNum = " << expectedSeqNum << ": Value = " << isPacketSent(tcp_flow, expectedSeqNum, PKT_LOSS_HEADING_TO_USER_EQUIPMENT));
        }
    }
}


int printSpecial(const struct PectPacketHeader *pectHeader, PectIP4Tuple tuple, pktLossInfo *tcp_flow) {
    // DISABLE THIS FOR PRODUCTION
    return 0;

    //if(loggerPacketLoss->isInfoEnabled()) {
    if(loggerPacketLoss->isTraceEnabled()) {
        if((tuple.ueIP == 2043369491) && (tuple.serverIP == 2114797117) && (tuple.uePort == 58192) && (tuple.serverPort == 8986)) {
            return 1;
        }
    }

    return 0;
}

int convertDirectionToPktLossDirection(int direction) {
    int pkt_loss_direction = -1;

    if(direction == HEADING_TO_INTERNET) {
        pkt_loss_direction = 0;
    } else if(direction == HEADING_TO_USER_EQUIPMENT) {
        pkt_loss_direction = 1;
    } else { // direction is not valid for packet loss calculation..
        pkt_loss_direction = -1;
    }

    return pkt_loss_direction;
}
/*
 * getPacketLossRate
 *
 * Calculate current packet loss based on current cumulative informaton
 */
void getPacketLossRate(flow_data *flow_data, int loc) {
    pktLossInfo *tcp_flow;
    int queueNum = flow_data->queueNumber;
    tcp_flow = &(flow_data->tcpPktLossInfo);
    tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = UINT_MAX;
    tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET] = UINT_MAX;
    // Packet Loss Rate is multiplied by PKTLOSS_RATE_RESOLUTION to keep from having to operate in floats
    tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = pktLossCheckDataIntegrity(tcp_flow, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);

    if(tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
        if(tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) {
			uint32_t uniqueReTx_count = tcp_flow->retxCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] - (tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
            flow_data->internetToUeLossRate = (uniqueReTx_count * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
        } else {
            if(loc) {
                hashTableCtrs.numFlowsNoPktLossRate_UE[queueNum]++;
            }
        }

        if(loc) {
            hashTableCtrs.numFlowsPktLoss_UE[queueNum]++;
        }
    }

    tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET] = pktLossCheckDataIntegrity(tcp_flow, PKT_LOSS_HEADING_TO_INTERNET);

    if(tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET]) {
        if(tcp_flow->isGoodData[PKT_LOSS_HEADING_TO_INTERNET]) {
			uint32_t uniqueReTx_count = tcp_flow->retxCount[PKT_LOSS_HEADING_TO_INTERNET] - (tcp_flow->dupRetxCount_non_RTO[PKT_LOSS_HEADING_TO_INTERNET] + tcp_flow->dupRetxCount_RTO[PKT_LOSS_HEADING_TO_INTERNET]);
            flow_data->ueToInternetLossRate = (uniqueReTx_count * PKTLOSS_RATE_RESOLUTION) / tcp_flow->uniquePktCount[PKT_LOSS_HEADING_TO_INTERNET];
        } else {
            if(loc) {
                hashTableCtrs.numFlowsNoPktLossRate_INET[queueNum]++;
            }
        }

        if(loc) {
            hashTableCtrs.numFlowsPktLoss_INET[queueNum]++;
        }
    }
}

/*
 * calculate TCP PacketLoss Updates
 */
void calculateTCPPacketLoss(flow_data *flow_data, unsigned int protocol, const struct PectPacketHeader *pectHeader, const PacketDirection_t direction, const u_char *rawPacket, u8 *new_flow, int queue_num) {
    unsigned int tcpHeaderSize = 0;
    uint32_t  tcpPayloadSize = 0;
    pktLossInfo *tcp_flow;
    PectIP4Tuple tuple;
    int pkt_loss_direction = -1;
    u_int32_t currSeqNum, currAckNum;
    unsigned int ip2PectPacketSize;
    unsigned int iph2_header_size;
    unsigned int ip2Offset;
    unsigned int ip2PacketTotalLength;

    if(pectHeader->isTcpPacket == false) {
        if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
            pthread_mutex_lock(&packetLossMutex);
            pktLossCtrs.totalPackets++ ;
            pthread_mutex_unlock(&packetLossMutex);
        }

        return;
    }

    tcp_flow = &(flow_data->tcpPktLossInfo);

    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        pthread_mutex_lock(&packetLossMutex);
        pktLossCtrs.totalPackets++ ;
        pktLossCtrs.tcpPackets++;
        pthread_mutex_unlock(&packetLossMutex);
    }

    tuple = pectHeader->fourTuple;

    if((tuple.ueIP == 0) && (tuple.serverIP == 0) && (tuple.uePort == 0) && (tuple.serverPort == 0)) {
        if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
            LOG4CXX_WARN(loggerPacketLoss, " PACKET LOSS: calculateTCPPacketLoss: Invalid UEIP or SERVER ADDRESS in TCP Packets/ Total Packets: "
                         << pktLossCtrs.tcpPackets << "/" << pktLossCtrs.totalPackets << " : UE IP --> " << tuple.ueIP  << ":" << tuple.uePort
                         << ": INTERNET IP --> " << tuple.serverIP << ":" << tuple.serverPort);
        } else {
            LOG4CXX_WARN(loggerPacketLoss, " PACKET LOSS: calculateTCPPacketLoss: Invalid UEIP or SERVER ADDRESS in TCP Packets/ Total Packets: "
                         << " : UE IP --> " << tuple.ueIP  << ":" << tuple.uePort
                         << ": INTERNET IP --> " << tuple.serverIP << ":" << tuple.serverPort);
        }

        return;
    }

    // tcp_flow->fourTuple is set only once, when the new flow is originated, as determined by IPOQUE'S "new_element"
    if( ((tcp_flow->fourTuple.ueIP == 0) || (tcp_flow->fourTuple.serverIP == 0) || (tcp_flow->fourTuple.uePort == 0) || (tcp_flow->fourTuple.serverPort == 0) ) & (*new_flow == 0) ) {
		if(loggerPacketLoss->isDebugEnabled()) {
				LOG4CXX_WARN(loggerPacketLoss, " PACKET LOSS: calculateTCPPacketLoss: INVALID TCP FLOW; UE or SERVER IP or PORTS are set to zero: "
							  << ": THIS FLOW (pectHeader) UE IP --> " << tcp_flow->fourTuple.ueIP  << ":" << tcp_flow->fourTuple.uePort
							  << ": THIS FLOW (pectHeader) INTERNET IP --> " << tcp_flow->fourTuple.serverIP << ":" << tcp_flow->fourTuple.serverPort
							   <<": THIS FLOW (flow_data) UE IP --> " << flow_data->fourTuple.ueIP  << ":" << flow_data->fourTuple.uePort
							  << ": THIS FLOW (flow_data) INTERNET IP --> " << flow_data->fourTuple.serverIP << ":" << flow_data->fourTuple.serverPort
							  << ": *new_flow (u8->int; 0 means not a new flow o/w new flow) =  " << (int) *new_flow
							  << ": ORIGINAL FLOW (pectHeader) UE IP --> " << pectHeader->fourTuple.ueIP  << ":" << pectHeader->fourTuple.uePort
							  << ": ORIGINAL FLOW (pectHeader) INTERNET IP --> " << pectHeader->fourTuple.serverIP << ":" << pectHeader->fourTuple.serverPort);
		}
        hashTableCtrs.numFlowsNotInitializedByPacketLoss[queue_num]++;
        hashTableCtrs.totalFlowsThisQueuePacketLoss[queue_num]++;
        return;
    }

    iph2_header_size = pectHeader->userHeaderSize;
    ip2PacketTotalLength = pectHeader->userTotalLength;
    ip2Offset = pectHeader->userPacketOffset;
    ip2PectPacketSize = pectHeader->userPacketSize; // don't think this is always correct; See 5 min smt file packet 21499
    tcphdr *tcp = (tcphdr *)(rawPacket + ip2Offset + iph2_header_size);
    tcpHeaderSize = tcp->doff * 4;
    currSeqNum = ntohl(tcp->seq);
    currAckNum = ntohl(tcp->ack_seq);
    tcpPayloadSize = ip2PacketTotalLength - iph2_header_size - tcpHeaderSize ;

    if(tcpHeaderSize < 20) {
        if(loggerPacketLoss->isTraceEnabled()) {
            LOG4CXX_TRACE(loggerPacketLoss, " PACKET LOSS: Invalid TCP header length: " << tcpHeaderSize << " bytes, packet: " << pktLossCtrs.totalPackets);
        } else {
			if(loggerPacketLoss->isDebugEnabled()) {
				LOG4CXX_WARN(loggerPacketLoss, " PACKET LOSS: Invalid TCP header length: " << tcpHeaderSize << " bytes");
			}
        }

        return;
    }

    // Due to difference in definition of direction between PCP & PKT LOSS, DO a re-definition here
    //  PCP DEFINITION: -
    //  NOT_YET_DEFINED = -1,
    //  HEADING_TO_INTERNET = 1,
    //  HEADING_TO_USER_EQUIPMENT = 2
    //
    //  PKT LOSS DEFN
    //  PKT_LOSS_HEADING_TO_USER_EQUIPMENT 1
    //  PKT_LOSS_HEADING_TO_INTERNET 0

    if(direction == HEADING_TO_INTERNET) {
        pkt_loss_direction = 0;
    } else if(direction == HEADING_TO_USER_EQUIPMENT) {
        pkt_loss_direction = 1;
    } else { // direction is not valid for packet loss calculation..
        return;
    }

    if(*new_flow != 0)  {
        // handle new tcp_flow;
        hashTableCtrs.totalFlowsThisQueuePacketLoss[queue_num]++;

        if((tcp_flow->fourTuple.ueIP != 0) && (tcp_flow->fourTuple.serverIP != 0) && (tcp_flow->fourTuple.uePort != 0) && (tcp_flow->fourTuple.serverPort != 0) & (*new_flow != 0)) {
            LOG4CXX_WARN(loggerPacketLoss, " PACKET LOSS: calculateTCPPacketLoss: THIS FLOW HAS BEEN INITIALISED PREVIOUSLY BY PACKET LOSS: "
                         << "THIS Flow_data four Tulpe information will be over written by the NEW pectHeader four tuple "
                         << ": THIS FLOW (pectHeader) UE IP --> " << tcp_flow->fourTuple.ueIP  << ":" << tcp_flow->fourTuple.uePort
                         << ": THIS FLOW (pectHeader) INTERNET IP --> " << tcp_flow->fourTuple.serverIP << ":" << tcp_flow->fourTuple.serverPort
                         << ": *new_flow (u8->int ; 0 means not a new flow o/w new flow) =  " << (int) *new_flow
                         << ": NEW FLOW (pectHeader) UE IP --> " << pectHeader->fourTuple.ueIP  << ":" << pectHeader->fourTuple.uePort
                         << ": NEW FLOW (pectHeader) INTERNET IP --> " << pectHeader->fourTuple.serverIP << ":" << pectHeader->fourTuple.serverPort);
        }

        initCounters(tcp_flow);
        tcp_flow->fourTuple = tuple;
        tcp_flow->queueNumber = (int16_t) flow_data->queueNumber;
        handleNewFlow(tcp, tcpPayloadSize, pkt_loss_direction, tcp_flow, &(pectHeader->packetTime_uS));

        if(loggerPacketLoss->isTraceEnabled())
            LOG4CXX_TRACE(loggerPacketLoss, "PACKET LOSS: NEW FLOW FOR CALCULATE PKT LOSS new_flow (u8 -> int) =  " << (int) *new_flow
                          << ": ueIP: port " << tcp_flow->fourTuple.ueIP << ": " << tcp_flow->fourTuple.uePort
                          << ": Server: port " << tcp_flow->fourTuple.serverIP << ": " << tcp_flow->fourTuple.serverPort);
    } else {
        // handle old tcp_flow
        // handle traffic PKT_LOSS_HEADING_TO_USER_EQUIPMENT direction
        if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
            if(tcp_flow->resetPerRop) {
                resetPerROPCounters(tcp_flow);
                tcp_flow->fourTuple = tuple;
                tcp_flow->queueNumber = (int16_t) flow_data->queueNumber;
                tcp_flow->resetPerRop = 0;
            }

            handleTCPPacketHeadingToUE(tcp, tcpPayloadSize, tcp_flow, &(pectHeader->packetTime_uS));
            // handle traffic PKT_LOSS_HEADING_TO_INTERNET direction
        } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
            if(tcp_flow->resetPerRop) {
                resetPerROPCounters(tcp_flow);
                tcp_flow->fourTuple = tuple;
                tcp_flow->queueNumber = (int16_t) flow_data->queueNumber;
                tcp_flow->resetPerRop = 0;
            }

            handleTCPPacketHeadingToInternet(tcp, tcpPayloadSize, tcp_flow, &(pectHeader->packetTime_uS));
        }
    }

    getPacketLossRate(flow_data, 0);

    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        uint32_t pktLossRate [2];
        pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = flow_data->internetToUeLossRate ;
        pktLossRate [PKT_LOSS_HEADING_TO_INTERNET] = flow_data->ueToInternetLossRate ;

        if((pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT] != 0) && (tcp_flow->pktCount[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > PACKET_LOSS_MIN_PACKETS)) {
            pthread_mutex_lock(&packetLossMutex);
            pktLossCtrs.internetToUEpktLoss++;

            if(pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT] > pktLossCtrs.maxLoss_internetToUE) {
                pktLossCtrs.maxLoss_internetToUE = pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT];
            }

            pthread_mutex_unlock(&packetLossMutex);
        }

        if((pktLossRate [PKT_LOSS_HEADING_TO_INTERNET] != 0) && (tcp_flow->pktCount[PKT_LOSS_HEADING_TO_INTERNET] > PACKET_LOSS_MIN_PACKETS)) {
            pthread_mutex_lock(&packetLossMutex);
            pktLossCtrs.ueToInternetpktLoss++;

            if(pktLossRate [PKT_LOSS_HEADING_TO_INTERNET] > pktLossCtrs.maxLoss_ueToInternet) {
                pktLossCtrs.maxLoss_ueToInternet = pktLossRate [PKT_LOSS_HEADING_TO_INTERNET];
            }

            pthread_mutex_unlock(&packetLossMutex);
        }
    }

    //if(loggerPacketLoss->isInfoEnabled()) {
    if(loggerPacketLoss->isTraceEnabled()) {
        if(printSpecial(pectHeader, tuple, tcp_flow)) {
            // get ADDR for printing only
            struct in_addr ueIPIn;
            struct in_addr serverIPIn;
            ueIPIn.s_addr = htonl((tuple.ueIP));
            serverIPIn.s_addr = htonl((tuple.serverIP));
            char ueIPBuf[40];
            char serverIPBuf[40];
            inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
            inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
            int headingNumber = 0;
            uint32_t pktLossRate [2];
            pktLossRate [PKT_LOSS_HEADING_TO_USER_EQUIPMENT] = flow_data->internetToUeLossRate ;
            pktLossRate [PKT_LOSS_HEADING_TO_INTERNET] = flow_data->ueToInternetLossRate ;
            // char *heading[]
            string heading[5] = {"----  PACKET LOSS : DEFAULT HEADING ---->",
                                 "----  PACKET LOSS : NEW FLOW:  HEADING_TO_USER_EQUIPMENT ---->",
                                 "----  PACKET LOSS : HEADING_TO_USER_EQUIPMENT ----> ",
                                 "----   PACKET LOSS : NEW FLOW:  HEADING_TO_INTERNET ---->",
                                 "----  PACKET LOSS : HEADING_TO_INTERNET---->"
                                };

            if(*new_flow != 0) {
                if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
                    headingNumber = 1;
                } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
                    headingNumber = 3;
                }
            } else {
                if(pkt_loss_direction == PKT_LOSS_HEADING_TO_USER_EQUIPMENT) {
                    headingNumber = 2;
                } else if(pkt_loss_direction == PKT_LOSS_HEADING_TO_INTERNET) {
                    headingNumber = 4;
                }
            }

            LOG4CXX_INFO(loggerPacketLoss, heading[headingNumber]  << "," << (int)*new_flow
                         << "," << pkt_loss_direction
                         << "," << ueIPBuf << "," << tuple.uePort
                         << "," << serverIPBuf << "," << tuple.serverPort
                         << "," << tcp_flow->pktCount[pkt_loss_direction]
                         << "," << tcp_flow->uniquePktCount[pkt_loss_direction]
                         << "," << tcp_flow->retxCount[pkt_loss_direction]
                         << "," << tcp_flow->dupRetxCount_RTO[pkt_loss_direction]
                         << "," << tcp_flow->fastReTxCount[pkt_loss_direction]
                         << "," << pktLossRate [pkt_loss_direction]);
            LOG4CXX_INFO(loggerPacketLoss, heading[headingNumber]  << "," <<  "new_flow (u8->int)"
                         << "," << "pkt_loss_direction"
                         << "," << "UE IP " << "," << "UE Port"
                         << "," << "Server IP" << "," << "Server Port"
                         << "," << "Pkt Count (total)"
                         << "," << "Unique Pkt Count"
                         << "," << "ReTx Count (total)"
                         << "," << "dup ReTx Count (RTO)"
                         << "," << "dup ReTx Count (non RTO)"
                         << "," << "Fast ReTx Count"
                         << "," << "pkt Loss Rate");
            //static_cast<void *>
            LOG4CXX_TRACE(loggerPacketLoss, "\n" << heading[headingNumber]  << "new_flow (u8->int) = " << (int)*new_flow << ": pkt_loss_direction = " << pkt_loss_direction << "\n"
                          << pktLossCtrs.totalPackets << "    PACKET LOSS UE IP                            : " << ueIPBuf << ":" << tuple.uePort <<  " [" << tuple.ueIP << "]" << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS INTERNET IP                      : " << serverIPBuf << ":" << tuple.serverPort <<  " [" << tuple.serverIP << "]" << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS Overall Packet Count             : tcp = " << pktLossCtrs.tcpPackets << ": Total = " << pktLossCtrs.totalPackets << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS PktCount [this flow]             : " <<  tcp_flow->pktCount[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS uniquePktCount [this flow]       : " <<  tcp_flow->uniquePktCount[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS ReTxCount (total) [this flow]    : " <<  tcp_flow->retxCount[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS DupReTxCount_RTO [this flow]     : " <<  tcp_flow->dupRetxCount_RTO[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS DupReTxCount_non_RTO [this flow] : " <<  tcp_flow->dupRetxCount_non_RTO[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS FastReTx [this flow]             : " <<  tcp_flow->fastReTxCount[pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << "    PACKET LOSS LossRate[this flow]              : " <<  pktLossRate [pkt_loss_direction] << endl
                          << pktLossCtrs.totalPackets << " END --------------------------------------------------------------" << endl);
        }
    }
}



