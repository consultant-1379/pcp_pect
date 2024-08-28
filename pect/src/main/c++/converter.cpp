#include "ipq_api.h"
#include "converter.h"
#include "UE_map.hpp"
#include "file_writer.hpp"


extern int kRopDurationInMinutes;
extern std::tr1::unordered_map<unsigned int, unsigned int>  custom_group_system;
extern const char *protocol_short_str[];
extern const char *protocolGroupString[];
void Converter::convertTo13AFunction(Classification13A *v13A, const flow_data *flow) {
    std::tr1::unordered_map<int, V13AFunction::V13AFunctionEnum>::iterator it = function13Bto13A.find(flow->group);

    if(it != function13Bto13A.end()) {
        v13A->function = it->second;
    } else {
        std::tr1::unordered_map<unsigned int, unsigned int>::iterator custom_group_Itr = custom_group_system.find(flow->protocol);

        if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 1)) { //speed test
            v13A->function = V13AFunction::speedtest;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 2)) { //weather cdp
            v13A->function = V13AFunction::weather;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 3)) { //maps cdp
            v13A->function = V13AFunction::maps;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 4)) { //news cdp
            v13A->function = V13AFunction::news;
        } else if(flow->protocol ==  IPOQUE_PROTOCOL_USENET) { //Also news cdp  NNTP protocol
            v13A->function = V13AFunction::news;
        } else if(custom_group_Itr != custom_group_system.end())  { //System group
            v13A->function = V13AFunction::system;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 5))  { //advertisement group
            v13A->function = V13AFunction::advertisement;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 6))  { //software_update group
            v13A->function = V13AFunction::software_update;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 7))  { //photo_sharing group
            v13A->function = V13AFunction::photo_sharing;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 8))  { //LLMNR Protocol
            v13A->function = V13AFunction::system;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 9))  { //flurry Protocol
            v13A->function = V13AFunction::advertisement;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 10))  { //andomedia Protocol
            v13A->function = V13AFunction::advertisement;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 11))  { //admob Protocol
            v13A->function = V13AFunction::advertisement;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 12))  { //symantec Protocol
            v13A->function = V13AFunction::software_update;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 13))  { //mcafee Protocol
            v13A->function = V13AFunction::software_update;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 14))  { //teamlava Protocol
            v13A->function = V13AFunction::gaming;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 15))  { //SpeedyShare Protocol is a file sharing  or P2P; but put it in generic as Service Provider want to distinguish it seperately 
            v13A->function = V13AFunction::unknown;
        } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 16))  { //Slacker Protocol
            v13A->function = V13AFunction::media_playback;
        } else {
            v13A->function = V13AFunction::unknown;
        }
    }
}

void Converter::convertTo13AProtocol(Classification13A *v13A, const flow_data *flow) {
    std::tr1::unordered_map<int, V13AProtocol::V13AProtocolEnum>::iterator it = protocol13Bto13A.find(flow->protocol);

    if(it != protocol13Bto13A.end()) {
        v13A->protocol = it->second;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 1)) { //speed test
        v13A->protocol = V13AProtocol::speedtest;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 2)) { //weather cdp
        v13A->protocol = V13AProtocol::weather;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 3)) { //maps cdp
        v13A->protocol = V13AProtocol::maps;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 4)) { //news cdp
        v13A->protocol = V13AProtocol::news;
    } else if(flow->protocol == (IPOQUE_PROTOCOL_USENET)) { //NTTP News cdp
        v13A->protocol = V13AProtocol::NNTP;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 5)) { //advertisement cdp
        v13A->protocol = V13AProtocol::ADS;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 6)) { //Software-update cdp
        v13A->protocol = V13AProtocol::SW;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 7)) { //photo-sharing cdp
        v13A->protocol = V13AProtocol::PHOTO;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 8)) { //LLMNR cdp
        v13A->protocol = V13AProtocol::LLMNR;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 9)) { //flurry cdp
        v13A->protocol = V13AProtocol::flurry;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 10)) { //andomedia cdp
        v13A->protocol = V13AProtocol::andomedia;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 11)) { //admob cdp
        v13A->protocol = V13AProtocol::admob;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 12)) { //symantec cdp
        v13A->protocol = V13AProtocol::symantec;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 13)) { //mcafee cdp
        v13A->protocol = V13AProtocol::mcafee;
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 14)) { //teamlava cdp
        v13A->protocol = V13AProtocol::teamlava;        
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 15)) { //teamlava cdp
        v13A->protocol = V13AProtocol::speedyshare;            
    } else if(flow->protocol == (IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 16)) { //Slacker cdp
        v13A->protocol = V13AProtocol::slacker;        
    } else {
        v13A->protocol = V13AProtocol::unknown;
    }
}

void Converter::convertTo13AEncryption(Classification13A *v13A, const flow_data *flow) {
    using namespace V13AEncry;
    V13AEncrptionEnum encryption;

    switch(flow->protocol) {
        case IPOQUE_PROTOCOL_SSL:
            encryption = SSL;
            break;

        case IPOQUE_PROTOCOL_IPSEC:
            encryption = IPSec_NAT_traversal;
            break;

        default:
            encryption = unknown_encry;
            break;
    }

    v13A->encryption = encryption;
}

void Converter::convertTo13AEncapsulation(Classification13A *v13A, const flow_data *flow) {
    using namespace V13AEncap;
    v13A->encapsulation = unknown_encap;
    unsigned int protocol = flow->protocol;

    if(protocol == IPOQUE_PROTOCOL_HTTP
            || protocol == IPOQUE_PROTOCOL_HTTP_APPLICATION_QQGAME
            || protocol == IPOQUE_PROTOCOL_HTTP_APPLICATION_VEOHTV
            || protocol == IPOQUE_PROTOCOL_HTTP_APPLICATION_GOOGLE_TALK
            || protocol == IPOQUE_PROTOCOL_HTTP_APPLICATION_ACTIVESYNC
            || IPOQUE_PROTOCOL_HTTP_TUNNEL) {
        v13A->encapsulation = V13AEncapsulationEnum::HTTP;
        return;
    }

    if(protocol == IPOQUE_PROTOCOL_IPSEC) {
        v13A->encapsulation = V13AEncapsulationEnum :: IPSec;
        return ;
    }

    if(protocol == IPOQUE_PROTOCOL_BLACKBERRY) {
        v13A->encapsulation = V13AEncapsulationEnum::blackberry;
        return;
    }

    if(protocol == IPOQUE_PROTOCOL_GRE) {
        v13A->encapsulation = V13AEncapsulationEnum::GRE;
        return;
    }
}

void Converter::getPacketLossValueAsString(unsigned int pktLossValue_uint, char *retValue) {
    if(pktLossValue_uint != std::numeric_limits<unsigned int>::max()) {
        float pktLossValue;
        pktLossValue = ((float)pktLossValue_uint) / ((float) PKTLOSS_RATE_RESOLUTION);
        snprintf(retValue, MAX_PKT_LOSS_STRING_LENGTH - 1, "%.6f", pktLossValue);
    } else {
        snprintf(retValue, MAX_PKT_LOSS_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    }
}

void Converter::get13AClassifcationFrom13BFlow(Classification13A *v13A, const flow_data *flow) {
    double tmpTime;
    v13A->ropCounter = flow->ropCounter;
    v13A->firstPacketTime = flow->firstPacketTime;
    //efitleo: Fix for EQEV-1014
    //efitleo: Fix for EQEV-5150: startTime files of captool is rop startTime, was  firstPacketTime
    unsigned int theRopCounter = flow->ropCounter;
    tmpTime = flow->firstPacketTime + (theRopCounter * (60 * kRopDurationInMinutes));

    if(theRopCounter >= 1) {
        roundDownEpoch(&tmpTime, &(v13A->ropStartTime));
        //printf("tmpTime = %.6f, v13A.ropStartTime = %.6f\n",tmpTime,v13A->ropStartTime);
    } else {
        v13A->ropStartTime = tmpTime;
    }

    v13A->lastPacketTime = flow->lastPacketTime;
    v13A->packetsDown = flow->packetsDown;
    v13A->packetsUp = flow->packetsUp;
    v13A->ueIP = flow->fourTuple.ueIP;
    v13A->internetToUeDataBytes = flow->internetToUeDataBytes;
    v13A->ueToInternetDataBytes = flow->ueToInternetDataBytes;
    convertTo13AProtocol(v13A, flow);
    convertTo13AFunction(v13A, flow);
    convertTo13AEncryption(v13A, flow);
    convertTo13AEncapsulation(v13A, flow);
    v13A->client=flow->client;
    v13A->service_provider = flow->service_provider;

    if(loggerCaptoolExtendedOutput->isDebugEnabled()) {
        memcpy(v13A->host, flow->host, MAX_HOST_NAME_SIZE);
        v13A->host[MAX_HOST_NAME_SIZE - 1] = '\0';
        memcpy(v13A->contentType, flow->contentType, MAX_CONTENT_TYPE_SIZE);
        v13A->contentType[MAX_CONTENT_TYPE_SIZE - 1] = '\0';
        memcpy(v13A->uriExtension, flow->uriExtension, MAX_URI_EXTENSION_LENGTH);
        v13A->uriExtension[MAX_URI_EXTENSION_LENGTH - 1] = '\0';
        getApplicationValueAsString(flow->application, v13A->applicationBuf);
        getSubProtocolValueAsString(flow->sub_protocol, flow->sub_protocol_str, v13A->subProtocolBuf);
        memcpy(v13A->ipoqueProtocolString, protocol_short_str[flow->protocol] , MAX_IPOQUE_PROTOCOL_STRING_LENGTH);
        v13A->ipoqueProtocolString[MAX_IPOQUE_PROTOCOL_STRING_LENGTH - 1] = '\0';
        memcpy(v13A->ipoqueGroupString, protocolGroupString[flow->group] , MAX_IPOQUE_GROUP_STRING_LENGTH);
        v13A->ipoqueGroupString[MAX_IPOQUE_GROUP_STRING_LENGTH - 1] = '\0';
    }
}

void fileWriterPrintTP(flow_data *flow) {
    if((loggerThroughput->isDebugEnabled()) || (loggerThroughput->isTraceEnabled())) {
        if(flow->isTcpFlow) {
            unsigned long packetThroughput;
            int bufSize = 2000;
            char buf[10][bufSize];
            double throughputDuration_ue, throughputDuration_inet;
            double pauseTime;
            unsigned long long totalPayloadBytes_ue, totalPayloadBytes_inet;
            throughputDuration_inet = ((double)(flow->tpDuration[PKT_LOSS_HEADING_TO_INTERNET] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_INTERNET]) / (double)PKTLOSS_RESOLUTION);
            throughputDuration_ue = ((double)(flow->tpDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) / (double)PKTLOSS_RESOLUTION);
            const double throughputDuration = ((double)(flow->tpDurationTotal + flow->tpBurstDurationTotal) / (double)PKTLOSS_RESOLUTION) ;
            LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics : \n"
                          << ":tpDurationTotal " << (flow->tpDurationTotal + flow->tpBurstDurationTotal)
                          << ":tpDuration_inet " << (flow->tpDuration[PKT_LOSS_HEADING_TO_INTERNET] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_INTERNET])
                          << ":tpDuration_ue " << (flow->tpDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]));
            calculateUniqueBytesAcknowledged(flow, &totalPayloadBytes_ue, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
            calculateUniqueBytesAcknowledged(flow, &totalPayloadBytes_inet, PKT_LOSS_HEADING_TO_INTERNET);
            LOG4CXX_TRACE(loggerThroughput, "Throughput Metrics : \n"
                          << ":totalPayloadBytes " << (totalPayloadBytes_ue + totalPayloadBytes_inet)
                          << ":totalPayloadBytes_inet " << totalPayloadBytes_inet
                          << ":totalPayloadBytes_ue " << totalPayloadBytes_ue);

            if((flow->tpDurationTotal + flow->tpBurstDurationTotal) > 0) {
                packetThroughput = (unsigned long)((flow->tpTotalBytes * 8 * PKTLOSS_RESOLUTION) / (flow->tpDurationTotal + flow->tpBurstDurationTotal));
            } else {
                packetThroughput = 0;
            }

            pauseTime = (flow->lastPacketTime - flow->firstPacketTime) - throughputDuration;
            snprintf(buf[0], bufSize, "Throughput Metrics fileWriterPrintTP:, ");
            snprintf(buf[1], bufSize, "%u, %u, %u, %u, : %10llu, %10lu, ", flow->fourTuple.ueIP, flow->fourTuple.uePort, flow->fourTuple.serverIP, flow->fourTuple.serverPort, flow->tpTotalBytes, packetThroughput);
            snprintf(buf[2], bufSize, "%10u, %llu ", flow->clientLatency, flow->tpThreshold[PKT_LOSS_HEADING_TO_INTERNET]);
            snprintf(buf[3], bufSize, "%10u, %llu ", flow->serverLatency, flow->tpThreshold[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]);
            snprintf(buf[4], bufSize, "%10f %10f, ", (flow->lastPacketTime - flow->firstPacketTime), pauseTime);
            snprintf(buf[5], bufSize, "%17.6f%s%16.6f%s%14.6f%s%12llu%s%10llu%s%10llu%s%10llu%s%10llu%s%10llu%s%10lu%s%10lu%s%10lu%s\n",
                     throughputDuration,                                                        RECORD_DELIMITER, // 25. flow duration for which TCP payload > 0
                     throughputDuration_inet,                                                   RECORD_DELIMITER, // 26. flow duration for which TCP payload > 0 ue -> inet
                     throughputDuration_ue,                                                     RECORD_DELIMITER, // 27. flow duration for which TCP payload > 0 inet -> ue
                     (totalPayloadBytes_inet + totalPayloadBytes_ue),                           RECORD_DELIMITER,
                     totalPayloadBytes_inet,                                                    RECORD_DELIMITER, // 28. Unique Payload Bytes (excl ReTransmits) ue -> inet
                     totalPayloadBytes_ue,                                                      RECORD_DELIMITER, // 29. Unique Payload Bytes (excl ReTransmits) inet -> ue
                     ((totalPayloadBytes_inet + totalPayloadBytes_ue) * 8),                     RECORD_DELIMITER,
                     (totalPayloadBytes_inet * 8),                                              RECORD_DELIMITER,
                     (totalPayloadBytes_ue * 8),                                                RECORD_DELIMITER,
                     flow->throughput,                                                          RECORD_DELIMITER, // 30. Throughput both directions
                     flow->throughput_heading_to_inet,                                          RECORD_DELIMITER, // 31. Throughput ue -> inet
                     flow->throughput_heading_to_ue,                                            RECORD_DELIMITER); // 32. Throughput inet -> ue
            LOG4CXX_INFO(loggerFileWriter, buf[0] << buf[1] << buf[2] << buf[3] << buf[4] << buf[5]);
            // these print on DEBUG LEVEL to pect.log
            uint64_t pktTime_us = (uint64_t)((double) flow->lastPacketTime * (double) PKTLOSS_RESOLUTION);
            LOG4CXX_DEBUG(loggerThroughput, "Throughput Metrics fileWriterPrintTP: Print METRICS PKT_LOSS_HEADING_TO_INTERNET at ROP END \n");
            printTPMetrics(flow, pktTime_us, 0);
            LOG4CXX_DEBUG(loggerThroughput, "Throughput Metrics fileWriterPrintTP: Print METRICS PKT_LOSS_HEADING_TO_USER_EQUIPMENT at ROP END \n");
            printTPMetrics(flow, pktTime_us, 1);
            LOG4CXX_DEBUG(loggerThroughput, "Throughput Metrics fileWriterPrintTP: Print METRICS PKT_LOSS BOTH DIRECTIONS at ROP END \n");
            printTPMetricsTotal(flow, pktTime_us);
        }
    }
}

/*
 * prints a header to help decifer the information in fileWriterPrintTP
 *
*/
void fileWriterPrintTP_Header() {
    if((loggerThroughput->isDebugEnabled()) || (loggerThroughput->isTraceEnabled())) {
        int bufSize = 2000;
        char buf[10][bufSize];
        // print a header
        snprintf(buf[0], bufSize, "Throughput Metrics fileWriterPrintTP: HEADER \n");
        snprintf(buf[1], bufSize, "Throughput Metrics fileWriterPrintTP: FOR BEST RESULTS Put Threshold to Zero Bytes in properties.xml and Use PCAP with only one Flow (unique four Tuple) \n");
        snprintf(buf[2], bufSize, "Throughput Metrics fileWriterPrintTP:, ");
        snprintf(buf[3], bufSize, "UEip, uePort, serverIP, serverPort, TOTAL Bytes, Packet Throughput, ");
        snprintf(buf[4], bufSize, "clientLatency,  tpThreshold, serverLatency, tpThreshold, ");
        snprintf(buf[5], bufSize, "Total_FLOW_time,  PAUSE Time, ");
        snprintf(buf[6], bufSize, "TPutDuration_TOTAL, TPutDuration_INET, TPutDuration_UE, TCPPayload, TCPPayloadInet, TCPPayloadUe, TCPPayload[bits], TCPPayloadInet[bits], TCPPayloadUe[bits], Throughput, ThroughputInet, ThroughputUe,\n");
        LOG4CXX_INFO(loggerFileWriter, buf[0] << buf[1] << buf[2] << buf[3] << buf[4] << buf[5] << buf[6]);
    }
}

void Converter::get13AThroughputFrom13BFlow(Throughput13A *v13A, flow_data *flow) {
    double tmpTime;
    unsigned long long totalPayloadBytes;
    calculateFlowDataFields(flow);//calculate throughput of the flow
    v13A->ropCounter = flow->ropCounter;
    v13A->firstPacketTime = flow->firstPacketTime;
    //efitleo: Fix for EQEV-5150: startTime files of staple is rop startTime, was  firstPacketTime
    unsigned int theRopCounter = flow->ropCounter;
    tmpTime = flow->firstPacketTime + (theRopCounter * (60 * kRopDurationInMinutes));

    if(theRopCounter >= 1) {
        roundDownEpoch(&tmpTime, &(v13A->ropStartTime));
        //printf("tmpTime = %.6f, v13A.ropStartTime = %.6f\n",tmpTime,v13A->ropStartTime);
    } else {
        v13A->ropStartTime = tmpTime;
    }

    v13A->isTcpFlow = flow->isTcpFlow;
    v13A->throughput = flow->throughput; // EQEV-6445  Fixed so that its Unique TCP Bytes/ dureation payload > 0; cumulative
    v13A->sessionThroughput = flow->sessionThroughput;
    //  EQEV-6445  dataReceived = Unique TCP Bytes, no ReTransmits, Ack Bytes
    calculateTotalUniqueBytesAcknowledged(flow, &totalPayloadBytes);
    v13A->dataReceived = totalPayloadBytes;
    v13A->direction = flow->getDirection();
    v13A->duration = ((double)(flow->tpDurationTotal + flow->tpBurstDurationTotal) / (double)PKTLOSS_RESOLUTION) ; // EQEV-6445  duration TCP payload > 0; cumulative
    v13A->maxPacketLength = flow->maxPacketLength;
    v13A->ueIP = flow->fourTuple.ueIP;
    v13A->uePort = flow->fourTuple.uePort;
    v13A->serverIP = flow->fourTuple.serverIP;
    v13A->serverPort = flow->fourTuple.serverPort;
    v13A->receiverWindowSize = (v13A->direction == 0 ? flow->serverMaxReceiverWindowSize : flow->ueMaxReceiverWindowSize);
    memcpy(v13A->contentType, flow->contentType, MAX_CONTENT_TYPE_SIZE);
    v13A->contentType[MAX_CONTENT_TYPE_SIZE - 1] = '\0';
    memcpy(v13A->host, flow->host, MAX_HOST_NAME_SIZE);
    v13A->host[MAX_HOST_NAME_SIZE - 1] = '\0';
    memcpy(v13A->uriExtension, flow->uriExtension, MAX_URI_EXTENSION_LENGTH);
    v13A->uriExtension[MAX_URI_EXTENSION_LENGTH - 1] = '\0';
    printMicroSecondsIfNotMaxVal(flow->clientLatency, v13A->clientLatencyBuf, MAX_RTT_STRING_LENGTH);
    printMicroSecondsIfNotMaxVal(flow->serverLatency, v13A->serverLatencyBuf, MAX_RTT_STRING_LENGTH);
    getPacketLossValueAsString(flow->internetToUeLossRate, v13A->pktLoss_internetToUeLossRate);
    getPacketLossValueAsString(flow->ueToInternetLossRate, v13A->pktLoss_ueToInternetLossRate);

    // Do the print here so that the TOTAL TP and DURATION fields are relevant for 13A output
    if((loggerThroughput->isDebugEnabled()) || (loggerThroughput->isTraceEnabled())) {
        fileWriterPrintTP(flow);
        printPktLossRateInfo(flow);
    }

    // Do the print here so that the TOTAL TP and DURATION fields are relevant for 13A output
    if((loggerPacketLoss->isDebugEnabled()) || (loggerPacketLoss->isTraceEnabled())) {
        printPktLossRateInfo(flow);
    }
}


int checkROPTime(const flow_data *flow){
		unsigned int theROPCounter = flow->ropCounter;
        double tmpTime = flow->firstPacketTime + (theROPCounter * (60 * kRopDurationInMinutes));
        double tmpROPStartTime;
        if(theROPCounter >= 1) {
            roundDownEpoch(&tmpTime, &tmpROPStartTime);
            //printf("tmpTime = %.6f, v13A.ropStartTime = %.6f\n",tmpTime,v13A->ropStartTime);
        } else {
        	tmpROPStartTime = tmpTime;
        }
        if (tmpROPStartTime > flow->lastPacketTime)
        	    	return 1;
        else
        	    	return 0;
}



