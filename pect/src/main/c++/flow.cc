/*
 * flow.cc
 *
 *  Created on: 7 Mar 2013
 *      Author: emilawl
 */

#include "flow.h"
#include "ipq_api.h"
#include "service_provider_init.hpp"

#include <stdlib.h>
#include <arpa/inet.h>
#include <iomanip>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/socket.h>

// Doesn't seem to be an IPOQUE string list for this so created one below.
// We could set these to be as per the database I guess(below), but I left them as is for now, alternatively we can send out the int and get application x to map to string.
#define IPOQUE_GROUP_STRINGS "generic", "standard", "p2p", "gaming", "tunnel", "business", "voip", \
                             "im", "streaming", "mobile", "remote_control", "video", "audio", \
                             "mail", "network_management", "database", "filetransfer", "web", "conference", "social-networking","MAX_IPOQUE_NUMBER_OF_GROUPS",\
                             "speedtest", "weather","maps","news","system","advertisement", "software-update", "photo-sharing"
#define DATABASE_STRINGS "\\N", "\\N", "file-sharing", "gaming", "\\N", "\\N", "VoIP", \
                         "instant-messaging", "media-playback", "MMS", "remote-access", "video-playback", "audio-playback", \
                         "email", "\\N", "\\N", "file-download", "web-browsing", "\\N"


using std::hex;
using std::setw;

const char *protocol_short_str[] = {IPOQUE_PROTOCOL_SHORT_STRING_CDP};
const char *protocolGroupString[] = {IPOQUE_GROUP_STRINGS};
static const char *DIRECTION_STR[] = {EMPTY_INT_STRING, "0", "1"};
static const char *application_str[] = { IPOQUE_APPLICATION_SHORT_STRING };

extern unsigned int MAX_SUPPORTED_PROTOCOLS;
extern unsigned int MAX_SUPPORTED_GROUPS;


ostream &operator<<(ostream &os, const flow_data *flow) {
    //  ID, First time, Last Time, Bytes, Packets down, Packets Up , protocol_short_str[flow->protocol], UE_IP << endl;
    char buf[MAX_GTPU_FLOW_LENGTH];
    printFlowToString(flow, buf, MAX_GTPU_FLOW_LENGTH);
    os << buf;
    return os;
}


void printMicroSecondsIfNotMaxVal(unsigned int value, char *destination, int maxLength) {
    if(value == UINT_MAX) {
        snprintf(destination, maxLength, "%s", EMPTY_INT_STRING);
    } else {
        float fval = ((float)value / 1000000);
        snprintf(destination, maxLength, "%0.6f", fval);
    }
}

void getPacketLossValueAsString(unsigned int pktLossValue_uint, char *retValue) {
    if(pktLossValue_uint != std::numeric_limits<unsigned int>::max()) {
        float pktLossValue;
        pktLossValue = ((float)pktLossValue_uint) / ((float) PKTLOSS_RATE_RESOLUTION);
        snprintf(retValue, MAX_PKT_LOSS_STRING_LENGTH - 1, "%.6f", pktLossValue);
    } else {
        snprintf(retValue, MAX_PKT_LOSS_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    }
}

/*
 *
 * The sub protocols string is already in flow_data-sub_protocol_str and put there by getSubProtocolString in classify
*/
void getSubProtocolValueAsString(unsigned int theSubProtocol, const char *subProtocolStr, char *retValue) {
    if((theSubProtocol == UINT_MAX) || (theSubProtocol > IPOQUE_MAX_SUPPORTED_SUB_PROTOCOLS)) {
        snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    } else {
        if(subProtocolStr != NULL)  {
            snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%s", subProtocolStr);
            retValue[MAX_SUB_PROTOCOL_STRING_LENGTH - 1] = '\0';
        } else {
            snprintf(retValue, MAX_SUB_PROTOCOL_STRING_LENGTH - 1, "%u", theSubProtocol);
        }
    }
}

void getApplicationValueAsString(unsigned int application, char *retValue)  {
    if((application == UINT_MAX) || (application > IPOQUE_NUMBER_OF_APPLICATIONS) || (application < 2)) {
        snprintf(retValue, MAX_APPLICATION_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    } else {
        snprintf(retValue, MAX_APPLICATION_STRING_LENGTH - 1, "%s", application_str[application]);
    }
}

void getProtocolValueAsString(unsigned int protocol, char *retValue)  {
    if((protocol == UINT_MAX) || (protocol > MAX_SUPPORTED_PROTOCOLS)) {
        snprintf(retValue, MAX_IPOQUE_PROTOCOL_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    } else {
        snprintf(retValue, MAX_IPOQUE_PROTOCOL_STRING_LENGTH - 1, "%s", protocol_short_str[protocol]);
    }
}

void getProtocolGroupValueAsString(unsigned int protocolGroup, char *retValue)  {
    if((protocolGroup == UINT_MAX) || (protocolGroup > MAX_SUPPORTED_GROUPS)) {
        snprintf(retValue, MAX_IPOQUE_GROUP_STRING_LENGTH - 1, "%s", EMPTY_INT_STRING);
    } else {
        snprintf(retValue, MAX_IPOQUE_GROUP_STRING_LENGTH - 1, "%s", protocolGroupString[protocolGroup]);
    }
}

void printFlowToString(const flow_data *flow, char *gtpu_data, int bufferLength) {
    //  ID, First time, Last Time, Bytes, Packets down, Packets Up , Protocol , UE_IP << endl;
    struct in_addr ueIPIn;
    struct in_addr serverIPIn;
    ueIPIn.s_addr = htonl((flow->fourTuple.ueIP));
    serverIPIn.s_addr = htonl((flow->fourTuple.serverIP));
    char ueIPBuf[40];
    char serverIPBuf[40];
    inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
    inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
    int direction = flow->getDirection();
    char clientLatencyBuf[MAX_RTT_STRING_LENGTH];
    char serverLatencyBuf[MAX_RTT_STRING_LENGTH];
    printMicroSecondsIfNotMaxVal(flow->clientLatency, clientLatencyBuf, MAX_RTT_STRING_LENGTH);
    printMicroSecondsIfNotMaxVal(flow->serverLatency, serverLatencyBuf, MAX_RTT_STRING_LENGTH);
    // Packet Loss is either a Value or  backslash N as Zero could be a realistic value
    char pktLoss_internetToUeLossRate[MAX_PKT_LOSS_STRING_LENGTH];
    char pktLoss_ueToInternetLossRate[MAX_PKT_LOSS_STRING_LENGTH];
    getPacketLossValueAsString(flow->internetToUeLossRate, pktLoss_internetToUeLossRate);
    getPacketLossValueAsString(flow->ueToInternetLossRate, pktLoss_ueToInternetLossRate);
    double throughputDuration_ue, throughputDuration_inet, throughputDuration;
    throughputDuration_inet = ((double)(flow->tpDuration[PKT_LOSS_HEADING_TO_INTERNET] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_INTERNET]) / (double)PKTLOSS_RESOLUTION);
    throughputDuration_ue = ((double)(flow->tpDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT] + flow->tpBurstDuration[PKT_LOSS_HEADING_TO_USER_EQUIPMENT]) / (double)PKTLOSS_RESOLUTION);
    throughputDuration = ((double)(flow->tpDurationTotal + flow->tpBurstDurationTotal) / (double)PKTLOSS_RESOLUTION) ;
    unsigned long long totalPayloadBytes_ue, totalPayloadBytes_inet;
    calculateUniqueBytesAcknowledged(flow, &totalPayloadBytes_ue, PKT_LOSS_HEADING_TO_USER_EQUIPMENT);
    calculateUniqueBytesAcknowledged(flow, &totalPayloadBytes_inet, PKT_LOSS_HEADING_TO_INTERNET);
    char applicationBuf[MAX_APPLICATION_STRING_LENGTH];
    getApplicationValueAsString(flow->application, applicationBuf);
    char sub_protocol_strBuf[MAX_SUB_PROTOCOL_STRING_LENGTH];
    getSubProtocolValueAsString(flow->sub_protocol, flow->sub_protocol_str, sub_protocol_strBuf);
    snprintf(gtpu_data, bufferLength,
             // 1     2     3    4   5    6   7     8    9   10    11    12    13    14  15  16  17  18  19  20  21   22    23    24  25    26    27     28   29    30    31   32   33   34  35  36   37  38  39  40  41
             "%.6f%s%.6f%s%.6f%s%s%s%hu%s%s%s%hu%s%.6f%s%u%s%llu%s%llu%s%llu%s%llu%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%ld%s%llu%s%llu%s%lu%s%.6f%s%.6f%s%.6f%s%llu%s%llu%s%llu%s%lu%s%lu%s%lu%s%s%s%s%s%hu%s%s%s%s%s%s%s%s%s%s",
             // May need to use precision to control the number of decimal places
             flow->firstPacketTime,                                                     RECORD_DELIMITER, //  1. ID of the flow.
             flow->firstPacketTime,                                                     RECORD_DELIMITER, //  2. First Packet Time
             flow->lastPacketTime,                                                      RECORD_DELIMITER, //  3. Last Packet Time
             ueIPBuf,                                                                   RECORD_DELIMITER, //  4. UE IP
             flow->fourTuple.uePort,                                                    RECORD_DELIMITER, //  5. UE Port
             serverIPBuf,                                                               RECORD_DELIMITER, //  6. Server IP
             flow->fourTuple.serverPort,                                                RECORD_DELIMITER, //  7. Server port
             flow->durationThisRop,                                                     RECORD_DELIMITER, //  8. Duration this ROP
             flow->ropCounter,                                                          RECORD_DELIMITER, //  9. ROP Counter
             flow->bytes,                                                               RECORD_DELIMITER, // 10. Bytes
             flow->maxPacketLength,                                                     RECORD_DELIMITER, // 11. Max Packet Length
             flow->packetsDown,                                                         RECORD_DELIMITER, // 12. Packets Down
             flow->packetsUp,                                                           RECORD_DELIMITER, // 13. Packets Up
             protocol_short_str[flow->protocol],                                        RECORD_DELIMITER, // 14. Protocol
             flow->host,                                                                RECORD_DELIMITER, // 15. Host Name
             flow->contentType,                                                         RECORD_DELIMITER, // 16. Content Type
             flow->uriExtension,                                                        RECORD_DELIMITER, // 17. URI Extension
             DIRECTION_STR[direction + 1],                                              RECORD_DELIMITER, // 18. traffic direction
             protocolGroupString[flow->group],                                          RECORD_DELIMITER, // 19. protocol group
             CLIENT_STR[flow->client],                                                  RECORD_DELIMITER, // 20. client
             flow->dataReceived,                                                        RECORD_DELIMITER, // 21. data received
             flow->ueToInternetDataBytes,                                               RECORD_DELIMITER, // 22. bytes uplink
             flow->internetToUeDataBytes,                                               RECORD_DELIMITER, // 23. bytes downlink
             flow->sessionThroughput,                                                   RECORD_DELIMITER, // 24. session throughput
             throughputDuration,                                                        RECORD_DELIMITER, // 25. flow duration for which TCP payload > 0
             throughputDuration_inet,                                                   RECORD_DELIMITER, // 26. flow duration for which TCP payload > 0 ue -> inet
             throughputDuration_ue,                                                     RECORD_DELIMITER, // 27. flow duration for which TCP payload > 0 inet -> ue
             (totalPayloadBytes_inet + totalPayloadBytes_ue),                           RECORD_DELIMITER, // 28. Unique Payload Bytes (excl ReTransmits) TOTAL
             totalPayloadBytes_inet,                                                    RECORD_DELIMITER, // 29. Unique Payload Bytes (excl ReTransmits) ue -> inet
             totalPayloadBytes_ue,                                                      RECORD_DELIMITER, // 30. Unique Payload Bytes (excl ReTransmits) inet -> ue
             flow->throughput,                                                          RECORD_DELIMITER, // 31. Throughput both directions
             flow->throughput_heading_to_inet,                                          RECORD_DELIMITER, // 32. Throughput ue -> inet
             flow->throughput_heading_to_ue,                                            RECORD_DELIMITER, // 33. Throughput inet -> ue
             clientLatencyBuf,                                                          RECORD_DELIMITER, // 34. Client side latency
             serverLatencyBuf,                                                          RECORD_DELIMITER, // 35. Server side latency - Doesn't require a delimiter, as it's at the end.
             (direction == 0 ? flow->serverMaxReceiverWindowSize : flow->ueMaxReceiverWindowSize), RECORD_DELIMITER,   // 36. max rwin  if no indication of direction(-1) ,max rwin = client's rwin.Doesn't require a delimiter, as it's at the end.
             pktLoss_internetToUeLossRate,                                              RECORD_DELIMITER, // 37. TCP Packet loss for packet HEADING TO UE
             pktLoss_ueToInternetLossRate,                                              RECORD_DELIMITER, // 38: TCP Packet loss for packet HEADING TO INTERNET
             applicationBuf,                                                            RECORD_DELIMITER, // 39. flow application
             service_provider_info::SERVICE_PROVIDER_STR[flow->service_provider],		RECORD_DELIMITER, // 40. Service Provider
             sub_protocol_strBuf);                                                                        // 41. Sub-Protocol just print the ID number for now- Doesn't require a delimiter, as it's at the end.
}

void printHeaderFlowToString(char *gtpu_header) {
    snprintf(gtpu_header, MAX_GTPU_FLOW_LENGTH + 1,
             //1  2                3               4     5       6         7           8                9           10     11               12           13         14        15        16           17             18        19        20      21            22           23             24                 25                  26                 27                28               29              30            31          32              33            34             35             36                 37                      38                      39           40                41 
             "ID%sfirstPacketTime%slastPacketTime%sueIp%suePort%sserverIp%sserverPort%sdurationThisRop%sropCounter%sbytes%smaxPacketLength%spacketsDown%spacketsUp%sprotocol%shostName%scontentType%suriExtension%sdirection%sfunction%sclient%sdataReceived%sbytesUplink%sbytesDownlink%ssessionThroughput%sTPutDuration_TOTAL%sTPutDuration_INET%sTPutDuration_UE%sTCPPayload_TOTAL%sTCPPayloadInet%sTCPPayloadUe%sThroughput%sThroughputInet%sThroughputUe%sclientLatency%sserverLatency%smaxReceiverWindow%sPacketLossInternetToUe%sPacketLossUeToInternet%sapplication%sservice_provider%sprotocol_subtype\n",
             RECORD_DELIMITER,  //  1. ID of the Flow
             RECORD_DELIMITER,  //  2. First Packet Time
             RECORD_DELIMITER,  //  3. Last Packet Time
             RECORD_DELIMITER,  //  4. UE IP
             RECORD_DELIMITER,  //  5. UE Port
             RECORD_DELIMITER,  //  6. Server IP
             RECORD_DELIMITER,  //  7. Server Port
             RECORD_DELIMITER,  //  8. Duration this ROP
             RECORD_DELIMITER,  //  9. ROP Counter
             RECORD_DELIMITER,  // 10. Bytes
             RECORD_DELIMITER,  // 11. Max Packet Length
             RECORD_DELIMITER,  // 12. Packets Down
             RECORD_DELIMITER,  // 13. Packets Up
             RECORD_DELIMITER,  // 14. Protocol
             RECORD_DELIMITER,  // 15. Host Name
             RECORD_DELIMITER,  // 16. Content Type
             RECORD_DELIMITER,  // 17. URI Extension
             RECORD_DELIMITER,  // 18. direction
             RECORD_DELIMITER,  // 19. Function
             RECORD_DELIMITER,  // 20. client
             RECORD_DELIMITER,  // 21. data received
             RECORD_DELIMITER,  // 22. bytes uplink
             RECORD_DELIMITER,  // 23  bytes downlink
             RECORD_DELIMITER,  // 24. session throughput
             RECORD_DELIMITER,  // 25. flow duration for which TCP payload > 0 TOTAL
             RECORD_DELIMITER,  // 26. flow duration for which TCP payload > 0 ue -> inet
             RECORD_DELIMITER,  // 27. flow duration for which TCP payload > 0 inet -> ue
             RECORD_DELIMITER,  // 28. Unique Payload Bytes (excl ReTransmits)Total
             RECORD_DELIMITER,  // 29. Unique Payload Bytes (excl ReTransmits)ue -> ine
             RECORD_DELIMITER,  // 30. Unique Payload Bytes (excl ReTransmits)inet -> ue
             RECORD_DELIMITER,  // 31. Throughput both directions
             RECORD_DELIMITER,  // 32. Throughput ue -> inet
             RECORD_DELIMITER,  // 33. Throughput inet -> ue
             RECORD_DELIMITER,  // 34  clientLatency
             RECORD_DELIMITER,  // 35. serverLatency
             RECORD_DELIMITER,  // 36. max receiver window - Doesn't require a delimiter, delimiters are applied after a header string.
             RECORD_DELIMITER,  // 37. TCP Packet loss for packet HEADING TO UE
             RECORD_DELIMITER,  // 38: TCP Packet loss for packet HEADING TO INTERNET - Doesn't require a delimiter, as it's at the end.
             RECORD_DELIMITER,   // 39 application
             RECORD_DELIMITER   // 40: Service Provider
            ); // 41. Protocol sub type ID
}

void getRopCounter(const flow_data *flow, unsigned int *ropCtr) {
    *ropCtr = flow->ropCounter;
}


