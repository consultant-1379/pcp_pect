/*
 * Throughput13A.hpp
 *
 *  Created on: 17 May 2013
 *      Author: ezhelao
 */

#ifndef THROUGHPUT13A_HPP_
#define THROUGHPUT13A_HPP_

#include "flow.h"
#include "pcp_limits.h"

#include <arpa/inet.h>
#include <iomanip>
#include <netinet/in.h>
#include <stdio.h>

#define DELIMITER13A "\t"

static const char *DIRECTION_STR[] = {EMPTY_INT_STRING, "0", "1"};

struct Throughput13A {
    double firstPacketTime;// time of first packet time
    double ropStartTime; // start time
    double duration;
    u_int32_t ueIP;
    u_int32_t serverIP;
    u_int16_t uePort;
    u_int16_t serverPort;
    int direction;
    unsigned long dataReceived;
    unsigned long throughput;
    unsigned long sessionThroughput;
    // session throughput without slowstart
    // channel rate
    // alone ration
    unsigned short receiverWindowSize; // receiver windows belongs to ue. default is zero
    char clientLatencyBuf[MAX_RTT_STRING_LENGTH];
    char serverLatencyBuf[MAX_RTT_STRING_LENGTH];
    unsigned long long maxPacketLength;
    // packet loss ratio terminal side
    // packet loss ratio network side
    char contentType[MAX_CONTENT_TYPE_SIZE];
    char host[MAX_HOST_NAME_SIZE];
    char uriExtension[MAX_URI_EXTENSION_LENGTH];

    struct in_addr ueIPIn;
    struct in_addr serverIPIn;
    char ueIPBuf[40];
    char serverIPBuf[40];

    char pktLoss_internetToUeLossRate[MAX_PKT_LOSS_STRING_LENGTH];
    char pktLoss_ueToInternetLossRate[MAX_PKT_LOSS_STRING_LENGTH];


    unsigned int ropCounter;
    bool isTcpFlow;

    void getAsString(char stringOutput[], unsigned int bufSize) {
        ueIPIn.s_addr = htonl((ueIP));
        serverIPIn.s_addr = htonl(serverIP);
        inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
        inet_ntop(AF_INET, &serverIPIn, serverIPBuf, 40);
        snprintf(stringOutput, bufSize,
                 "%.6f" DELIMITER13A //  1. start time
                 "%.6f" DELIMITER13A //  2. duration
                 "%s"   DELIMITER13A //  3. source ip
                 "%hu"  DELIMITER13A //  4. source port
                 "%s"   DELIMITER13A //  5. des ip
                 "%hu"  DELIMITER13A //  6. des port
                 "%s"   DELIMITER13A //  7. direction         //TODO default direction
                 "%lu"  DELIMITER13A //  8. data received
                 "%lu"  DELIMITER13A //  9. throughput
                 "%lu"  DELIMITER13A // 10. session throughput
                 "\\N"  DELIMITER13A // 11. session throughput without slow start
                 "\\N"  DELIMITER13A // 12. channel rate
                 "\\N"  DELIMITER13A // 13. alone ratio
                 "%hu"  DELIMITER13A // 14. max reciever window
                 "%s"   DELIMITER13A // 15. initial rtt terminal side
                 "%s"   DELIMITER13A // 16. initial rtt network side
                 "%llu" DELIMITER13A // 17. max packet size
                 "%s"   DELIMITER13A // 18. packet loss (UE) terminal to network (Internet)
                 "%s"   DELIMITER13A // 19. packet loss (Internet) network to terminal (UE)
                 "%s"   DELIMITER13A // 20. content type
                 "%s"   DELIMITER13A // 21. host name
                 "%s"   DELIMITER13A // 22. uri extionsion
                 ,
                 ropStartTime,    // 1   //efitleo: Fix for EQEV-5150: startTime files of staple is ropStartTime, was  firstPacketTime
                 duration,        // 2
                 ueIPBuf,         // 3
                 uePort,          // 4
                 serverIPBuf,     // 5
                 serverPort,      // 6
                 DIRECTION_STR[direction + 1], // 7
                 dataReceived,    // 8
                 throughput,      // 9
                 sessionThroughput, // 10
                 // 11
                 // 12
                 // 13
                 receiverWindowSize, // 14
                 clientLatencyBuf,   // 15
                 serverLatencyBuf,   // 16
                 maxPacketLength,    // 17
                 pktLoss_ueToInternetLossRate, // 18
                 pktLoss_internetToUeLossRate,// 19
                 contentType, // 20
                 host,        // 21
                 uriExtension // 22
                );
    }
};

#endif /* THROUGHPUT13A_HPP_ */
