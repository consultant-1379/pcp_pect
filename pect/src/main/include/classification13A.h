/*
 * classification13A.hpp
 *
 *  Created on: 20 May 2013
 *      Author: ezhelao
 */

#ifndef CLASSIFICATION13A_HPP_
#define CLASSIFICATION13A_HPP_

#include "pcp13A_encry_encap.h"
#include "pcp13A_function.h"
#include "pcp13A_protocol.h"
#include "service_provider_init.hpp"
#include "pcp_limits.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string>

#define DELIMITER13A_CAPTOOL "|"

using namespace std;
extern const char* CLIENT_STR[];
extern const unsigned int MAX_SUPPORTED_CLIENTS;

struct Classification13A {
    unsigned int ropCounter;

    //id not used
    double firstPacketTime; // ID
    double ropStartTime;  // period start
    double lastPacketTime;  // period end

    u_int32_t ueIP;
    unsigned long long packetsDown;
    unsigned long long packetsUp;
    unsigned long long internetToUeDataBytes; // bytes_downlink
    unsigned long long ueToInternetDataBytes; // bytes_uplink
    V13AProtocol::V13AProtocolEnum protocol;
    V13AFunction::V13AFunctionEnum function;
    V13AEncap::V13AEncapsulationEnum encapsulation;
    V13AEncry::V13AEncrptionEnum encryption;
    //char client[MAX_CLIENT_TYPE_SIZE];
    unsigned int client;
    struct in_addr ueIPIn;
    char ueIPBuf[40];
    char contentType[MAX_CONTENT_TYPE_SIZE];
    char host[MAX_HOST_NAME_SIZE];
    char uriExtension[MAX_URI_EXTENSION_LENGTH];
    char applicationBuf[MAX_APPLICATION_STRING_LENGTH];
    char subProtocolBuf[MAX_SUB_PROTOCOL_STRING_LENGTH];
    char ipoqueGroupString[MAX_IPOQUE_GROUP_STRING_LENGTH];
    char ipoqueProtocolString[MAX_IPOQUE_PROTOCOL_STRING_LENGTH];
	unsigned int service_provider;

    void getAsString(char stringOutput[], unsigned int bufSize, const string &gtpcMiddleCaptoolStr) {
        ueIPIn.s_addr = htonl((ueIP));
        inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
        snprintf(stringOutput, bufSize,
                 "%.6f" DELIMITER13A_CAPTOOL //  1. ID
                 "%.6f" DELIMITER13A_CAPTOOL //  2. beginning timestamp
                 "%.6f" DELIMITER13A_CAPTOOL //  3. end timestamp
                 "%s"   DELIMITER13A_CAPTOOL //  4 5 6 7 8 9 10 11
                 "%s"   DELIMITER13A_CAPTOOL // 12. IPV4 string for ue
                 "%llu" DELIMITER13A_CAPTOOL // 13. packet downlink
                 "%llu" DELIMITER13A_CAPTOOL // 14. packet uplink
                 "%llu" DELIMITER13A_CAPTOOL // 15. bytes_downlink
                 "%llu" DELIMITER13A_CAPTOOL // 16. bytes uplink
                 "%s"   DELIMITER13A_CAPTOOL // 17. protocol
                 "%s"   DELIMITER13A_CAPTOOL // 18. function
                 "%s"   DELIMITER13A_CAPTOOL // 19. encapsulation
                 "%s"   DELIMITER13A_CAPTOOL // 20. encryption
                 "%s"   DELIMITER13A_CAPTOOL // 21. service provider
                 "%s"   DELIMITER13A_CAPTOOL // 22. client
                 ,
                 firstPacketTime,        //(int)firstPacketTime,  //  1
                 ropStartTime,          //  2   //efitleo: Fix for EQEV-5150: startTime files of captool is rop startTime, was  firstPacketTime
                 lastPacketTime,        //  3
                 gtpcMiddleCaptoolStr.c_str(), // 4 5 6 7 8 9 10 11
                 ueIPBuf,               // 12
                 packetsDown,           // 13
                 packetsUp,             // 14
                 internetToUeDataBytes, // 15
                 ueToInternetDataBytes, // 16
                 V13AProtocol::V13A_PROTOCOL_STR[protocol],        // 17
                 V13AFunction::V13A_FUNCTION_STR[function],        // 18
                 V13AEncap::V13A_ENCAPSULATION_STR[encapsulation], // 19
                 V13AEncry::V13A_ENCRYPTION_STR[encryption],       // 20
                 service_provider_info::SERVICE_PROVIDER_STR[service_provider], // 21
                 CLIENT_STR[client] //client // 22
                );
    }

    void getAsDebugString(char stringOutput[], unsigned int bufSize, const string &gtpcMiddleCaptoolStr) {
        ueIPIn.s_addr = htonl((ueIP));
        inet_ntop(AF_INET, &ueIPIn, ueIPBuf, 40);
        snprintf(stringOutput, bufSize,
                 "%.6f" DELIMITER13A_CAPTOOL //  1. ID
                 "%.6f" DELIMITER13A_CAPTOOL //  2. beginning timestamp
                 "%.6f" DELIMITER13A_CAPTOOL //  3. end timestamp
                 "%s"   DELIMITER13A_CAPTOOL //  4 5 6 7 8 9 10 11
                 "%s"   DELIMITER13A_CAPTOOL // 12. IPV4 string for ue
                 "%llu" DELIMITER13A_CAPTOOL // 13. packet downlink
                 "%llu" DELIMITER13A_CAPTOOL // 14. packet uplink
                 "%llu" DELIMITER13A_CAPTOOL // 15. bytes_downlink
                 "%llu" DELIMITER13A_CAPTOOL // 16. bytes uplink
                 "%s"   DELIMITER13A_CAPTOOL // 17. protocol
                 "%s"   DELIMITER13A_CAPTOOL // 18. function
                 "%s"   DELIMITER13A_CAPTOOL // 19. encapsulation
                 "%s"   DELIMITER13A_CAPTOOL // 20. encryption
                 "%s"   DELIMITER13A_CAPTOOL // 21. service provider
                 "%s"   DELIMITER13A_CAPTOOL // 22. client
                 "%s"   DELIMITER13A_CAPTOOL // 23. host
                 "%s"   DELIMITER13A_CAPTOOL // 24. contentType
                 "%s"   DELIMITER13A_CAPTOOL // 25. uriExtension
                 "%s"   DELIMITER13A_CAPTOOL // 26. applicationBuf
                 "%s"   DELIMITER13A_CAPTOOL // 27. ipoqueProtocolString
                 "%s"   DELIMITER13A_CAPTOOL // 28. subProtocolBuf
                 "%s"   DELIMITER13A_CAPTOOL // 29. ipoqueGroupString
                 ,
                 firstPacketTime,        //(int)firstPacketTime,  //  1
                 ropStartTime,          //  2   //efitleo: Fix for EQEV-5150: startTime files of captool is rop startTime, was  firstPacketTime
                 lastPacketTime,        //  3
                 gtpcMiddleCaptoolStr.c_str(), // 4 5 6 7 8 9 10 11
                 ueIPBuf,               // 12
                 packetsDown,           // 13
                 packetsUp,             // 14
                 internetToUeDataBytes, // 15
                 ueToInternetDataBytes, // 16
                 V13AProtocol::V13A_PROTOCOL_STR[protocol],        // 17
                 V13AFunction::V13A_FUNCTION_STR[function],        // 18
                 V13AEncap::V13A_ENCAPSULATION_STR[encapsulation], // 19
                 V13AEncry::V13A_ENCRYPTION_STR[encryption],       // 20
                 service_provider_info::SERVICE_PROVIDER_STR[service_provider], // 21
                 CLIENT_STR[client],  //client, // 22
                 host, // 23
                 contentType, //24
                 uriExtension, //25
                 applicationBuf, //26
                 ipoqueProtocolString, //27
                 subProtocolBuf, //28
                 ipoqueGroupString //29
                );
    }
};

#endif /* CLASSIFICATION13A_HPP_ */
