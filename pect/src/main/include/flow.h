/*
 * flow.h
 *
 *  Created on: 7 Mar 2013
 *      Author: emilawl
 */

#ifndef FLOW_H_
#define FLOW_H_

// System includes
#include <algorithm>
#include <climits>
#include <functional>
#include <iostream>
#include <list>
#include <string>
#include <sstream>
#include <boost/tr1/unordered_map.hpp>
#include <limits>

// Local includes
#include "GTPv1_packetFields.h"
#include "ipq_api.h"
#include "map_utils.hpp"
#include "mutex.hpp"
#include "packetbuffer.h"
#include "pcp_limits.h"
#include "packetloss3.h"
#include "pcp_check.hpp"



#define IPOQUE_PROTOCOL_SHORT_STRING_CDP "ukn","bit","edk","kazaa","gnu","winmx","directconnect","apple","soul",\
"ares","freenet","mute","xdcc","skype","sip","msn","yahoo","oscar","irc","jabber","orb","sling","vcast","http",\
"ddl","pop","smtp","imap","usenet","ftp","dns","rtsp","filetopia","manolito","imesh","ssl","flash","mms","mpeg",\
"quicktime","pando","openvpn","ipsec","gre","notdetect","h323","windowsmedia","realmedia","tvants","sopcast",\
"tvuplayer","ppstream","pplive","iax","vtun","mgcp","gadugadu","zattoo","winny","qq","qqlive","feidian","ssh",\
"popo","thunder","uusee","vnc","icmp","dhcp","igmp","egp","steam","hl2","xbox","softether","sctp","smb","telnet",\
"ntp","nfs","off","rtp","tor","ssdp","worldofwarcraft","avi","vpnx","hamachi","skinny","citrix","ogg","paltalk",\
"move","postgres","ospf","bgp","quake","secondlife","mysql","battlefield","pcanywhere","rdp","snmp","kontiki",\
"icecast","shoutcast","httpqqgame","httpveohtv","kerberos","openft","ipip","gtp","radius","pandora","stun","syslog","tds",\
"netbios","mdns","ipp","ldap","warcraft3","xdmcp","oovoo","httpgoogletalk","iskoot","fring","mapi","genvoice","l2tp","isakmp",\
"rtcp","iptv","tftp","mssql","ppp","pptp","stealthnet","sap","icmpv6","yourfreedom","voipswitchvoiptunnel","dhcpv6",\
"meebo","funshion","afp","aimini","truphone","clubpenguin","florensia","teamspeak","maplestory","osh","ps3",\
"dofus","wii","ipsecudp","wokf","fiesta","splashfighter","httpactivesync","jabbernimbuzz", "crossfire","tunnelvoice",\
"wapwsp","wapwtpwsp","wapwtls","multimediamessaging","guildwars","armagetron","blackberry","rfactor", "rdt", \
"teamviewer", "gamekit", "netmotion", "ultrabac", "teredo", "spotify", "implus", "antsp2p", "ultrasurf", "viber", \
"tango", "iplayer", "jbk3k", "operamini", "bolt", "scydo", "whatsapp", "webex", "netflix", "mojo", "imo", \
"citrixgoto", "ficall", "comodounite", "goober", "ventrilo", "mypeople", "websocket", "ebuddy", \
"sstp", "adobeconnect", "jap", "ldp", "wuala", "msrp", "webdav", "lync", "socks", "audiogalaxy", "mig33", \
"httptunnel", "rhapsody", "sudaphone", "webqq", "pdproxy", "license", "silverlight", "spdy", "cyberghost", "google", \
"fix", "oracledb", "itv", "demand5", "rsvp", "channel4od", "lotusnotes", "poisonivy", "netflow", "hidrive", "wechat", \
"myvideo", "soap", "kik", "mplus", "line", \
"speedtest","weather","maps","news","advertisement","software_update","photo_sharing","llmnr","flurry","andomedia","admob",\
"symantec","mcafee","teamlava","speedyshare","slacker","USER17","USER18","USER19","USER20","USER21",\
"USER22","USER23","USER24","USER25","USER26","USER27","USER28","USER29","USER30","USER31",\
"USER32","USER33","USER34","USER35","USER36","USER37","USER38","USER39",\
"USER40","USER41","USER42","USER43","USER44","USER45","USER46","USER47","USER48","USER49",\
"USER50","USER51","USER52","USER53","USER54","USER55","USER56","USER57","USER58","USER59",\
"USER60","USER61","USER62","USER63","USER64","USER65","USER66","USER67","USER68","USER69",\
"USER70","USER71","USER72","USER73","USER74","USER75","USER76","USER77","USER78","USER79",\
"USER80","USER81","USER82","USER83","USER84","USER85","USER86","USER87","USER88","USER89",\
"USER90","USER91","USER92","USER93","USER94","USER95","USER96","USER97","USER98","USER99",\
"USER100"

//NOTE These USER1 to USER8 assigned as follows
// "HTTP-speedtest","HTTP-weather","HTTP-MAPS","HTTP-NEWS","HTTP-ADS","HTTP-SW","HTTP-PHOTO","LLMNR","USER9","USER10","USER11",

using std::ostream;
using std::stringstream;
using std::endl;
using std::list;

typedef list<struct flow_data *> FlowList_t;
typedef std::tr1::unordered_map<u_int32_t, FlowList_t *> UEFlowMap_t;
static const unsigned short throughputThresholdFactor = 6;
static const unsigned long long throughputDefaultThreshold = 1000000; // 1 Second
extern const char* CLIENT_STR[];
extern const unsigned int MAX_SUPPORTED_CLIENTS;

struct cdpDetectionDataStruct {
    unsigned char *host;
    unsigned char *content;
    unsigned char *user_agent;
    unsigned char *url;
    u16 host_len;
    u16 content_len ;
    u16 user_agent_len ;
    const struct ipoque_cdp_generic_info *genericInfo;
    u16 cdpGenericDataSet;
    u16 cdpHostDataSet;

};

struct flow_data {

    int queueNumber;
    unsigned long long packetsDown;
    unsigned long long packetsUp;
    unsigned long long maxPacketLength;
    unsigned long long bytes; //total bytes of the flow
    unsigned int protocol;
    unsigned int application;
    unsigned int sub_protocol;
    u_int32_t hashKey;
    double firstPacketTime;
    double lastPacketTime;
    double firstPacketTimeInRop;
    struct PectIP4Tuple fourTuple;
    iphdr *userPacketIPHeader;
    struct ipoque_pace_client_server_indication_host_status ueHost;
    struct ipoque_pace_client_server_indication_host_status serverHost;
    bool contentTypeNotSet;
    bool hostNotSet;
    int userAgentNotSet;
    char sub_protocol_str[MAX_SUB_PROTOCOL_STRING_LENGTH];
    char host[MAX_HOST_NAME_SIZE];
    char contentType[MAX_CONTENT_TYPE_SIZE];
    unsigned int client;
    unsigned int ropCounter;
    double durationThisRop;
    unsigned long long ropStartTime; // Time in epoch seconds current ROP started.
    unsigned long long firstPacketRopBoundryTime; // In most real time cases = ropStartTime; But If its a pcap, then packet time will be time pcap recorded.
    unsigned long long ueToInternetDataBytes;
    unsigned long long internetToUeDataBytes;
    char uriExtension[MAX_URI_EXTENSION_LENGTH];
    int uri_extension_not_set;
    unsigned int group;
    unsigned long sessionThroughput;
    unsigned long throughput;
    unsigned long dataReceived;
    IPOQUE_TIMESTAMP_COUNTER_SIZE serverLatency;
    IPOQUE_TIMESTAMP_COUNTER_SIZE clientLatency;
    unsigned short ueMaxReceiverWindowSize; //    receiver windows belongs to ue. default is zero
    unsigned short serverMaxReceiverWindowSize;// receiver windows belongs to server. default is zero
    bool removed;
    struct pktLossInfo tcpPktLossInfo;
    bool isTcpFlow;
    unsigned int internetToUeLossRate;
    unsigned int ueToInternetLossRate;

    struct UserPlaneTunnelId tunnelId;

    int hostnameAddedToStats_NonHttpNoHostName;
    int hostnameAddedToStats_HttpNoHostName;


    unsigned long long tpLastRopBoundryTime;
    unsigned long long lastPacketTime_us;

    int tpDurationStopwatchStarted[2];
    unsigned long long tpDuration[2];
    unsigned long long tpBurstDuration[2];
    unsigned long long tpTimeLastBurstStarted[2];
    unsigned long long tpAckLastPacketTime[2];
    unsigned long long tpOutOfOrderPackets[2];  // These are out of order packets that are received in this ROP but belong to the previous ROP ; Cumulative
    unsigned long throughput_heading_to_ue;
    unsigned long throughput_heading_to_inet;
    unsigned long long tpDurationTotal;
    unsigned long long tpBurstDurationTotal;
    unsigned long long tpTimeLastBurstStartedTotal;
    unsigned long long tpLastPktTimeOfLastBurst[2];
    unsigned long long tpThreshold[2];
    unsigned long long tpTotalBytes;

    unsigned long long cdpNumPackets;
    int cdpSTATE;
    int cdpEXCLUDED[IPOQUE_MAX_HTTP_CUSTOM_PROTOCOLS];

    int printOnce;
	unsigned int service_provider;
	
	unsigned int isHttpConnection;
	
	// efitleo:  Multiple Timeout Queues
    int flowTimeoutClass;

    void init() {
        packetsDown = 0;
        packetsUp = 0;
        maxPacketLength = 0;
        bytes = 0;
        protocol = 0;
        hashKey = 0;
        contentTypeNotSet = false;
        hostNotSet = false;
        ropCounter = 0;
        durationThisRop = 0;
        ueToInternetDataBytes = 0;
        internetToUeDataBytes = 0;
        sessionThroughput = 0;
        throughput = 0;
        dataReceived = 0;
        ueMaxReceiverWindowSize = 0;
        serverMaxReceiverWindowSize = 0;
        fourTuple.serverIP = 0;
        fourTuple.serverPort = 0;
        fourTuple.ueIP = 0;
        fourTuple.uePort = 0;
        queueNumber = -1;
        firstPacketTime = std::numeric_limits<double>::max();
        firstPacketTimeInRop = std::numeric_limits<double>::max();
        lastPacketTime = 0.0;
        contentType[0] = '\\';
        contentType[1] = 'N';
        contentType[2] = '\0';
        
        host[0] = '\\';
        host[1] = 'N';
        host[2] = '\0';
        
        client=0;
        
        uriExtension[0] = '\\';
        uriExtension[1] = 'N';
        uriExtension[2] = '\0';
        
        uri_extension_not_set = 1;
        isHttpConnection = UINT_MAX;
        contentTypeNotSet = true;
        hostNotSet = true;
        userAgentNotSet = 10; // number packets to try before not checking any more; tests at live site show client will be set on first or second packet
        group = UINT_MAX;
        serverLatency = UINT_MAX;
        clientLatency = UINT_MAX;
        ropCounter = 0;
        removed = false;
        ueToInternetLossRate = std::numeric_limits<unsigned int>::max();
        internetToUeLossRate = std::numeric_limits<unsigned int>::max();
        isTcpFlow = false;
        tpLastRopBoundryTime = 0;
        tpDurationTotal = 0;
        tpDuration[0] = 0;
        tpDurationStopwatchStarted[0] = 0;
        tpTimeLastBurstStarted[0] = 0;
        tpDuration[1] = 0;
        tpDurationStopwatchStarted[1] = 0;
        tpTimeLastBurstStarted[1] = 0;
        tpAckLastPacketTime[0] = 0;
        tpAckLastPacketTime[1] = 0;
        throughput_heading_to_inet = 0;
        throughput_heading_to_ue = 0;
        tpOutOfOrderPackets[0] = 0;
        tpOutOfOrderPackets[1] = 0;
        tpDurationTotal = 0;
        tpBurstDuration[0] = 0;
        tpBurstDuration[1] = 0;
        tpBurstDurationTotal = 0;
        tpTimeLastBurstStartedTotal = 0;
        printOnce = 0;
        tpThreshold[0] = throughputDefaultThreshold;
        tpThreshold[1] = throughputDefaultThreshold;
        lastPacketTime_us = 0;
        tpLastPktTimeOfLastBurst[0] = 0;
        tpLastPktTimeOfLastBurst[1] = 0;
        tpTotalBytes = 0; // cumulative total version of bytes
        memset(&tunnelId, 0, sizeof(struct UserPlaneTunnelId)) ;
        hostnameAddedToStats_NonHttpNoHostName = 0;
        hostnameAddedToStats_HttpNoHostName = 0;
        application = UINT_MAX ;
        sub_protocol = UINT_MAX;
        cdpNumPackets = 0;
        cdpSTATE = -1;
        service_provider = 0;
        
        // efitleo:  Multiple Timeout Queues
        flowTimeoutClass=-1;
        

        for(int i = 0; i < IPOQUE_MAX_HTTP_CUSTOM_PROTOCOLS; i++) {
            cdpEXCLUDED[i] = 0;
        }
    }


    flow_data() {
        init();
    }

    void resetPerBurst(int direction) {
        tpDurationStopwatchStarted[direction] = 0;
        tpTimeLastBurstStarted[direction] = 0;
        tpBurstDuration[direction] = 0;
        tpAckLastPacketTime[direction] = 0;
    }
    void resetFlowPerRop() {
        sessionThroughput = 0;
        throughput = 0;
        bytes = 0;
        dataReceived = 0;
        durationThisRop = 0;
        internetToUeDataBytes = 0;
        ueToInternetDataBytes = 0;
        packetsDown = 0;
        packetsUp = 0;
        firstPacketTimeInRop = std::numeric_limits<double>::max();
        // Packet Loss Rate is Cumulative; Don't reset per ROP, this handles the case where
        // ROP 1 the rate > 0 and ROP2 has no rate due to no unique packets. Active rate is the rate got in ROP1
        // ueToInternetLossRate = std::numeric_limits<unsigned int>::max();
        // internetToUeLossRate = std::numeric_limits<unsigned int>::max();
        //EQEV-6445 Conversation 9 dec-13 now flow based...don't reset ThroughPut Values here
        throughput_heading_to_inet = 0;  // re-calculate each ROP baed on cumulative flow.
        throughput_heading_to_ue = 0;
    }

    double getUniqueId() {
        return firstPacketTime;
    }

    int getDirection()const {
        const int clientConnections = 50;

        if(ueHost.host_type == IPOQUE_HOST_IS_CLIENT && ueHost.percentage_of_client_connections > clientConnections) {
            return 1;
        }

        if(serverHost.host_type == IPOQUE_HOST_IS_SERVER && serverHost.percentage_of_client_connections < clientConnections) {
            return 1;
        }

        if(ueHost.host_type == IPOQUE_HOST_IS_SERVER && ueHost.percentage_of_client_connections < clientConnections) {
            return 0;
        }

        if(serverHost.host_type == IPOQUE_HOST_IS_CLIENT && serverHost.percentage_of_client_connections > clientConnections) {
            return 0;
        }

        return -1;
    }

    ~flow_data() {
        tcpPktLossInfo.cleanupMaps();
    }

};

ostream &operator<<(ostream &os, const flow_data *flow);
void printFlowToString(const flow_data *flow, char *gtpu_data, int maxLength);
void printHeaderFlowToString(char *gtpu_data);
void getRopCounter(const flow_data *flow, unsigned int *ropCtr);
void printMicroSecondsIfNotMaxVal(unsigned int value, char *destination, int maxLength) ;
void calculateTCPPacketLoss(flow_data *flow_data, unsigned int protocol, const struct PectPacketHeader *pectHeader, const PacketDirection_t direction, const u_char *rawPacket, u8 *new_flow, int queue_num);
void checkBurstFinished(flow_data *flow_data, int direction, int *isDupReTX);
void getUnigueBytesCount(flow_data *flow_data, int direction, unsigned long long *uniqueBytesCount);
void calculateUniqueBytesAcknowledged(const flow_data *fd, unsigned long long *totalBytes, int direction);
void calculateTotalUniqueBytesAcknowledged(const flow_data *fd, unsigned long long *totalBytes);
void printTPMetricsTotal(flow_data *flow_data, const unsigned long long packetTime_uS);
void printTPMetrics(flow_data *flow_data, const unsigned long long packetTime_uS, int direction);
void tpTimeoutBurst(flow_data *flow_data, const unsigned long long *lastPacketTime_us, const unsigned long long  *currentPacketTime_uS, int direction, int ropBoundary);
void tpGetLastPacketTime(flow_data *flow_data, unsigned long long *returnedLastPacketTime_us, int direction);
void tpTimer(flow_data *flow_data, const unsigned long long *packetTime_uS, PacketDirection_t pktDirection);
void handleThroughPutStats(flow_data *thisFlow, const unsigned long long *curPktTime_uS);
void getFirstPacketRopBoundryTime(flow_data *flow_data);
int convertDirectionToPktLossDirection(int direction);
void pktLossGetExpectedSeqNumMapSize_ue(flow_data *fd, unsigned long *mapSizeBytes);
void pktLossGetExpectedSeqNumMapSize_inet(flow_data *fd, unsigned long *mapSizeBytes);
void pktLossInitialiseMaps(flow_data *fd,  PectIP4Tuple fourTuple);
void pktLossCleanupMaps(flow_data *fd);
void printPktLossMapInfo_inet(flow_data *fd, int loc, char *testName,  PectIP4Tuple fourTuple) ;
void printPktLossMapInfo_ue(flow_data *fd, int loc, char *testName,  PectIP4Tuple fourTuple) ;
void printPktLossRateInfo_Header();
void printPktLossRateInfo(flow_data *fd);
void getPacketLossValueAsString(unsigned int pktLossValue_uint, char *retValue);
void getPacketLossRate(flow_data *flow_data, int loc);
void getSubProtocolValueAsString(unsigned int theSubProtocol, const char *subProtocolStr, char *retValue);
void getApplicationValueAsString(unsigned int application, char *retValue);
void getProtocolValueAsString(unsigned int protocol, char *retValue);
void getProtocolGroupValueAsString(unsigned int protocolGroup, char *retValue);

#endif /* FLOW_H_ */
