/*
 * gtpv1_utils.h
 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#ifndef GTPV1_UTILS_H_
#define GTPV1_UTILS_H_

#define LENGTHOF(a) (sizeof(a)/sizeof(a[0]))
#define VERSION_ONE "1"
#define VERSION_TWO "2"
#define VERSION_BOTH "both"

//#pragma pack(1) //vital to get bit fields to line up correctly
typedef unsigned char UCHAR;

#include <iostream>
#include <string>
#include <netinet/in.h>
#include "GTPv1_packetFields.h"
#include <netinet/if_ether.h>
#include <boost/tr1/unordered_map.hpp>
#include <list>
#include "gtp_ie.h"
#include "pcp_limits.h"

using std::ofstream;
using std::cerr;
using std::endl;
using std::string;
using std::ostream;
using std::list;


struct EArgs {
    //GTPC options
    string GTPCVersion;
    string GTPCInput;
    string GTPCInstance_tag;
    string type;
    int gtpcCacheWriteInterval; // The time to sleep inbetween GTP-C Cache writes.
    int GTP_file_interval;
    int GTPC_HASHMAP_MAX_SIZE;
    int gtpcSessionTimeoutAge;
    int gtpcSessionTimeoutFrequency;

    //GTP-U handling
    int packetBufferSourceCount;
    int packetBufferCaptureType;
    int packetBufferSinkCount;
    int packetBufferMacOfKnownElementCount;
    bool useMultiplePacketBuffers;
    unsigned int packetBufferSize;
    unsigned int ipqConnectionNormalTimeout;
    unsigned int ipqConnectionShortTimeout;
    unsigned int ipqConnectionLongTimeout;
    list<string> packetBufferGtpuSourceName;
    list<unsigned long> packetBufferMacOfKnownElement;
    int printPacketBufferStatsInterval;
    unsigned int packetLossUserThreshold_UE_to_INET;
    unsigned int packetLossUserThreshold_INET_to_UE;

    //Output handling
    string outputlocation;
    string tempOutputLocation;
    string fileOutputFormat;
    int outputReportingPeriod;
    unsigned int minFlowSize;
    std::tr1::unordered_map<string, int> excludeRATs;

    //License handling
    //string ipoquePaceLicenseFile;
    string rmiLicenseFullPath;
    string rmiLicenseHost;
    string rmiLicensePort;
    string rmiLicenseName;

    //parameter type
    string propertyFileName;
    bool usePropertyFile;

    //System management
    unsigned long programTimeout;

    // The HOST array depth search here.
    list<int> cdpDecodeHostsLevel;

    //THE NON Default string arrays
    bool cdpDecodeExtraHosts;

    // THE URL DECODE string arrays .
    bool cdpcdpDecodeURL;

    // THE USER AGENT DECODE string arrays.
    bool cdpDecodeUserAgent;

    int GTP_capture_type_is_live_interface;

} ;

// Utility functions
bool isDir(const char *path);
int parseArgs(int argc, char **argv, pcap_t **descr);
bool checkDataMatches(const string &description, long long expectedValue, long long obtainedValue);
bool checkDataGE(const string &description, long long expectedValue, long long obtainedValue);
bool GetPacketPointerAndLength(const u_char *packet, bool cooked, const struct my_ip **ipP, int *lengthP, struct pcap_pkthdr *pkthdr);

using std::endl;
using std::ostream;

#define NUM_OF_RAT_DESCRIPTION 8

extern const char *RAT_DESCRIPTIONS[];

class PacketCounter {
private:
    PacketCounter(const PacketCounter &pc) {
        totalUnexpectedPackets = pc.totalUnexpectedPackets;
        totalErrorPackets = pc.totalErrorPackets;
        totalPackets = pc.totalPackets;
        totalNonEthernetPackets = pc.totalNonEthernetPackets;
        totalNumberOfVersionOnePackets = pc.totalNumberOfVersionOnePackets;
        totalNumberOfVersionTwoPackets = pc.totalNumberOfVersionTwoPackets;
        nonIPV4Packets = pc.nonIPV4Packets;
        invalidHeaderLength = pc.invalidHeaderLength;
        truncatedPackets = pc.truncatedPackets;
        nonUDPPackets = pc.nonUDPPackets;
        fragmentedPackets = pc.fragmentedPackets;
    }

    PacketCounter():
        totalUnexpectedPackets(0),
        totalErrorPackets(0),
        totalPackets(0),
        totalNonEthernetPackets(0),
        totalNumberOfVersionOnePackets(0),
        totalNumberOfVersionTwoPackets(0),
        nonIPV4Packets(0),
        nonUDPPackets(0),
        invalidHeaderLength(0),
        truncatedPackets(0),
        fragmentedPackets(0)

    {}
public:
    string getDetails() const;
    ~PacketCounter() {
		// efitleo: Comment out the following code lines 
		// Attempt to fix EVEV-16224; Should not set pointer to object to null; This can case double free corruption
		// http://www.cplusplus.com/reference/new/operator%20delete/
		// An expression with the delete operator, first calls the appropriate destructor (for class types), and then calls a deallocation function.
		
       // if(theInstance) {
       //     theInstance = 0;
       // }
    }
public:
    static PacketCounter *getInstance() {
        if(!theInstance) {
            theInstance = new PacketCounter();
        }

        return theInstance;
    }
    void incrementTotalNumberOfVersion(int theVersion) {
        switch(theVersion) {
            case 1:
                totalNumberOfVersionOnePackets++ ;
                break;

            case 2:
                totalNumberOfVersionTwoPackets++ ;
                break;
        }
    }
    void incrementTotalPackets() {
        totalPackets++;
    }

    void incrementTotalErrorPackets() {
        totalErrorPackets++;
    }

    void incrementTotalUnexpectedPackets() {
        totalUnexpectedPackets++;
    }

    void incrementNonEthernetPackets() {
        totalNonEthernetPackets++;
    }

    void incrementNonIPV4Packets() {
        nonIPV4Packets++;
    }

    void incrementInvalidHeaderLengthPackets() {
        invalidHeaderLength++;
    }

    void incrementTruncatedPackets() {
        truncatedPackets++;
    }

    long getInvalidHeaderLength() const {
        return invalidHeaderLength;
    }

    void setInvalidHeaderLength(long invalidHeaderLength) {
        this->invalidHeaderLength = invalidHeaderLength;
    }

    long getNonIpv4Packets() const {
        return nonIPV4Packets;
    }

    void setNonIpv4Packets(long nonIpv4Packets) {
        nonIPV4Packets = nonIpv4Packets;
    }

    long getTruncatedPackets() const {
        return truncatedPackets;
    }

    void setTruncatedPackets(long truncatedPackets) {
        this->truncatedPackets = truncatedPackets;
    }

    long getTotalOKPackets() const {
        return totalPackets - totalUnexpectedPackets - totalErrorPackets;
    }

    long getTotalErrorPackets() const {
        return totalErrorPackets;
    }

    void setTotalErrorPackets(long totalErrorPackets) {
        this->totalErrorPackets = totalErrorPackets;
    }

    long getTotalPackets() const {
        return totalPackets;
    }

    void setTotalPackets(long totalPackets) {
        this->totalPackets = totalPackets;
    }

    long getTotalUnexpectedPackets() const {
        return totalUnexpectedPackets;
    }

    void setTotalUnexpectedPackets(long totalUnexpectedPackets) {
        this->totalUnexpectedPackets = totalUnexpectedPackets;
    }

    long getTotalNonEthernetPackets() const {
        return totalNonEthernetPackets;
    }

    void setTotalNonEthernetPackets(long totalNonEthernetPackets) {
        this->totalNonEthernetPackets = totalNonEthernetPackets;
    }

    long getTotalNumberOfVersionOnePackets() const {
        return totalNumberOfVersionOnePackets;
    }

    void setTotalNumberOfVersionOnePackets(long totalNumberOfVersionOnePackets) {
        this->totalNumberOfVersionOnePackets = totalNumberOfVersionOnePackets;
    }

    long getTotalNumberOfVersionTwoPackets() const {
        return totalNumberOfVersionTwoPackets;
    }

    void setTotalNumberOfVersionTwoPackets(long totalNumberOfVersionTwoPackets) {
        this->totalNumberOfVersionTwoPackets = totalNumberOfVersionTwoPackets;
    }

    void clearCounters() {
        this->setTotalErrorPackets(0);
        this->setTotalPackets(0);
        this->setTotalUnexpectedPackets(0);
        this->setTotalNonEthernetPackets(0);
        this->setTotalNumberOfVersionOnePackets(0);
        this->setTotalNumberOfVersionTwoPackets(0);
        this->setNonIpv4Packets(0);
        this->setNonUdpPackets(0);
        this->setFragmentedPackets(0);
        this->setTruncatedPackets(0);
        this->setInvalidHeaderLength(0);
    }

    void incrementNonUDPPackets() {
        nonUDPPackets++;
    }

    long getNonUdpPackets() const {
        return nonUDPPackets;
    }

    void setNonUdpPackets(long nonUdpPackets) {
        nonUDPPackets = nonUdpPackets;
    }

    void incrementFragmentedPackets() {
        fragmentedPackets++;
    }

    long getFragmentedPackets() const {
        return fragmentedPackets;
    }

    void setFragmentedPackets(long fragmentedPackets) {
        this->fragmentedPackets = fragmentedPackets;
    }

private:
    long totalUnexpectedPackets;
    long totalErrorPackets;
    long totalPackets;
    long totalNonEthernetPackets;
    long totalNumberOfVersionOnePackets;
    long totalNumberOfVersionTwoPackets;
    long nonIPV4Packets;
    long nonUDPPackets;
    long invalidHeaderLength;
    long truncatedPackets;
    long fragmentedPackets;
    static PacketCounter *theInstance;
};

ostream &operator<<(ostream &os, const PacketCounter *pc);

class printIFGT0 {
public:
    printIFGT0(long long theValue, const string &theSeparator = ","): value(theValue), separator(theSeparator) {}

    long long getValue() const {
        return value;
    }

    const string &getSeparator() const {
        return separator;
    }

private:
    long long value;
    string separator;
};
ostream &operator<<(ostream &os, const printIFGT0 &value);

class printIFGE0 {
public:
    printIFGE0(long long theValue, const string &theSeparator = ","): value(theValue), separator(theSeparator) {}

    long long getValue() const {
        return value;
    }

    const string &getSeparator() const {
        return separator;
    }

private:
    long long value;
    string separator;
};
ostream &operator<<(ostream &os, const printIFGE0 &value);

struct IPAddress {
    union {
        unsigned long address;
        unsigned char bytes[4];
    } data;
    IPAddress(unsigned long theAddress) {
        this->data.address = theAddress;
    }
};
ostream &operator<< (ostream &os, const IPAddress &ipAddress);

class PDN_CAUSE {
public:
    enum VALUE {
        NON_EXISTENT 								= 192,
        INVALID_MESSAGE_FORMAT 					= 193,
        IMSI_NOT_KNOWN								= 194,
        MS_IS_GPRS_DETACHED						= 195,
        MS_IS_NOT_GPRS_RESPONDING					= 196,
        MS_REFUSES									= 197,
        VERSION_NOT_SUPPORTED						= 198,
        NO_RESOURCES_AVAILABLE	 					= 199,
        SERVICE_NOT_SUPPORTED						= 200,
        MANDATORY_IE_INCORRECT	 					= 201,
        MANDATORY_IE_MISSING						= 202,
        OPTIONAL_IE_INCORRECT 						= 203,
        SYSTEM_FAILURE								= 204,
        ROAMING_RESTRICTION						= 205,
        P_TMSI_SIGNATURE_MISMATCH					= 206,
        GPRS_CONNECTION_SUSPENDED					= 207,
        AUTHENTICATION_FAILURE						= 208,
        USER_AUTHENTICATION_FAILED					= 209,
        CONTEXT_NOT_FOUND							= 210,
        ALL_DYNAMIC_PDP_ADDRESSES_ARE_OCCUPIED		= 211,
        NO_MEMORY_IS_AVAILABLE						= 212,
        RELOCATION_FAILURE	 						= 213,
        UNKNOWN_MANDATORY_EXTENSION_HEADER	 		= 214,
        SEMANTIC_ERROR_IN_THE_TFT_OPERATION		= 215,
        SYNTACTIC_ERROR_IN_THE_TFT_OPERATION		= 216,
        SEMANTIC_ERRORS_IN_PACKET_FILTERS			= 217,
        SYNTACTIC_ERRORS_IN_PACKET_FILTERS			= 218,
        MISSING_OR_UNKNOWN_APN						= 219,
        UNKNOWN_PDP_ADDRESS_OR_PDP_TYPE			= 220,
        PDP_CONTEXT_WITHOUT_TFT_ALREADY_ACTIVATED	= 221,
        APN_ACCESS_DENIED_NO_SUBSCRIPTION			= 222,
        APN_RESTRICTION_TYPE_INCOMPATIBILITY_WITH_CURRENTLY_ACTIVE_PDP_CONTEXTS	= 223,
        MS_MBMS_CAPABILITIES_NSUFFICIENT			= 224,
        INVALID_CORRELATION_ID	 					= 225,
        MBMS_BEARER_CONTEXT_SUPERSEDED	 			= 226,
        BEARER_CONTROL_MODE_VIOLATION				= 227,
        COLLISION_WITH_NETWORK_INITIATED_REQUEST	= 228,
        APN_CONGESTION								= 229,
        BEARER_HANDLING_NOT_SUPPORTED				= 230,
    };



};

inline unsigned short NetworkShortAt(unsigned char *p) {
    return ntohs(* (unsigned short *) p);
}

inline unsigned int NetworkIntAt(unsigned char *p) {
    return ntohl(* (unsigned int *) p);
}

bool isDir(const char *path);
int isFile(const string &path);
void initSignalHandler();

#endif /* GTPV1_UTILS_H_ */
