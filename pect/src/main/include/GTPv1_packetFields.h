#ifndef GTPv1_packetFields
#define GTPv1_packetFields

#include <pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <string>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <boost/tr1/unordered_map.hpp>
#include <fstream>
#include <vector>
#include <boost/serialization/level.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/shared_ptr.hpp>
#include <boost/serialization/vector.hpp>

#include "gtpv1_utils.h"
#include "gtp_ie.h"
#include "pcp_check.hpp"

using std::string;
using std::cout;
using std::ostream;
using std::endl;

#define RECORD_DELIMITER ","
#define RECORD_DELIMITER_13A "\t"
#define RECORD_DELIMITER_13A_CAPTOOL "|"

extern std::ofstream f_out;

class GTPPorts {
public:
    enum PortNumbers {
        GTP_CONTROL_PORT = 2123
    };
};

class IPVersion {
public:
    enum {
        IPV4 = 4
    };
};

class GTPMessageTypes {
public:
    enum {
        ECHO_REQUEST = 1,
        ECHO_RESPONSE = 2,
        VERSION_NOT_SUPPORTED = 3,
        SEND_ROUTING_FOR_QPRS_REQUEST = 32,
        SEND_ROUTING_FOR_QPRS_RESPONSE = 33,
        CREATE_PDP_CONTEXT_REQUEST = 0X10,
        CREATE_PDP_CONTEXT_RESPONSE = 0X11,
        UPDATE_PDP_CONTEXT_REQUEST = 0X12,
        UPDATE_PDP_CONTEXT_RESPONSE = 0x13,
        DELETE_PDP_CONTEXT_REQUEST = 0x14,
        DELETE_PDP_CONTEXT_RESPONSE = 0x15
    };
};

enum ControlPlaneTeidIndex {
    GGSN = 0, SGSN = 1
};

typedef enum {
    SGSN_INITIATED,
    GGSN_INITIATED,
    UNKNOWN = -1
} MessageDirection_t;

typedef enum {
    UNITIALIZED,
    INITIALIZED,
    CREATE_REQUEST_RECEIVED,
    CREATE_FAILED,
    CREATED,
    UPDATE_REQUEST_RECEIVED,
    UPDATE_FAILED,
    UPDATED,
    DELETE_REQUEST_RECEIVED,
    DELETE_FAILED,
    DELETED,
    SEQ_NUM_TIMEOUT
} PDPSessionStatus_t;

struct FTEID {
    friend class boost::serialization::access;
    friend std::ostream &operator<<(std::ostream &os, const FTEID &field);

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &addr &teid &time;
    }

    unsigned long addr;
    unsigned int teid;
    double time; // creation time

    FTEID() {
        addr = 0;
        teid = 0;
        time = -1;
    }
};

bool operator!=(const FTEID &lhs, const FTEID &rhs);
bool operator==(const FTEID &lhs, const FTEID &rhs);

struct dataeq {
    size_t operator()(const FTEID &x) const {
        return std::hash<u_int32_t>()((u_int32_t) x.addr ^ (u_int32_t) x.teid);
    }

    bool operator()(const FTEID f1, const FTEID f2) const {
        return (f1.addr == f2.addr) && (f1.teid == f2.teid);
    }
};

typedef struct PDPQOSInfo {
    friend class boost::serialization::access;

    int arp;
    int delay_class;
    int reliability_class;
    int precedence;
    int thp;
    int max_ul;
    int max_dl;
    int gbr_ul;
    int gbr_dl;
    string traffic_class;
    int sdu;

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &arp &delay_class &reliability_class &precedence &thp &max_ul
        & max_dl &gbr_ul &gbr_dl &traffic_class &sdu;
    }

    void init();
} PDPQOSInfo_t;

typedef struct PDPLocationInfo {
    friend class boost::serialization::access;

    char mnc[MNC_MAX_CHARS];
    char mcc[MCC_MAX_CHARS];
    int lac, rac;
    int cid, sac;

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &mcc &mnc &lac &rac &sac &cid;
    }

    void init();
} PDPLocationInfo_t;

/**
 * The Sequence Number is used to match a GTP-C response message to the relevant request.
 */
typedef struct SequenceNumber {
    friend class boost::serialization::access;
    friend std::ostream &operator<<(std::ostream &os, const struct SequenceNumber &sequenceNumber);

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &messageType &sequenceNumber;
        ar &src_addr &src_port &dst_addr &dst_port;
        ar &time &teid;
    }

    unsigned char messageType;
    int sequenceNumber;
    unsigned long src_addr, dst_addr;
    unsigned short src_port, dst_port;
    double time;
    FTEID teid;
} SequenceNumber_t;

struct SequenceNumberEq {
    size_t operator()(const SequenceNumber_t &x) const {
        return std::hash<u_int64_t>()(((u_int64_t)(x.src_addr) << 32) ^ ((u_int64_t)x.src_port << 48)
                                      ^ (u_int32_t)(x.dst_addr) ^ ((u_int32_t)x.dst_port << 16) ^ ((u_int64_t) x.sequenceNumber << 8));
    }

    bool operator()(const SequenceNumber_t f1,
                    const SequenceNumber_t f2) const {
        return (f1.src_addr == f2.src_addr) && (f1.dst_addr == f2.dst_addr) && (f1.src_port == f2.src_port)
               && (f1.dst_port == f2.dst_port) && (f1.sequenceNumber == f2.sequenceNumber);
    }
};

struct UserPlaneTunnelId {
    friend class boost::serialization::access;
    friend std::ostream &operator<<(std::ostream &os, const struct UserPlaneTunnelId &userPlaneTunnelId);

    FTEID teids[2]; // Indexed by PacketDirection_t

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        ar &teids;
    }
};

typedef struct UserPlaneTunnelIdOperators {
    size_t operator()(const struct UserPlaneTunnelId &x) const {
        return std::hash<u_int32_t>()(
                   (u_int32_t) x.teids[0].addr ^ (u_int32_t) x.teids[0].teid
                   ^ (u_int32_t) x.teids[1].addr
                   ^ (u_int32_t) x.teids[1].teid);
    }

    bool operator()(const struct UserPlaneTunnelId f1,
                    const struct UserPlaneTunnelId f2) const {
        return (f1.teids[0] == f2.teids[0]) && (f1.teids[1] == f2.teids[1]);
    }
} UserPlaneTunnelIdOperators_t;

typedef struct PDPSession *PDPSessionPtr_t;

typedef struct CreatePDPContextInfo {
    bool isSecondary;
    PDPSessionPtr_t primarySession;
    CreatePDPContextInfo()  : isSecondary(false), primarySession(NULL) {}
} CreatePDPContextInfo_t;

typedef struct UpdatePDPContextInfo {
    MessageDirection_t direction;
    PDPLocationInfo_t locationInfo;
    FTEID sgsn_c, sgsn_d; // Mandatory for SGSN initiated
    FTEID ggsn_c, ggsn_d;
    PDPQOSInfo_t qosInfo; // Mandatory for SGSN initiated
    char rat[RAT_MAX_CHARS];
    int ratPresent;
    char imsi[IMSI_MAX_CHARS];
    int imsiPresent;
    int dtFlag;
    int nsapi; // Mandatory
    u_int32_t ue_addr;
    void init();
    UpdatePDPContextInfo() {
        init();
    }
} UpdatePDPContextInfo_t;

typedef struct MessageData {
    CreatePDPContextInfo_t *createInfo;
    UpdatePDPContextInfo_t *updateInfo;
    PDPSessionPtr_t session;
    MessageData() : createInfo(NULL), updateInfo(NULL), session(NULL) {
    }
    ~MessageData() {
        if(createInfo != NULL) {
            delete createInfo;
        }

        if(updateInfo != NULL) {
            delete updateInfo;
        }
    }
} MessageData_t;

struct PDPSession {
    IPQ_REDZONE_DEF(0)
    friend class boost::serialization::access;

    template<class Archive>
    void serialize(Archive &ar, const unsigned int version) {
        boost::serialization::split_member(ar, *this, version);
    }

    IPQ_REDZONE_DEF(1)

    template<class Archive>
    void save(Archive &ar, const unsigned int version) const {
        const_cast<PDPSession *>(this)->serializeCommon(ar);
    }

    IPQ_REDZONE_DEF(2)

    template<class Archive>
    void load(Archive &ar, const unsigned int version) {
        touch = (double)time(0);
        pthread_mutex_init(&(pdpSessionMutex), 0);
        serializeCommon(ar);
    }

    template<class Archive>
    void serializeCommon(Archive &ar) {
        ar &startTime &touch;
        ar &imsi &imei;
        ar &sgsn_c &ggsn_c &dle;
        ar &apn &msisdn &ue_addr &nsapi &linkedNSAPI;
        ar &pdp_type &rat;
        ar &dtflag;
        ar &locationInfo;
        ar &pdn_cause &update_cause;
        ar &qosInfo;
        ar &instanceCounter &deleteCounter;
        ar &sequenceNumbers;
        ar &status;
        ar &userPlaneTunnelId;
        ar &teardownInd;
    }

    IPQ_REDZONE_DEF(3)
    pthread_mutex_t pdpSessionMutex; //init this when load
    IPQ_REDZONE_DEF(4)
    double startTime;
    double touch;  // last activity on this session of any kind
    int loadedFromCache;
    char imsi[IMSI_MAX_CHARS];
    IPQ_REDZONE_DEF(5)
    char imei[IMEI_MAX_CHARS];
    IPQ_REDZONE_DEF(6)
    struct FTEID sgsn_c;
    IPQ_REDZONE_DEF(7)
    struct FTEID ggsn_c;
    IPQ_REDZONE_DEF(8)
    struct FTEID dle; // downlink endpoint (rnc or sgsn)
    IPQ_REDZONE_DEF(9)
    char apn[APN_MAX_CHARS];
    IPQ_REDZONE_DEF(10)
    char msisdn[MSISDN_MAX_CHARS];
    IPQ_REDZONE_DEF(11)
    u_int32_t ue_addr;
    IPQ_REDZONE_DEF(12)
    int nsapi;
    int linkedNSAPI;
    char pdp_type[PDN_TYPE_MAX_CHARS]; //primary or secondary
    IPQ_REDZONE_DEF(13)
    char rat[RAT_MAX_CHARS]; //GSM, ...
    IPQ_REDZONE_DEF(14)
    int dtflag;
    IPQ_REDZONE_DEF(15)
    PDPLocationInfo_t locationInfo;
    IPQ_REDZONE_DEF(16)
    int pdn_cause;
    unsigned int update_cause;
    IPQ_REDZONE_DEF(17)
    PDPQOSInfo_t qosInfo;
    IPQ_REDZONE_DEF(18)
    static int instanceCounter;
    static int deleteCounter;
    IPQ_REDZONE_DEF(19)
    std::vector<SequenceNumber_t> sequenceNumbers;
    PDPSessionStatus_t status;
    struct UserPlaneTunnelId userPlaneTunnelId;
    bool teardownInd;
    IPQ_REDZONE_DEF(20)

    void initRedZone() {
        IPQ_REDZONE_REF(0) = 0xdead;
        IPQ_REDZONE_REF(1) = 0xdead;
        IPQ_REDZONE_REF(2) = 0xdead;
        IPQ_REDZONE_REF(3) = 0xdead;
        IPQ_REDZONE_REF(4) = 0xdead;
        IPQ_REDZONE_REF(5) = 0xdead;
        IPQ_REDZONE_REF(6) = 0xdead;
        IPQ_REDZONE_REF(7) = 0xdead;
        IPQ_REDZONE_REF(8) = 0xdead;
        IPQ_REDZONE_REF(9) = 0xdead;
        IPQ_REDZONE_REF(10) = 0xdead;
        IPQ_REDZONE_REF(11) = 0xdead;
        IPQ_REDZONE_REF(12) = 0xdead;
        IPQ_REDZONE_REF(13) = 0xdead;
        IPQ_REDZONE_REF(14) = 0xdead;
        IPQ_REDZONE_REF(15) = 0xdead;
        IPQ_REDZONE_REF(16) = 0xdead;
        IPQ_REDZONE_REF(17) = 0xdead;
        IPQ_REDZONE_REF(18) = 0xdead;
        IPQ_REDZONE_REF(19) = 0xdead;
        IPQ_REDZONE_REF(20) = 0xdead;
    }

    void checkRedZone() {
        if(IPQ_REDZONE_REF(0) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(1) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(2) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(3) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(4) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(5) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(6) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(7) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(8) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(9) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(10) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(11) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(12) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(13) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(14) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(15) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(16) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(17) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(18) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(19) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }

        if(IPQ_REDZONE_REF(20) != 0xdead) {
            IPQ_FORCE_SEGFAULT();
        }
    }

    void init();

    PDPSession(char imsi_init[IMSI_MAX_CHARS]) {
        init();
        memcpy(imsi, imsi_init, IMSI_MAX_CHARS);
        imsi[IMSI_MAX_CHARS - 1] = '\0';
        instanceCounter++;
    }

    void createPDPSessionUsingIMSI(char imsi_init[IMSI_MAX_CHARS]) {
        init();
        memcpy(imsi, imsi_init, IMSI_MAX_CHARS);
        imsi[IMSI_MAX_CHARS - 1] = '\0';
        instanceCounter++;
    }

    PDPSession() {
        init();
        instanceCounter++;
    }

    ~PDPSession() {
        pthread_mutex_destroy(&(pdpSessionMutex));
        instanceCounter--;
        deleteCounter++;
    }

    static int getInstanceCounter() {
        return instanceCounter;
    }
    static int getDeleteCounter() {
        return deleteCounter;
    }

    void print() {
    }
    void printUpdate();
    void printPDPSession();
    void applyStagingArea(const UpdatePDPContextInfo_t *updateInfo);
    friend std::ostream &operator<<(std::ostream &os, const PDPSession *session);
};

struct PDPSessionString {

    char mcc[MCC_MAX_CHARS];
    char mnc[MNC_MAX_CHARS];
    char imsi[IMSI_MAX_CHARS];
    unsigned int ue_addr;

    int lac;

    double startTime;
    string pdpsession_str;

    PDPSessionString() {
        lac = 0;
        startTime = 0;
        ue_addr = 0;
    }

    PDPSessionString(PDPSession &pdpsession) {
        startTime = pdpsession.startTime;
        lac = pdpsession.locationInfo.lac;
        ue_addr = pdpsession.ue_addr;
        strcpy(mcc, pdpsession.locationInfo.mcc);
        strcpy(mnc, pdpsession.locationInfo.mnc);
        strcpy(imsi, pdpsession.imsi);
        pdpsession_str.append(pdpsession.imsi);
    }
};

struct MNCBCDDigits {
    unsigned char : 4;
    unsigned char Hundreds : 4;
    unsigned char Tens : 4;
    unsigned char Units : 4;
};

//the bitfield for the MCC as per GTPv1
struct MCCBCDDigits {
    unsigned char Hundreds : 4;
    unsigned char Tens : 4;
    unsigned char Units : 4;
};

struct GTP_Control_Full_Header {
    unsigned char N_PDUNumberFlag : 1;
    unsigned char SequenceNumberFlag : 1;
    unsigned char ExtensionHeaderFlag : 1;
    unsigned char Reserved : 1;
    unsigned char ProtocolType : 1;
    unsigned char Version : 3;
    unsigned char MessageType : 8;
    unsigned short TotalLength : 16;
    unsigned int TunnelEndpointIdentifier : 32;
    unsigned short SequenceNumber : 16;
    unsigned char N_PDUNumber : 8;
    unsigned char NextExtensionHeaderType : 8;
};

struct GTP_Control_Basic_Header {
    unsigned char N_PDUNumberFlag : 1;
    unsigned char SequenceNumberFlag : 1;
    unsigned char ExtensionHeaderFlag : 1;
    unsigned char Reserved : 1;
    unsigned char ProtocolType : 1;
    unsigned char Version : 3;
    unsigned char MessageType : 8;
    unsigned short TotalLength : 16;
    unsigned int TunnelEndpointIdentifier : 32;
};

union GTP_Control_Header {
    GTP_Control_Basic_Header basicHeader;
    GTP_Control_Full_Header fullHeader;
};

struct LinuxCookedHeader {
    u_short incoming : 16;
    u_short ARPHPD_ : 16;
    u_short loopback : 16;
    u_short llaAddressType : 16;
    u_short llaAddress[4];
};

struct my_ip {
    u_int8_t ip_vhl; /* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
    u_int8_t ip_tos; /* type of service */
    u_int16_t ip_len; /* total length */
    u_int16_t ip_id; /* identification */
    u_int16_t ip_off; /* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    u_int8_t ip_ttl; /* time to live */
    u_int8_t ip_p; /* protocol */
    u_int16_t ip_sum; /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};

void decodeMNC(unsigned char *p, char *mnc);
void decodeMCC(unsigned char *p, char *mcc);
unsigned long long parseIMSI_IMEI_Field(unsigned char *p, int pos);
unsigned int extractIpAddress(unsigned char *p);
unsigned short extractPortFromPacket(unsigned char *p);
string debugPDPSession(PDPSession *session);
ostream &getGTPCCaptoolMiddleString(ostream &os, const PDPSession *session);
ostream &getGTPCCaptoolEndingString(ostream &os, const PDPSession *session);
ostream &getGTPCStapleEndingString(ostream &os, const PDPSession *session);

static const FTEID DEFAULT_FTEID = FTEID();

#endif

