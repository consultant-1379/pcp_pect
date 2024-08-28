#ifndef GTPIE_H
#define GTPIE_H

#include <string>
#include "pcp_check.hpp"

// These values are defined in 3GPP TS 23.003, 3GPP TS 29.060 and ITU-T E.164
// (the extra digit is the string terminator)

#define IMSI_MAX_CHARS		(16+1) //must be bigger than SV_MAX_CHARS
#define IMEI_MAX_CHARS		(16+1)
#define MSISDN_MAX_CHARS	(15+1)
#define MNC_MAX_CHARS		(3+1)
#define MCC_MAX_CHARS		(3+1)
#define APN_MAX_CHARS		(100+1)
#define TAC_MAX_CHARS       (8+1)
#define SV_MAX_CHARS        (2+1)
#define PDN_TYPE_MAX_CHARS  (15+1)
#define RAT_MAX_CHARS       (10+1)


// esirich: DEFTFTS-1879 these values are output to indicate that a
// given data item has not been read from GTP
#define EMPTY_INT_STRING	"\\N"
#define IMSI_INIT_STRING	"\\N"
#define IMEI_INIT_STRING	"\\N"
#define MSISDN_INIT_STRING	"\\N"
#define MNC_INIT_STRING		"\\N"
#define MCC_INIT_STRING		"\\N"
#define APN_INIT_STRING		"\\N"
#define CLIENT_INIT_STRING  "\\N"


#define CHECK_UE_MAP_INTERVAL  (60)

using std::string;

class DecodedMsg {
    void initRedZone();

public:

    // esirich changed several values to strings for DEFTFTS-1825
    IPQ_REDZONE_DEF(0);
    DecodedMsg();
    void checkRedZone();
    unsigned char messageType;
    double timestamp;
    unsigned int src_addr; // from ip addr fields host byte order
    unsigned int dst_addr;
    unsigned short src_port;
    unsigned short dst_port;
    int rat_present;
    const char *rat;
    int sequenceNumber;
    int sequenceNumberPresent;
    IPQ_REDZONE_DEF(1);
    int imsi_present;
    char imsi[IMSI_MAX_CHARS];
    IPQ_REDZONE_DEF(2);
    char imei[IMEI_MAX_CHARS];
    IPQ_REDZONE_DEF(3);
    unsigned int teid;
    int teid_d_present;
    unsigned int teid_d;
    int teid_c_present;
    unsigned int teid_c;
    IPQ_REDZONE_DEF(4);
    int nsapi;
    int linked_nsapi;
    int dtflag;
    int apn_present;
    char apn[APN_MAX_CHARS];
    IPQ_REDZONE_DEF(5);
    int addr1_present, addr2_present;
    unsigned int addr1, addr2;
    char msisdn[MSISDN_MAX_CHARS];
    IPQ_REDZONE_DEF(6);
    int cause;

    unsigned int ue_addr;

    char mnc[MNC_MAX_CHARS];
    IPQ_REDZONE_DEF(7);
    char mcc[MCC_MAX_CHARS];
    IPQ_REDZONE_DEF(8);
    int lac, rac;
    int cid, sac;

    int arp, delay_class, reliability_class, precedence;
    string traffic_class;
    IPQ_REDZONE_DEF(9);
    int thp;

    int max_ul, max_dl;
    int gbr_ul, gbr_dl;

    int sdu;
    IPQ_REDZONE_DEF(10);
    bool teardownInd;

};

int DecodeIMSI_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

int DecodeIMEISV_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

int DecodeMSISDN_IE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg);

// Micheal Lawless commented commented this out in the .cc file - comment by Luke Potter
//int DecodePDPContext_IE(unsigned char *p, int pos, int datalen);

unsigned int ReadMaxBitrate(unsigned int i);

unsigned int ReadExtensionBitrate(unsigned int i);

int DecodeIE(unsigned char *p, int pos, int datalen, struct DecodedMsg *pmsg) ;

#endif
