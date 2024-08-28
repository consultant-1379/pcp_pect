/*
 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#include "GTPv1_packetFields.h"
#include <iostream>

using std::cerr;
using std::endl;

int PDPSession::instanceCounter = 0;
int PDPSession::deleteCounter = 0;

void UpdatePDPContextInfo_t::init() {
    direction = UNKNOWN;
    locationInfo.init();
    sgsn_c = DEFAULT_FTEID;
    sgsn_d = DEFAULT_FTEID;
    ggsn_c = DEFAULT_FTEID;
    ggsn_d = DEFAULT_FTEID;
    qosInfo = PDPQOSInfo();
    strcpy(rat, EMPTY_INT_STRING);
    rat[RAT_MAX_CHARS - 1] = '\0';
    ratPresent = 0;
    bzero(imsi, IMSI_MAX_CHARS);
    strcpy(imsi, IMSI_INIT_STRING);
    imsiPresent = 0;
    dtFlag = 0;
    nsapi = -1;
    ue_addr = 0;
}

void PDPLocationInfo_t::init() {
    memset(this, -1, sizeof(PDPLocationInfo_t));
    strcpy(mcc, MCC_INIT_STRING);
    strcpy(mnc, MNC_INIT_STRING);
}

void PDPQOSInfo_t::init() {
    arp = -1;
    delay_class = -1;
    reliability_class = -1;
    precedence = -1;
    thp = -1;
    max_ul = -1;
    max_dl = -1;
    gbr_ul = -1;
    gbr_dl = -1;
    string traffic_class = EMPTY_INT_STRING;
    sdu = -1;
}

void PDPSession::init() {
    initRedZone();
    pthread_mutex_init(&(pdpSessionMutex), 0);
    startTime = 0;
    touch = 0;
    bzero(imsi, IMSI_MAX_CHARS);
    strcpy(imsi, IMSI_INIT_STRING);
    pdn_cause = -1;
    update_cause = 0;
    bzero(msisdn, MSISDN_MAX_CHARS);
    strcpy(msisdn, MSISDN_INIT_STRING);
    //efitleo :eqev-5831
    strcpy(pdp_type, "unknown");
    pdp_type[PDN_TYPE_MAX_CHARS - 1] = '\0';
    strcpy(rat, EMPTY_INT_STRING);
    rat[RAT_MAX_CHARS - 1] = '\0';
    nsapi = -1;
    linkedNSAPI = -1;
    bzero(imei, IMEI_MAX_CHARS);
    strcpy(imei, IMEI_INIT_STRING);
    ue_addr = 0;
    locationInfo.init();
    dtflag = 0;
    status = INITIALIZED;
    bzero(&userPlaneTunnelId, sizeof(struct UserPlaneTunnelId));
    qosInfo.init();
    teardownInd = false;
    sgsn_c = DEFAULT_FTEID;
    ggsn_c = DEFAULT_FTEID;
    sequenceNumbers.clear();
    loadedFromCache = 0;
}

//Selectively apply the staging area

void PDPSession::applyStagingArea(const UpdatePDPContextInfo_t *updateInfo) {
    sgsn_c = updateInfo->sgsn_c;
    ggsn_c = updateInfo->ggsn_c;
    userPlaneTunnelId.teids[SGSN] = updateInfo->sgsn_d;
    userPlaneTunnelId.teids[GGSN] = updateInfo->ggsn_d;

    if(updateInfo->imsiPresent != 0) {
        strcpy(imsi, updateInfo->imsi);
    }

    dtflag = updateInfo->dtFlag;
    ue_addr = updateInfo->ue_addr == 0 ? ue_addr : updateInfo->ue_addr;

    if(updateInfo->ratPresent != 0) {
        strcpy(rat, updateInfo->rat);
    }

    const PDPLocationInfo_t *updateLocInfo = &updateInfo->locationInfo;
    const PDPQOSInfo_t *updateQOSInfo = &updateInfo->qosInfo;

    if(strcmp(updateLocInfo->mcc, MCC_INIT_STRING)) {  // If they aren't matching
        strcpy(locationInfo.mcc, updateLocInfo->mcc);
    }

    if(strcmp(updateLocInfo->mnc, MNC_INIT_STRING)) {
        strcpy(locationInfo.mnc, updateLocInfo->mnc);
    }

    locationInfo.cid = (updateLocInfo->cid == -1 ? locationInfo.cid : updateLocInfo->cid);
    locationInfo.lac = (updateLocInfo->lac == -1 ? locationInfo.lac : updateLocInfo->lac);
    locationInfo.rac = (updateLocInfo->rac == -1 ? locationInfo.rac : updateLocInfo->rac);
    locationInfo.sac = (updateLocInfo->sac == -1 ? locationInfo.sac : updateLocInfo->sac);
    qosInfo.arp = (updateQOSInfo->arp == -1 ? qosInfo.arp : updateQOSInfo->arp);
    qosInfo.delay_class = (updateQOSInfo->delay_class == -1 ? qosInfo.delay_class : updateQOSInfo->delay_class);
    qosInfo.gbr_dl = (updateQOSInfo->gbr_dl == -1 ? qosInfo.gbr_dl : updateQOSInfo->gbr_dl);
    qosInfo.gbr_ul = (updateQOSInfo->gbr_ul == -1 ? qosInfo.gbr_ul : updateQOSInfo->gbr_ul);
    qosInfo.max_dl = (updateQOSInfo->max_dl == -1 ? qosInfo.max_dl : updateQOSInfo->max_dl);
    qosInfo.max_ul = (updateQOSInfo->max_ul == -1 ? qosInfo.max_ul : updateQOSInfo->max_ul);
    qosInfo.precedence = (updateQOSInfo->precedence == -1 ? qosInfo.precedence : updateQOSInfo->precedence);
    qosInfo.reliability_class = (updateQOSInfo->reliability_class == -1 ? qosInfo.reliability_class : updateQOSInfo->reliability_class);
    qosInfo.sdu = (updateQOSInfo->sdu == -1 ? qosInfo.sdu : updateQOSInfo->sdu);
    qosInfo.thp = (updateQOSInfo->thp == -1 ? qosInfo.thp : updateQOSInfo->thp);
    qosInfo.traffic_class = (updateQOSInfo->traffic_class == EMPTY_INT_STRING ? qosInfo.traffic_class : updateQOSInfo->traffic_class);
}

std::ostream &operator<<(std::ostream &os, const FTEID &field) {
    os << std::hex << field.addr << "_" << field.teid << "_" << std::fixed << field.time;
    return os;
}

ostream &operator<<(ostream &os, const PDPSession *session) {
    os.precision(3);
    os.setf(std::ios::fixed);
    os << session->startTime << RECORD_DELIMITER;

    if(session->pdn_cause == 128) {
        os << "SUCCESS" << RECORD_DELIMITER;
    } else if(session->pdn_cause == -1) {
        os << "TIMEOUT" << RECORD_DELIMITER;
    } else {
        os << "REJECT" << RECORD_DELIMITER;
    }

    os << session->pdp_type << RECORD_DELIMITER;

    //efitleo : eqev-5180
    if(strlen(session->rat)) {
        os << session->rat << RECORD_DELIMITER;
    } else {
        os << EMPTY_INT_STRING << RECORD_DELIMITER;
    }

    if(session->pdn_cause != 128) {
        //TODO implement array of values
        // get value from map print it else print no cause code
        const char *c;

        switch(session->pdn_cause) {
            case 192:
                c = "NON-EXISTENT";
                break;

            case 193:
                c = "INVALID MESSAGE FORMAT";
                break;

            case 194:
                c = "IMSI NOT KNOWN";
                break;

            case 195:
                c = "MS IS GPRS DETACHED";
                break;

            case 196:
                c = "MS IS NOT GPRS RESPONDING";
                break;

            case 197:
                c = "MS REFUSES";
                break;

            case 198:
                c = "VERSION NOT SUPPORTED";
                break;

            case 199:
                c = "NO RESOURCES AVAILABLE";
                break;

            case 200:
                c = "SERVICE NOT SUPPORTED";
                break;

            case 201:
                c = "MANDATORY IE INCORRECT";
                break;

            case 202:
                c = "MANDATORY IE MISSING";
                break;

            case 203:
                c = "OPTIONAL IE INCORRECT";
                break;

            case 204:
                c = "SYSTEM FAILURE";
                break;

            case 205:
                c = "ROAMING RESTRICTION";
                break;

            case 206:
                c = "P-TMSI SIGNATURE MISMATCH";
                break;

            case 207:
                c = "GPRS CONNECTION SUSPENDED";
                break;

            case 208:
                c = "AUTHENTICATION FAILURE";
                break;

            case 209:
                c = "USER AUTHENTICATION FAILED";
                break;

            case 210:
                c = "CONTEXT NOT FOUND";
                break;

            case 211:
                c = "ALL DYNAMIC PDP ADDRESSES ARE OCCUPIED";
                break;

            case 212:
                c = "NO MEMORY IS AVAILABLE";
                break;

            case 213:
                c = "RELOCATION FAILURE";
                break;

            case 214:
                c = "UNKNOWN MANDATORY EXTENSION HEADER";
                break;

            case 215:
                c = "SEMANTIC ERROR IN THE TFT OPERATION";
                break;

            case 216:
                c = "SYNTACTIC ERROR IN THE TFT OPERATION";
                break;

            case 217:
                c = "SEMANTIC ERRORS IN PACKET FILTERS";
                break;

            case 218:
                c = "SYNTACTIC ERRORS IN PACKET FILTERS";
                break;

            case 219:
                c = "MISSING OR UNKNOWN APN";
                break;

            case 220:
                c = "UNKNOWN PDP ADDRESS OR PDP TYPE";
                break;

            case 221:
                c = "PDP CONTEXT WITHOUT TFT ALREADY ACTIVATED";
                break;

            case 222:
                c = "APN ACCESS DENIED - NO SUBSCRIPTION";
                break;

            case 223:
                c =
                    "APN RESTRICTION TYPE INCOMPATIBILITY WITH CURRENTLY ACTIVE PDP CONTEXTS";
                break;

            case 224:
                c = "MS MBMS CAPABILITIES INSUFFICIENT";
                break;

            case 225:
                c = "INVALID CORRELATION-ID";
                break;

            case 226:
                c = "MBMS BEARER CONTEXT SUPERSEDED";
                break;

            case 227:
                c = "BEARER CONTROL MODE VIOLATION";
                break;

            case 228:
                c = "COLLISION WITH NETWORK INITIATED REQUEST";
                break;

            case 229:
                c = "APN CONGESTION";
                break;

            case 230:
                c = "BEARER HANDLING NOT SUPPORTED";
                break;

            default:
                c = "INVALID CAUSE CODE";
                break;
        }

        os << c << RECORD_DELIMITER;
    } else {
        os << "NOCAUSECODE" << RECORD_DELIMITER;
    }

    os << session->locationInfo.mcc << RECORD_DELIMITER;
    os << session->locationInfo.mnc << RECORD_DELIMITER;
    os << printIFGE0(session->locationInfo.lac, RECORD_DELIMITER);
    os << printIFGE0(session->locationInfo.rac, RECORD_DELIMITER);
    os << printIFGE0(session->locationInfo.cid, RECORD_DELIMITER);
    os << printIFGE0(session->locationInfo.sac, RECORD_DELIMITER);
    os << session->imsi << RECORD_DELIMITER;
    os << session->imei << RECORD_DELIMITER;
    os << IPAddress(session->userPlaneTunnelId.teids[GGSN].addr)
       << RECORD_DELIMITER;
    os << session->apn << RECORD_DELIMITER;
    os << session->msisdn << RECORD_DELIMITER;
    os << session->nsapi << RECORD_DELIMITER;
    os << IPAddress(session->ue_addr) << RECORD_DELIMITER;
    os << printIFGE0(session->qosInfo.arp, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.delay_class, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.reliability_class, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.precedence, RECORD_DELIMITER);
    os
            << (session->qosInfo.traffic_class.empty() ?
                EMPTY_INT_STRING : session->qosInfo.traffic_class)
            << RECORD_DELIMITER;
    os << printIFGE0(session->qosInfo.thp, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.max_ul, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.max_dl, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.gbr_ul, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.gbr_dl, RECORD_DELIMITER);
    os << printIFGE0(session->qosInfo.sdu, RECORD_DELIMITER);
    os << printIFGE0(session->dtflag, RECORD_DELIMITER);
    //used to have the same number of fields in V1 and V2 Michael Lawless 07/08/2012
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //ecgi
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //default_bearer_id
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //mme.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //mme.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //sgw_c.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //sgw_c.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER;        //sgw_d.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //enb.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //enb.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER;         //sreq_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER;             //paging_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER;            //time_update_request
    os << EMPTY_INT_STRING << RECORD_DELIMITER;           //time_update_response
    os << EMPTY_INT_STRING << RECORD_DELIMITER;             //update_cause
    return os;
}

std::ostream &operator<<(std::ostream &os, const struct UserPlaneTunnelId &userPlaneTunnelId) {
    os << userPlaneTunnelId.teids[SGSN] << "," << userPlaneTunnelId.teids[GGSN];
    return os;
}

string debugPDPSession(PDPSession *session) {
    std::stringstream ss;
    ss << "BEFORE : sgsn_c[" << session->sgsn_c << "] ggsn_c[" << session->ggsn_c << "] upTEID[" << session->userPlaneTunnelId << "]\n";
    //ss << "STAGING: sgsn_c[" << session->updateStagingArea.sgsn_c << "] ggsn_c[" << session->updateStagingArea.ggsn_c << "] upTEID[" << session->updateStagingArea.sgsn_d << "," << session->updateStagingArea.ggsn_d
    //		<< "] direction[ " << session->updateStagingArea.direction << "]\n";
    ss << "HISTORY (recent first, max 10): ";
    auto it = session->sequenceNumbers.rbegin();
    int count = 0;
    while(it != session->sequenceNumbers.rend() && count < 10) {
    	ss << " {" << *it << "} ";
    	it++;
    	count++;
    }
    return ss.str();
}

bool operator==(const FTEID &lhs, const FTEID &rhs) {
    return lhs.addr == rhs.addr && lhs.teid == rhs.teid;
}

bool operator!=(const FTEID &lhs, const FTEID &rhs) {
    return !(lhs == rhs);
}

std::ostream &operator<<(std::ostream &os, const SequenceNumber_t &sequenceNumber) {
    os << "(" << (unsigned int) sequenceNumber.messageType << "|" << sequenceNumber.src_addr << ":" << sequenceNumber.src_port << "|" << sequenceNumber.dst_addr << ":"
       << sequenceNumber.dst_port << "|" << sequenceNumber.sequenceNumber << "|" << sequenceNumber.teid << "|" << std::fixed << sequenceNumber.time << ")";
    return os;
}

// esirich: DEFTFTS-1825 convert TBCD to ASCII digits -- see ETSI ETR 060
static const char *tbcd = "0123456789*#abc\0";

// esirich DEFTFTS-1825 read MCC/MNC as TBCD strings

ostream &getGTPCCaptoolEndingString(ostream &os, const PDPSession *session) {
    if(session->pdn_cause == 128) {              //PDN CAUSE
        os << "SUCCESS" << RECORD_DELIMITER_13A_CAPTOOL;
    } else if(session->pdn_cause == -1) {
        os << "TIMEOUT" << RECORD_DELIMITER_13A_CAPTOOL;
    } else {
        os << "REJECT" << RECORD_DELIMITER_13A_CAPTOOL;
    }

    //PDN TYPE
    os << session->pdp_type << RECORD_DELIMITER_13A_CAPTOOL;

    //CAUSE
    if(session->pdn_cause != 128) {
        //TODO implement array of values
        // get value from map print it else print no cause code
        const char *c;

        switch(session->pdn_cause) {
            case 192:
                c = "NON-EXISTENT";
                break;

            case 193:
                c = "INVALID MESSAGE FORMAT";
                break;

            case 194:
                c = "IMSI NOT KNOWN";
                break;

            case 195:
                c = "MS IS GPRS DETACHED";
                break;

            case 196:
                c = "MS IS NOT GPRS RESPONDING";
                break;

            case 197:
                c = "MS REFUSES";
                break;

            case 198:
                c = "VERSION NOT SUPPORTED";
                break;

            case 199:
                c = "NO RESOURCES AVAILABLE";
                break;

            case 200:
                c = "SERVICE NOT SUPPORTED";
                break;

            case 201:
                c = "MANDATORY IE INCORRECT";
                break;

            case 202:
                c = "MANDATORY IE MISSING";
                break;

            case 203:
                c = "OPTIONAL IE INCORRECT";
                break;

            case 204:
                c = "SYSTEM FAILURE";
                break;

            case 205:
                c = "ROAMING RESTRICTION";
                break;

            case 206:
                c = "P-TMSI SIGNATURE MISMATCH";
                break;

            case 207:
                c = "GPRS CONNECTION SUSPENDED";
                break;

            case 208:
                c = "AUTHENTICATION FAILURE";
                break;

            case 209:
                c = "USER AUTHENTICATION FAILED";
                break;

            case 210:
                c = "CONTEXT NOT FOUND";
                break;

            case 211:
                c = "ALL DYNAMIC PDP ADDRESSES ARE OCCUPIED";
                break;

            case 212:
                c = "NO MEMORY IS AVAILABLE";
                break;

            case 213:
                c = "RELOCATION FAILURE";
                break;

            case 214:
                c = "UNKNOWN MANDATORY EXTENSION HEADER";
                break;

            case 215:
                c = "SEMANTIC ERROR IN THE TFT OPERATION";
                break;

            case 216:
                c = "SYNTACTIC ERROR IN THE TFT OPERATION";
                break;

            case 217:
                c = "SEMANTIC ERRORS IN PACKET FILTERS";
                break;

            case 218:
                c = "SYNTACTIC ERRORS IN PACKET FILTERS";
                break;

            case 219:
                c = "MISSING OR UNKNOWN APN";
                break;

            case 220:
                c = "UNKNOWN PDP ADDRESS OR PDP TYPE";
                break;

            case 221:
                c = "PDP CONTEXT WITHOUT TFT ALREADY ACTIVATED";
                break;

            case 222:
                c = "APN ACCESS DENIED - NO SUBSCRIPTION";
                break;

            case 223:
                c =
                    "APN RESTRICTION TYPE INCOMPATIBILITY WITH CURRENTLY ACTIVE PDP CONTEXTS";
                break;

            case 224:
                c = "MS MBMS CAPABILITIES INSUFFICIENT";
                break;

            case 225:
                c = "INVALID CORRELATION-ID";
                break;

            case 226:
                c = "MBMS BEARER CONTEXT SUPERSEDED";
                break;

            case 227:
                c = "BEARER CONTROL MODE VIOLATION";
                break;

            case 228:
                c = "COLLISION WITH NETWORK INITIATED REQUEST";
                break;

            case 229:
                c = "APN CONGESTION";
                break;

            case 230:
                c = "BEARER HANDLING NOT SUPPORTED";
                break;

            default:
                c = "INVALID CAUSE CODE";
                break;
        }

        os << c << RECORD_DELIMITER_13A_CAPTOOL;
    } else {
        os << "NOCAUSECODE" << RECORD_DELIMITER_13A_CAPTOOL;
    }

    //GGSN address
    os << IPAddress(session->userPlaneTunnelId.teids[GGSN].addr)
       << RECORD_DELIMITER_13A_CAPTOOL;
    os << session->msisdn << RECORD_DELIMITER_13A_CAPTOOL;
    os << session->nsapi << RECORD_DELIMITER_13A_CAPTOOL;
    os << IPAddress(session->ue_addr) << RECORD_DELIMITER_13A_CAPTOOL;
    os << printIFGE0(session->qosInfo.arp, RECORD_DELIMITER_13A_CAPTOOL);
    os
            << printIFGE0(session->qosInfo.delay_class,
                          RECORD_DELIMITER_13A_CAPTOOL);
    os
            << printIFGE0(session->qosInfo.reliability_class,
                          RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.precedence, RECORD_DELIMITER_13A_CAPTOOL);
    os
            << (session->qosInfo.traffic_class.empty() ?
                EMPTY_INT_STRING : session->qosInfo.traffic_class)
            << RECORD_DELIMITER_13A_CAPTOOL;
    os << printIFGE0(session->qosInfo.thp, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.max_ul, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.max_dl, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.gbr_ul, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.gbr_dl, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->qosInfo.sdu, RECORD_DELIMITER_13A_CAPTOOL);
    os << printIFGE0(session->dtflag, RECORD_DELIMITER_13A_CAPTOOL);
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //ecgi
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;  //default_bearer_id
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //mme.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //mme.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //sgw_c.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //sgw_c.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;        //sgw_d.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //enb.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //enb.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;         //sreq_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;        //paging_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL; //time_update_request
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL; //time_update_response
    os << EMPTY_INT_STRING;             //update_cause
    return os;
}

ostream &getGTPCCaptoolMiddleString(ostream &os, const PDPSession *session) {
    // Not thread safe.  Only called by the single threaded captool file writer
    static char tac[TAC_MAX_CHARS];
    static char sv[SV_MAX_CHARS];
    memcpy(tac, session->imei, TAC_MAX_CHARS - 1);
    tac[TAC_MAX_CHARS - 1] = '\0';
    memcpy(sv, &(session->imei[IMEI_MAX_CHARS - SV_MAX_CHARS]), SV_MAX_CHARS); // Copy includes null terminator
    sv[SV_MAX_CHARS - 1] = '\0';
    os << session->imsi << RECORD_DELIMITER_13A_CAPTOOL; //IMSI
    os << tac << RECORD_DELIMITER_13A_CAPTOOL; //IMEISV (TAC)
    os << sv << RECORD_DELIMITER_13A_CAPTOOL; //IMEISV (SV)
    os << session->apn << RECORD_DELIMITER_13A_CAPTOOL; //APN

    //efitleo : eqev-5831
    if(strlen(session->rat)) {                  //RAT
        os << session->rat << RECORD_DELIMITER_13A_CAPTOOL;
    } else {
        os << EMPTY_INT_STRING << RECORD_DELIMITER_13A_CAPTOOL;
    }

    os << session->locationInfo.mcc << ":" << session->locationInfo.mnc << ":"
       << printIFGE0(session->locationInfo.lac, ":")
       << printIFGE0(session->locationInfo.cid,
                     RECORD_DELIMITER_13A_CAPTOOL); //CGI(MCC:MNC:LAC:CI)
    os << session->locationInfo.mcc << ":" << session->locationInfo.mnc << ":"
       << printIFGE0(session->locationInfo.lac, ":")
       << printIFGE0(session->locationInfo.sac,
                     RECORD_DELIMITER_13A_CAPTOOL); //SAI (MCC:MNC:LAC:SAC)
    os << session->locationInfo.mcc << ":" << session->locationInfo.mnc << ":"
       << printIFGE0(session->locationInfo.lac, ":")
       << printIFGE0(session->locationInfo.rac, ""); //RAI MCC:MNC:LAC:RAC
    return os;
}

ostream &getGTPCStapleEndingString(ostream &os, const PDPSession *session) {
    if(session->pdn_cause == 128) {  //PDN CAUSE
        os << "SUCCESS" << RECORD_DELIMITER_13A;
    } else if(session->pdn_cause == -1) {
        os << "TIMEOUT" << RECORD_DELIMITER_13A;
    } else {
        os << "REJECT" << RECORD_DELIMITER_13A;
    }

    //PDN TYPE
    os << session->pdp_type << RECORD_DELIMITER_13A;

    //RAT
    //efitleo : eqev-5180
    if(strlen(session->rat)) {                 //RAT
        os << session->rat << RECORD_DELIMITER_13A;
    } else {
        os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;
    }

    //CAUSE
    if(session->pdn_cause != 128) {
        //TODO implement array of values
        // get value from map print it else print no cause code
        const char *c;

        switch(session->pdn_cause) {
            case 192:
                c = "NON-EXISTENT";
                break;

            case 193:
                c = "INVALID MESSAGE FORMAT";
                break;

            case 194:
                c = "IMSI NOT KNOWN";
                break;

            case 195:
                c = "MS IS GPRS DETACHED";
                break;

            case 196:
                c = "MS IS NOT GPRS RESPONDING";
                break;

            case 197:
                c = "MS REFUSES";
                break;

            case 198:
                c = "VERSION NOT SUPPORTED";
                break;

            case 199:
                c = "NO RESOURCES AVAILABLE";
                break;

            case 200:
                c = "SERVICE NOT SUPPORTED";
                break;

            case 201:
                c = "MANDATORY IE INCORRECT";
                break;

            case 202:
                c = "MANDATORY IE MISSING";
                break;

            case 203:
                c = "OPTIONAL IE INCORRECT";
                break;

            case 204:
                c = "SYSTEM FAILURE";
                break;

            case 205:
                c = "ROAMING RESTRICTION";
                break;

            case 206:
                c = "P-TMSI SIGNATURE MISMATCH";
                break;

            case 207:
                c = "GPRS CONNECTION SUSPENDED";
                break;

            case 208:
                c = "AUTHENTICATION FAILURE";
                break;

            case 209:
                c = "USER AUTHENTICATION FAILED";
                break;

            case 210:
                c = "CONTEXT NOT FOUND";
                break;

            case 211:
                c = "ALL DYNAMIC PDP ADDRESSES ARE OCCUPIED";
                break;

            case 212:
                c = "NO MEMORY IS AVAILABLE";
                break;

            case 213:
                c = "RELOCATION FAILURE";
                break;

            case 214:
                c = "UNKNOWN MANDATORY EXTENSION HEADER";
                break;

            case 215:
                c = "SEMANTIC ERROR IN THE TFT OPERATION";
                break;

            case 216:
                c = "SYNTACTIC ERROR IN THE TFT OPERATION";
                break;

            case 217:
                c = "SEMANTIC ERRORS IN PACKET FILTERS";
                break;

            case 218:
                c = "SYNTACTIC ERRORS IN PACKET FILTERS";
                break;

            case 219:
                c = "MISSING OR UNKNOWN APN";
                break;

            case 220:
                c = "UNKNOWN PDP ADDRESS OR PDP TYPE";
                break;

            case 221:
                c = "PDP CONTEXT WITHOUT TFT ALREADY ACTIVATED";
                break;

            case 222:
                c = "APN ACCESS DENIED - NO SUBSCRIPTION";
                break;

            case 223:
                c =
                    "APN RESTRICTION TYPE INCOMPATIBILITY WITH CURRENTLY ACTIVE PDP CONTEXTS";
                break;

            case 224:
                c = "MS MBMS CAPABILITIES INSUFFICIENT";
                break;

            case 225:
                c = "INVALID CORRELATION-ID";
                break;

            case 226:
                c = "MBMS BEARER CONTEXT SUPERSEDED";
                break;

            case 227:
                c = "BEARER CONTROL MODE VIOLATION";
                break;

            case 228:
                c = "COLLISION WITH NETWORK INITIATED REQUEST";
                break;

            case 229:
                c = "APN CONGESTION";
                break;

            case 230:
                c = "BEARER HANDLING NOT SUPPORTED";
                break;

            default:
                c = "INVALID CAUSE CODE";
                break;
        }

        os << c << RECORD_DELIMITER_13A;
    } else {
        os << "NOCAUSECODE" << RECORD_DELIMITER_13A;
    }

    os << session->locationInfo.mcc << RECORD_DELIMITER_13A; //MCC
    os << session->locationInfo.mnc << RECORD_DELIMITER_13A; //MNC
    os << printIFGE0(session->locationInfo.lac, RECORD_DELIMITER_13A); //LAC
    os << printIFGE0(session->locationInfo.rac, RECORD_DELIMITER_13A);     //RAC
    os << printIFGE0(session->locationInfo.cid, RECORD_DELIMITER_13A);     //CID
    os << printIFGE0(session->locationInfo.sac, RECORD_DELIMITER_13A);     //SAC
    os << session->imsi << RECORD_DELIMITER_13A; //IMSI
    os << session->imei << RECORD_DELIMITER_13A; //IMEISV (TAC)
    os << IPAddress(session->userPlaneTunnelId.teids[GGSN].addr)
       << RECORD_DELIMITER_13A;     //GGSN address
    os << session->apn << RECORD_DELIMITER_13A; //APN
    os << session->msisdn << RECORD_DELIMITER_13A;
    os << session->nsapi << RECORD_DELIMITER_13A;
    os << IPAddress(session->ue_addr) << RECORD_DELIMITER_13A;
    os << printIFGE0(session->qosInfo.arp, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.delay_class, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.reliability_class, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.precedence, RECORD_DELIMITER_13A);
    os
            << (session->qosInfo.traffic_class.empty() ?
                EMPTY_INT_STRING : session->qosInfo.traffic_class)
            << RECORD_DELIMITER_13A;
    os << printIFGE0(session->qosInfo.thp, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.max_ul, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.max_dl, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.gbr_ul, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.gbr_dl, RECORD_DELIMITER_13A);
    os << printIFGE0(session->qosInfo.sdu, RECORD_DELIMITER_13A);
    os << printIFGE0(session->dtflag, RECORD_DELIMITER_13A);
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //ecgi
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //default_bearer_id
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //mme.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //mme.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //sgw_c.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //sgw_c.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;        //sgw_d.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //enb.addr
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //enb.teid
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;         //sreq_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;             //paging_flag
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;        //time_update_request
    os << EMPTY_INT_STRING << RECORD_DELIMITER_13A;       //time_update_response
    os << EMPTY_INT_STRING;             //update_cause
    return os;
}

void decodeMNC(unsigned char *p, char *mnc) {
    mnc[0] = tbcd[p[1] & 0x0f];
    mnc[1] = tbcd[(p[1] & 0xf0) >> 4];
    mnc[2] = tbcd[(p[0] & 0xf0) >> 4];
    mnc[3] = 0;
}

void decodeMCC(unsigned char *p, char *mcc) {
    mcc[0] = tbcd[p[0] & 0x0f];
    mcc[1] = tbcd[(p[0] & 0xf0) >> 4];
    mcc[2] = tbcd[p[1] & 0x0f];
    mcc[3] = 0;
}

unsigned short extractPortFromPacket(unsigned char *p) {
    return ntohs(*(unsigned short *) p);
}

PacketCounter *PacketCounter::theInstance = 0;

