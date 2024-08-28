/************************************************************************
 * COPYRIGHT (C) Ericsson 2013                                           *
 * The copyright to the computer program(s) herein is the property       *
 * of Telefonaktiebolaget LM Ericsson.                                   *
 * The program(s) may be used and/or copied only with the written        *
 * permission from Telefonaktiebolaget LM Ericsson or in accordance with *
 * the terms and conditions stipulated in the agreement/contract         *
 * under which the program(s) have been supplied.                        *
 *************************************************************************
 *************************************************************************
 * File: gtpv1_maps.cc
 * Date: 13 Jan 2014
 * Author: LMI/LXR/ROO/PE Richard Kerr
 ************************************************************************/

/**
 * This module manages the PDPSession related maps, providing functionality to read, modify and delete entries.
 */

#ifndef GTPV1_MAPS_H_
#define GTPV1_MAPS_H_

#include "GTPv1_packetFields.h"
#include "gtpv1_utils.h"

#define ASSOCIATE_OLD_SESSION_DOESNT_EXIST 1
#define ASSOCIATE_NSAPI_MAP_NULL 2

// Used to map control plane tunnels to a collection of PDPSessions, uniquely identified by NSAPI
typedef std::tr1::unordered_map<int, struct PDPSession *> NSAPIMap_t;
typedef std::tr1::unordered_map<struct FTEID, NSAPIMap_t *, dataeq, dataeq> ControlPDPSessionMap_t;

// Matches user plane tunnel endpoints (i.e. both ends) to the relevant PDPSession
typedef std::tr1::unordered_map<struct UserPlaneTunnelId, struct PDPSession *, UserPlaneTunnelIdOperators_t, UserPlaneTunnelIdOperators_t> UserPDPSessionMap_t;

// Used to match 'response' type messages to the relevant requests
typedef std::tr1::unordered_map<SequenceNumber_t, MessageData_t *, struct SequenceNumberEq, struct SequenceNumberEq> SequenceNumberMap_t;

struct PDPSession *createControlPDPSession(FTEID &teid_c, unsigned int &messageTEID, int &nsapi, char *imsi);
int associateControlPDPSession(FTEID &oldFTEID, FTEID &newFTEID);
struct PDPSession *getControlPDPSession(const FTEID &teid, const int &nsapi);
int updateSessionMapping(MessageData_t *messageData);
struct PDPSession *getUserPDPSession(const struct UserPlaneTunnelId &searchStruct);
void removePDPSession(struct PDPSession *pdpSession);
void addUserPDPSession(struct PDPSession *pdpSession);
void deleteSinglePDPSession(struct PDPSession *session);
void teardownPDNConnection(struct PDPSession *session);
void lockPDPSession(struct PDPSession *session);
void logGTPCMapStatistics();
int checkMapSizes(int pendingCreate);
void timeoutGTPSessions(const time_t &lastPacketTime, const EArgs &eargs);
int addSequenceNumber(const SequenceNumber_t &seqNumber, MessageData_t *messageData);
MessageData_t *getSequenceNumber(SequenceNumber_t &seqNumber);
void *gtpcWriteTimer(void *init);
int addPDPSession(PDPSession *session);
void writeGtpcCache();

#endif
