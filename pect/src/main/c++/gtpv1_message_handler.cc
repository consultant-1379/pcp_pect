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
 * File: gtpv1_message_handler.cc
 * Date: 14 Jan 2014
 * Author: LMI/LXR/ROO/PE Richard Kerr
 ************************************************************************/

/**
 * This module manages the PDPSession related maps, providing functionality to read, modify and delete entries.
 */
#include <memory>
#include <pthread.h>
#include <functional>

#include "gtp_ie.h"
#include "GTPv1_packetFields.h"
#include "gtpv1_maps.h"
#include "UE_map.hpp"
#include "gtpv1_message_utils.h"
#include "gtpv1_message_handler.h"

void deleteMessageData(MessageData_t *messageData) {
    if(messageData != NULL) {
        delete messageData;
    }
}

void handleGTPV1CreatePrimaryPDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    FTEID sgsn;
    sgsn.addr = message->addr1;
    sgsn.teid = message->teid_c;
    sgsn.time = message->timestamp;
    PDPSession *pdpSession = createControlPDPSession(sgsn, message->teid, message->nsapi, message->imsi);

    if(pdpSession == NULL) {  // Couldnt create the session?
        LOG4CXX_WARN(loggerGtpcParser,
                     "handleGTPV1CreatePDPContextRequest: Couldn't create an appropriate PDPContext, ignoring message");
        return;
    }

    pdpSession->checkRedZone();
    pdpSession->status = CREATE_REQUEST_RECEIVED;
    // Fill relevant records
    pdpSession->startTime = message->timestamp;
    pdpSession->sgsn_c = sgsn;

    if(message->imei[0] != 0) {
        memcpy(pdpSession->imei, message->imei, IMEI_MAX_CHARS);
        pdpSession->imei[IMEI_MAX_CHARS - 1] = '\0';
    }

    pdpSession->checkRedZone();

    if(message->rat_present) {
        snprintf(pdpSession->rat, RAT_MAX_CHARS, "%s", message->rat);
        pdpSession->rat[RAT_MAX_CHARS - 1] = '\0';
    }

    if(message->teid == 0) {
        snprintf(pdpSession->pdp_type, PDN_TYPE_MAX_CHARS, "GPRS_PRIMARY");
    } else {
        snprintf(pdpSession->pdp_type, PDN_TYPE_MAX_CHARS, "GPRS_SECONDARY");
        LOG4CXX_INFO(loggerGtpcParser, "createPDPContextRequest: Secondary PDP context being created");
    }

    pdpSession->checkRedZone();
    FillLoc(pdpSession, message);
    pdpSession->nsapi = message->nsapi;
    pdpSession->linkedNSAPI = message->linked_nsapi;
    pdpSession->checkRedZone();
    message->apn[APN_MAX_CHARS - 1] = '\0';
    snprintf(pdpSession->apn, APN_MAX_CHARS, "%s", message->apn);
    pdpSession->apn[APN_MAX_CHARS - 1] = '\0';
    pdpSession->checkRedZone();
    memcpy(pdpSession->msisdn, message->msisdn, MSISDN_MAX_CHARS);
    pdpSession->msisdn[MSISDN_MAX_CHARS - 1] = '\0';
    pdpSession->checkRedZone();
    pdpSession->userPlaneTunnelId.teids[SGSN].addr = message->addr2;
    pdpSession->userPlaneTunnelId.teids[SGSN].teid = message->teid_d;
    pdpSession->userPlaneTunnelId.teids[SGSN].time = message->timestamp;
    pdpSession->touch = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->src_addr;
    sequenceNumber.dst_addr = message->dst_addr;
    sequenceNumber.src_port = message->src_port;
    sequenceNumber.dst_port = message->dst_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = sgsn;
    pdpSession->sequenceNumbers.push_back(sequenceNumber); // Keep a history of the messages for this session
    MessageData_t *messageData = new MessageData_t;
    messageData->createInfo = new CreatePDPContextInfo_t;
    messageData->createInfo->isSecondary = false;
    messageData->session = pdpSession;

    if(addSequenceNumber(sequenceNumber, messageData) != 0) {
        LOG4CXX_DEBUG(loggerGtpcParser, "handleGTPV1CreatePDPContextRequest: Error adding session to sequence number tracking (" << sequenceNumber << ")");
    } else {
        stats.pendingCreateResponses++;
        stats.unmatchedCreateRequests++;
    }

    pdpSession->checkRedZone();
    pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
}

//TODO: THIS IS NOT FULLY IMPLEMENTED
// Current implementation just gathers information about the secondary pdp context
void handleGTPV1CreateSecondaryPDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    LOG4CXX_INFO(loggerGtpcParser, "Handling secondary pdp context: " << std::fixed << message->timestamp);
    FTEID teid;
    teid.addr = message->dst_addr;
    teid.teid = message->teid;
    teid.time = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->src_addr;
    sequenceNumber.dst_addr = message->dst_addr;
    sequenceNumber.src_port = message->src_port;
    sequenceNumber.dst_port = message->dst_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = teid;
    PDPSession *session = getControlPDPSession(teid, message->linked_nsapi); // Find the primary PDP context which we are trying to link to

    if(session != NULL) {
        pthread_mutex_unlock(&session->pdpSessionMutex);
    }

    MessageData_t *messageData = new MessageData_t;
    messageData->createInfo = new CreatePDPContextInfo_t;
    messageData->createInfo->isSecondary = true;
    messageData->createInfo->primarySession = session;
    messageData->session = NULL;
    addSequenceNumber(sequenceNumber, messageData);
    stats.pendingCreateResponses++;
}

void handleGTPV1CreatePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    stats.createRequestCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);

    if(message->teid == 0) {
        handleGTPV1CreatePrimaryPDPContextRequest(message, stats);
    } else {
        if(message->teid_c_present == 1) {
            LOG4CXX_INFO(loggerGtpcParser, "handleGTPV1CreatePDPContextRequest: teid!=0, teid_c PRESENT");
        }

        handleGTPV1CreateSecondaryPDPContextRequest(message, stats);
    }

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1CreatePDPContextRequest: Map sizes incorrect.[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests));
        //LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(pdpSession));
    }
}

void handleGTPV1CreatePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    //EEMTS FIX
    if(message->teid == 0) {
        if(message->cause != 128) {
            LOG4CXX_WARN(loggerGtpcMap,
                         "handleGTPV1CreatePDPContextResponse: Cause code indicated CREATE_FAILED (!=128) : message->cause = "
                         << message->cause << ": message->teid =  " << std::hex << message->teid << ": message->src_addr:port = "
                         << message->src_addr << ":" << message->src_port << ": message->dst_addr:port  = " << message->dst_addr
                         << ":" << message->dst_port << std::fixed << ": message->timestamp = " << message->timestamp
                         << " Session will be removed later in this function (seach CREATE_FAILED) ");
        } else {
            LOG4CXX_WARN(loggerGtpcMap,
                         "handleGTPV1CreatePDPContextResponse: Possible Issue with TEID : message->cause = " << message->cause
                         << ": message->teid =  " << std::hex << message->teid << ": message->src_addr:port = " << message->src_addr
                         << ":" << message->src_port << ": message->dst_addr:port  = " << message->dst_addr << ":" << message->dst_port
                         << std::fixed << ": message->timestamp = " << message->timestamp << " .. ignoring message");
            return;
        }
    }

    stats.createResponseCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);
    FTEID sgsn;
    sgsn.addr = message->dst_addr;
    sgsn.teid = message->teid;
    sgsn.time = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->dst_addr;
    sequenceNumber.dst_addr = message->src_addr;
    sequenceNumber.src_port = message->dst_port;
    sequenceNumber.dst_port = message->src_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = sgsn;
    MessageData_t *messageData = getSequenceNumber(sequenceNumber);

    if(messageData == NULL) {
        stats.createResponseUnmatchedSeqCount++;
        // Unexpected response, increment a counter and log the error
        LOG4CXX_DEBUG(loggerGtpcParser, "CreatePDPContextResponse: Unable to find a matching sequence number ("
                      << std::hex << sequenceNumber.sequenceNumber << ", " << message->src_addr << ":" << message->src_port << "->" << message->dst_addr << ":" << message->dst_port << ", " << std::fixed
                      << sequenceNumber.time << "), ignoring message");
        return;
    }

    // TODO: Temporary handling of secondary pdp context, does nothing other than printing messages
    if(messageData->createInfo != NULL && messageData->createInfo->isSecondary) {
        LOG4CXX_INFO(loggerGtpcParser, "CreatePDPContextResponse: SecondaryPDPContext, session not created: Cause(" << message->cause << ") Primary Session(" << (void *)messageData->createInfo->primarySession
                     << ")");
        deleteMessageData(messageData);
        stats.pendingCreateResponses--;
        return;
    }

    PDPSession *session = messageData->session;
    deleteMessageData(messageData);
    lockPDPSession(session);
    session->checkRedZone();
    session->sequenceNumbers.push_back(sequenceNumber);

    if(sgsn != session->sgsn_c) {
        // sgsn teid doesn't match... something is wrong!
        LOG4CXX_ERROR(loggerGtpcParser, "CreatePDPContextResponse TEID " << sgsn << " doesn't match for expected PDP Session "
                      << session->sgsn_c << ", ignoring message");
        stats.pendingCreateResponses--;
        return;
    }

    if(session->status != CREATE_REQUEST_RECEIVED) {
        // We aren't expecting a Create Response at this stage, log some information
        LOG4CXX_ERROR(loggerGtpcParser,
                      "CreatePDPContextResponse: Session not expecting response, ignoring message");
    }

    if(message->cause != 128) {
        // Failed message
        // Increment counter, log message?, remove 'sgsn' from tracking
        session->status = CREATE_FAILED;
        //EEMTS
        LOG4CXX_DEBUG(loggerGtpcParser, "CreatePDPContextResponse: CREATE_FAILED for PDP Session TEID " << sgsn
                      << ": pdpSession->status = " << session->status
                      << ": message->cause = " << message->cause
                      << ": pdpSession->sequenceNumbers.back() = " << session->sequenceNumbers.back());
        //pthread_mutex_unlock(&pdpSession->pdpSessionMutex);  //EEMTS FIX
        deleteSinglePDPSession(session);
        stats.pendingCreateResponses--;
        stats.unmatchedCreateRequests--;
        stats.failedCreateCount++;
        return;
    }

    // Fill in relevant values
    session->ggsn_c.addr = message->addr1;
    session->ggsn_c.teid = message->teid_c;
    session->ggsn_c.time = message->timestamp;
    session->userPlaneTunnelId.teids[GGSN].addr = message->addr2;
    session->userPlaneTunnelId.teids[GGSN].teid = message->teid_d;
    session->userPlaneTunnelId.teids[GGSN].time = message->timestamp;
    session->ue_addr = message->ue_addr;
    session->pdn_cause = message->cause;
    session->touch = message->timestamp;

    if(!(strcmp(message->imei, "\\N000000000000000"))) {
        memcpy(session->imei, message->imei, IMEI_MAX_CHARS);
        session->imei[IMEI_MAX_CHARS - 1] = '\0';
    }

    FillQoS(session, message);
    session->status = CREATED;
    addUserPDPSession(session);
    int ret = associateControlPDPSession(session->sgsn_c, session->ggsn_c);

    if(ret != 0) {
        LOG4CXX_ERROR(loggerGtpcParser,
                      "CreatePDPContextResponse: Unable to associate new TEID (" << session->ggsn_c << ") with existing TEID (" << session->sgsn_c << ")");
    }

    session->checkRedZone();
    pthread_mutex_unlock(&session->pdpSessionMutex);
    stats.pendingCreateResponses--;
    stats.unmatchedCreateRequests--;

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1CreatePDPContextResponse: Map sizes incorrect[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests));
        LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(session));
    }
}

void handleGTPV1UpdatePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    // EEMTS FIX
    if(message->teid == 0) {
        LOG4CXX_WARN(loggerGtpcMap, "handleGTPV1UpdatePDPContextRequest: : Possible Issue with TEID  message->teid =  " << std::hex << message->teid
                     << ": message->src_addr:port = " << message->src_addr << ":" << message->src_port
                     << ": message->dst_addr:port  = " << message->dst_addr << ":" << message->dst_port
                     << std::fixed << ": message->timestamp = " << message->timestamp
                    );
        return;
    }

    stats.updateRequestCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);
    FTEID messageTEID;
    messageTEID.addr = message->dst_addr;
    messageTEID.teid = message->teid;
    messageTEID.time = message->timestamp;
    PDPSession *pdpSession = getControlPDPSession(messageTEID, message->nsapi);

    if(pdpSession == NULL) {
        stats.updateRequestUnmatchedSession++;
        LOG4CXX_TRACE(loggerGtpcParser,
                      "UpdatePDPContextRequest: Matching session not found (" << messageTEID << ")");
        return;
    } else if(pdpSession->status != PDPSessionStatus_t::CREATED
              && pdpSession->status != PDPSessionStatus_t::UPDATED) {
        // Invalid status to be receiving an update request
        LOG4CXX_DEBUG(loggerGtpcParser,
                      "UpdatePDPContextRequest: Matching session is not in an appropriate state (" << pdpSession->status << " | " << messageTEID << ")");
    }

    pdpSession->checkRedZone();
    pdpSession->status = PDPSessionStatus_t::UPDATE_REQUEST_RECEIVED;
    pdpSession->touch = message->timestamp;
    // Populate the MessageData with the appropriate parameters from the message
    MessageData_t *messageData = new MessageData_t;
    messageData->session = pdpSession;
    messageData->updateInfo = new UpdatePDPContextInfo_t;
    UpdatePDPContextInfo_t *updateStagingArea = messageData->updateInfo;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->src_addr;
    sequenceNumber.dst_addr = message->dst_addr;
    sequenceNumber.src_port = message->src_port;
    sequenceNumber.dst_port = message->dst_port;

    if(message->addr1_present) {  // If it is SGSN initiated, populate different fields
        updateStagingArea->direction = MessageDirection_t::SGSN_INITIATED;
        updateStagingArea->sgsn_c.teid = (message->teid_c_present) ? message->teid_c : pdpSession->sgsn_c.teid; // teid_c.teid is an optional field
        updateStagingArea->sgsn_c.addr = message->addr1; // address is mandatory
        updateStagingArea->sgsn_c.time = message->timestamp;
        fillLoc(updateStagingArea->locationInfo, message);
        memcpy(updateStagingArea->rat, message->rat, RAT_MAX_CHARS);
        updateStagingArea->ratPresent = message->rat_present;
        updateStagingArea->sgsn_d.teid = message->teid_d; // teid_d is mandatory
        updateStagingArea->sgsn_d.addr = message->addr2;  // teid_d address is mandatory
        updateStagingArea->sgsn_d.time = message->timestamp;
        sequenceNumber.teid = updateStagingArea->sgsn_c;

        if(messageTEID != pdpSession->ggsn_c) {
            LOG4CXX_ERROR(loggerGtpcParser,
                          "UpdatePDPContextRequest: PDP Session TEID does not match mapped value (" << messageTEID << " | " << pdpSession->ggsn_c << " | " << pdpSession->sgsn_c);
        }

        // EEMTS FIX
        if(updateStagingArea->sgsn_c.teid == 0) { // Error condition
            LOG4CXX_ERROR(loggerGtpcParser,
                          "UpdatePDPContextRequest: PDP Session sgsn_c TEID is zero(" << messageTEID << " | " << pdpSession->ggsn_c << " | " << pdpSession->sgsn_c << " ignoring message");
            updateStagingArea->init();
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
            return;
        }
    } else {
        updateStagingArea->direction = MessageDirection_t::GGSN_INITIATED;
        updateStagingArea->ggsn_c = pdpSession->ggsn_c;
        updateStagingArea->ggsn_d = pdpSession->userPlaneTunnelId.teids[GGSN];
        sequenceNumber.teid = updateStagingArea->ggsn_c;
        updateStagingArea->ue_addr = message->ue_addr;

        if(messageTEID != pdpSession->sgsn_c) {
            LOG4CXX_ERROR(loggerGtpcParser,
                          "UpdatePDPContextRequest: PDP Session TEID does not match mapped value (" << messageTEID << " | " << pdpSession->ggsn_c << " | " << pdpSession->sgsn_c);
        }

        // EEMTS FIX
        if(updateStagingArea->ggsn_c.teid == 0) { // Error condition
            LOG4CXX_ERROR(loggerGtpcParser,
                          "UpdatePDPContextRequest: PDP Session ggsn_c TEID is zero(" << messageTEID << " | " << pdpSession->ggsn_c << " | " << pdpSession->sgsn_c << " ignoring message");
            deleteMessageData(messageData);
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
            return;
        }
    }

    // Populate the common fields
    updateStagingArea->dtFlag = message->dtflag;

    if(message->imsi_present) {
        strcpy(updateStagingArea->imsi, message->imsi);
        updateStagingArea->imsiPresent = message->imsi_present;
    }

    updateStagingArea->nsapi = message->nsapi;
    fillQoS(updateStagingArea->qosInfo, message);
    // Prepare sequence number and add to the map
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    pdpSession->sequenceNumbers.push_back(sequenceNumber);

    if(addSequenceNumber(sequenceNumber, messageData) != 0) {
        LOG4CXX_DEBUG(loggerGtpcParser, "handleGTPV1UpdatePDPContextRequest: Error adding session to sequence number tracking (" << sequenceNumber << ")");
    } else {
        stats.pendingUpdateResponses++;
    }

    pdpSession->checkRedZone();
    pthread_mutex_unlock(&pdpSession->pdpSessionMutex);

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1UpdatePDPContextRequest: Map sizes incorrect[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests));
        LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(pdpSession));
    }
}

void handleGTPV1UpdatePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    // EEMTS FIX
    if(message->teid == 0) {
        if(message->cause != 128) {
            LOG4CXX_DEBUG(loggerGtpcMap, "handleGTPV1UpdatePDPContextResponse: : Cause code indicated UPDATE_FAILED (!=128) : message->cause = " << message->cause
                          << ": message->teid =  " << std::hex << message->teid
                          << ": message->src_addr:port = " << message->src_addr << ":" << message->src_port
                          << ": message->dst_addr:port  = " << message->dst_addr << ":" << message->dst_port
                          << std::fixed << ": message->timestamp = " << message->timestamp
                          << " .. ignoring message");
        } else {
            LOG4CXX_WARN(loggerGtpcMap, "handleGTPV1UpdatePDPContextResponse: : Possible Issue with TEID  message->cause = " << message->cause
                         << ": message->teid =  " << std::hex << message->teid
                         << ": message->src_addr:port = " << message->src_addr << ":" << message->src_port
                         << ": message->dst_addr:port  = " << message->dst_addr << ":" << message->dst_port
                         << std::fixed << ": message->timestamp = " << message->timestamp
                         << " .. ignoring message");
        }

        return;
    }

    stats.updateResponseCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);
    FTEID messageTEID;
    messageTEID.addr = message->dst_addr;
    messageTEID.teid = message->teid;
    messageTEID.time = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->dst_addr;
    sequenceNumber.dst_addr = message->src_addr;
    sequenceNumber.src_port = message->dst_port;
    sequenceNumber.dst_port = message->src_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = messageTEID;
    MessageData_t *messageData = getSequenceNumber(sequenceNumber);

    if(messageData == NULL) {
        // Unexpected response, increment a counter and log the error
        stats.updateResponseUnmatchedSeqCount++;
        LOG4CXX_DEBUG(loggerGtpcParser,
                      "UpdatePDPContextResponse: Unable to find a matching sequence number  messageTEID = " <<  messageTEID << " ("
                      << std::hex << sequenceNumber.sequenceNumber << ", " << message->src_addr << ":" << message->src_port << "->" << message->dst_addr << ":" << message->dst_port << ", " << std::fixed << sequenceNumber.time << "), ignoring message");
        return;
    }

    UpdatePDPContextInfo_t *updateStagingArea = messageData->updateInfo;

    if(updateStagingArea == NULL) {
        LOG4CXX_DEBUG(loggerGtpcParser, "UpdatePDPContextResponse: UpdateStagingArea NULL. session->sequenceNumbers.back: " << messageData->session->sequenceNumbers.back() << ".  Sequence number re-added.");
        addSequenceNumber(sequenceNumber, messageData); // Re-add the sequence number, possibly an incorrect match!
        return;
    }

    struct PDPSession *pdpSession = messageData->session;

    pdpSession->checkRedZone();

    if(message->cause != 128) {   // Update was not successful
        lockPDPSession(pdpSession);
        deleteMessageData(messageData);
        pdpSession->status = PDPSessionStatus_t::UPDATE_FAILED;
        stats.pendingUpdateResponses--;
        LOG4CXX_DEBUG(loggerGtpcParser, "UdpatePDPContextResponse: UPDATE_FAILED for session (" << messageTEID
                      << " | " << pdpSession->sgsn_c << " | " << pdpSession->ggsn_c << "), staging area rolled back");
        pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        return;
    }

    // else, lets handle the fields different depending if this was SGSN or GGSN initiated
    if(updateStagingArea->direction == MessageDirection_t::SGSN_INITIATED) {
        updateStagingArea->ggsn_c.addr = message->addr1_present ? message->addr1 : pdpSession->ggsn_c.addr;
        updateStagingArea->ggsn_c.teid = message->teid_c_present ? message->teid_c : pdpSession->ggsn_c.teid;
        updateStagingArea->ggsn_c.time = (message->addr1_present || message->teid_c_present) ? message->timestamp : pdpSession->ggsn_c.time;
        updateStagingArea->ggsn_d.addr = message->addr2_present ? message->addr2 : pdpSession->userPlaneTunnelId.teids[GGSN].addr;
        updateStagingArea->ggsn_d.teid = message->teid_d_present ? message->teid_d : pdpSession->userPlaneTunnelId.teids[GGSN].teid;
        updateStagingArea->ggsn_d.time = (message->addr1_present || message->teid_d_present) ? message->timestamp : pdpSession->userPlaneTunnelId.teids[GGSN].time;
    } else if(updateStagingArea->direction == MessageDirection_t::GGSN_INITIATED) {
        updateStagingArea->sgsn_c = pdpSession->sgsn_c;
        updateStagingArea->sgsn_d.addr = message->addr1_present ? message->addr1 : pdpSession->userPlaneTunnelId.teids[SGSN].addr;
        updateStagingArea->sgsn_d.teid = message->teid_d_present ? message->teid_d : pdpSession->userPlaneTunnelId.teids[SGSN].teid;
        updateStagingArea->sgsn_d.time = (message->addr1_present || message->teid_d_present) ? message->timestamp : pdpSession->userPlaneTunnelId.teids[SGSN].time;
        fillLoc(updateStagingArea->locationInfo, message);
    } else {
        // Unknown direction, log an error and return
        // EEMTS FIX
        LOG4CXX_WARN(loggerGtpcMap, "handleGTPV1UpdatePDPContextResponse: Unknown direction : pdpSession->updateStagingArea.direction = " << updateStagingArea->direction
                     << ": message->messageType  = " << std::hex << (unsigned int) message->messageType << ": message->teid =  " << std::hex << message->teid
                     << ": message->src_addr:port = " << message->src_addr << ":" << message->src_port << ": message->dst_addr:port  = " << message->dst_addr
                     << ":" << message->dst_port << std::fixed << ": message->timestamp = " << message->timestamp << ": updateStagingArea->ggsn_c  = "
                     << updateStagingArea->ggsn_c << ": updateStagingArea->sgsn_c  = " << updateStagingArea->sgsn_c << ": Sequence Number Info (incl msg type) = "
                     << pdpSession->sequenceNumbers.back());
        LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(pdpSession));
        return;
    }

    // Common data, GGSN or SGSN initiated updates
    fillQoS(updateStagingArea->qosInfo, message);
    // NO NEED TO LOCK BEFORE THIS
    // All previous calls are read-only (and the sessions shouldn't be modified outside of this thread)
    updateSessionMapping(messageData); // Returns the session locked
    pdpSession->sequenceNumbers.push_back(sequenceNumber);
    pdpSession->touch = message->timestamp;

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1UpdatePDPContextResponse: Map sizes incorrect[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests) << "]");
        LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(pdpSession));
    }

    pdpSession->applyStagingArea(updateStagingArea);
    pdpSession->status = PDPSessionStatus_t::UPDATED;
    pdpSession->checkRedZone();
    pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
    deleteMessageData(messageData);
    stats.pendingUpdateResponses--;
}

void handleGTPV1DeletePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    stats.deleteRequestCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);
    FTEID messageTEID;
    messageTEID.addr = message->dst_addr;
    messageTEID.teid = message->teid;
    messageTEID.time = message->timestamp;
    PDPSession *pdpSession = getControlPDPSession(messageTEID, message->nsapi);

    if(pdpSession == NULL) {
        stats.deleteRequestUnmatchedSession++;
        LOG4CXX_DEBUG(loggerGtpcParser, "DeletePDPContextRequest: Unable to find an active PDP Session");
        return;
    }

    pdpSession->checkRedZone();
    pdpSession->touch = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->src_addr;
    sequenceNumber.dst_addr = message->dst_addr;
    sequenceNumber.src_port = message->src_port;
    sequenceNumber.dst_port = message->dst_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = pdpSession->sgsn_c == messageTEID ? pdpSession->ggsn_c : pdpSession->sgsn_c;
    MessageData_t *messageData = new MessageData_t();
    messageData->session = pdpSession;

    if(addSequenceNumber(sequenceNumber, messageData) != 0) {
        LOG4CXX_DEBUG(loggerGtpcParser, "handleGTPV1DeletePDPContextRequest: Error adding session to sequence number tracking (" << sequenceNumber << ")");
    } else {
        stats.pendingDeleteResponses++;
    }

    pdpSession->sequenceNumbers.push_back(sequenceNumber);
    pdpSession->teardownInd = message->teardownInd;
    pdpSession->status = PDPSessionStatus_t::DELETE_REQUEST_RECEIVED;
    pdpSession->checkRedZone();
    pthread_mutex_unlock(&pdpSession->pdpSessionMutex);

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1DeletePDPContextRequest: Map sizes incorrect[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests));
        LOG4CXX_WARN(loggerGtpcParser, debugPDPSession(pdpSession));
    }
}

void handleGTPV1DeletePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats) {
    stats.deleteResponseCount++;
    int mapSize = checkMapSizes(stats.unmatchedCreateRequests);
    FTEID messageTEID;
    messageTEID.addr = message->dst_addr;
    messageTEID.teid = message->teid;
    messageTEID.time = message->timestamp;
    SequenceNumber_t sequenceNumber;
    sequenceNumber.src_addr = message->dst_addr;
    sequenceNumber.dst_addr = message->src_addr;
    sequenceNumber.src_port = message->dst_port;
    sequenceNumber.dst_port = message->src_port;
    sequenceNumber.time = message->timestamp;
    sequenceNumber.messageType = message->messageType;
    sequenceNumber.sequenceNumber = message->sequenceNumber;
    sequenceNumber.teid = messageTEID;
    MessageData_t *messageData = getSequenceNumber(sequenceNumber);

    if(messageData == NULL) {
        stats.deleteResponseUnmatchedSeqCount++;
        LOG4CXX_DEBUG(loggerGtpcParser,
                      "DeletePDPContextResponse: Unable to find a matching sequence number ("
                      << std::hex << sequenceNumber.sequenceNumber << ", " << message->src_addr << ":" << message->src_port << "->" << message->dst_addr << ":" << message->dst_port << ", " << std::fixed << sequenceNumber.time << "), ignoring message");
        return;
    }

    struct PDPSession *pdpSession = messageData->session;

    pdpSession->checkRedZone();

    lockPDPSession(pdpSession); // EEMTS FIX

    pdpSession->touch = message->timestamp;

    pdpSession->sequenceNumbers.push_back(sequenceNumber);

    pdpSession->status = PDPSessionStatus_t::DELETED;

    if(pdpSession->teardownInd) {
        pthread_mutex_unlock(&pdpSession->pdpSessionMutex); // EEMTS FIX: Locked again in teardownPDNConnection
        teardownPDNConnection(pdpSession);
    } else {
        deleteSinglePDPSession(pdpSession);
    }

    stats.pendingDeleteResponses--;

    if(mapSize != checkMapSizes(stats.unmatchedCreateRequests)) {
        LOG4CXX_WARN(loggerGtpcParser, "handleGTPV1DeletePDPContextResponse: Map sizes incorrect[" << mapSize << "," << checkMapSizes(stats.unmatchedCreateRequests));
    }

    deleteMessageData(messageData);
}

void GTPV1MessageHandlerStats_t::reset() {
    createRequestCount = 0;
    createResponseCount = 0;
    updateRequestCount = 0;
    updateResponseCount = 0;
    deleteRequestCount = 0;
    deleteResponseCount = 0;
    failedCreateCount = 0;
    failedUpdateCount = 0;
    createResponseUnmatchedSeqCount = 0;
    updateResponseUnmatchedSeqCount = 0;
    deleteResponseUnmatchedSeqCount = 0;
    updateRequestUnmatchedSession = 0;
    deleteRequestUnmatchedSession = 0;
}

