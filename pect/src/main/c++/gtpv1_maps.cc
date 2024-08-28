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

#include <boost/tr1/unordered_map.hpp>
#include <sys/prctl.h>
#include <set>
#include <iomanip>

#include "gtpv1_maps.h"
#include "GTPv1_packetFields.h"
#include "UE_map.hpp"
#include "flow.h"
#include "gtpv1_message_handler_types.h"
#include "gtpc_map_serialisation_utils.h"
#include <float.h>

ControlPDPSessionMap_t controlPDPSessionMap;
UserPDPSessionMap_t userPDPSessionMap;
SequenceNumberMap_t expectedSequenceNumberMap;

pthread_mutex_t controlPDPSessionMapMutex;

extern GTPV1MessageHandlerStats_t messageHandlerStats;

void logGTPCMapStatistics() {
    LOG4CXX_INFO(loggerGtpcParser,
                 "controlPDPSessionMap: size(" << controlPDPSessionMap.size() << ")");
    LOG4CXX_INFO(loggerGtpcParser,
                 "userPDPSessionMap: size(" << userPDPSessionMap.size() << ")");
}

// Used for debugging
int checkMapSizes(int pendingCreate) {
    return ((int)userPDPSessionMap.size() * 2) - (int)controlPDPSessionMap.size() + pendingCreate ;
}


int verifyNSAPIMap(const FTEID &sgsnTEID, const FTEID &ggsnTEID,
                   const NSAPIMap_t *nsapiMap) {
    for(auto it = nsapiMap->begin(); it != nsapiMap->end(); it++) {
        if(it->second->sgsn_c != sgsnTEID || it->second->ggsn_c != ggsnTEID) {
            LOG4CXX_DEBUG(loggerGtpcMap, "verifyNSAPIMap: Target NSAPI map not valid for teids " << sgsnTEID << " & " << ggsnTEID);
            return 1;
        }
    }

    return 0;
}

// Used when deleting a session to ensure that the expectedSequenceNumberMap has no invalid entries
void clearExpectedSequenceMap(struct PDPSession *session) {
    MessageData_t *messageData;

    for(auto it = expectedSequenceNumberMap.begin(); it != expectedSequenceNumberMap.end();) {
        messageData = it->second;

        if(messageData->session == session) {
            switch(it->first.messageType) {
                case GTPMessageTypes::CREATE_PDP_CONTEXT_REQUEST:
                    messageHandlerStats.pendingCreateResponses--;
                    messageHandlerStats.unmatchedCreateRequests--;
                    break;

                case GTPMessageTypes::UPDATE_PDP_CONTEXT_REQUEST:
                    messageHandlerStats.pendingUpdateResponses--;
                    break;

                case GTPMessageTypes::DELETE_PDP_CONTEXT_REQUEST:
                    messageHandlerStats.pendingDeleteResponses--;
                    break;

                default:
                    break;
            }

            it = expectedSequenceNumberMap.erase(it);
            delete messageData;
        } else {
            it++;
        }
    }
}
/**
 * Runs a deep delete on the given NSAPIMap_t
 *
 * The given pointer (nsapiMap) is no longer valid after the calling of this function
 */
void deleteNSAPIMap(NSAPIMap_t *nsapiMap) {
    for(auto mapIter = nsapiMap->begin(); mapIter != nsapiMap->end();
            mapIter++) {
        // Make sure that any references to these sessions are also removed
        controlPDPSessionMap.erase(mapIter->second->ggsn_c);
        controlPDPSessionMap.erase(mapIter->second->sgsn_c);
        userPDPSessionMap.erase(mapIter->second->userPlaneTunnelId);
        pthread_mutex_lock(&mapIter->second->pdpSessionMutex); // Get the lock, incase the session is in use
        clearExpectedSequenceMap(mapIter->second);
        delete(mapIter->second);
    }

    delete nsapiMap;
}

// Clears out a complete mapping (both sides of control plane, and all associated user plane mappings)
void teardownPDNConnection(const FTEID &teid) {
    ControlPDPSessionMap_t::iterator it = controlPDPSessionMap.find(teid);

    if(it == controlPDPSessionMap.end()) {
        return;
    }

    FTEID sgsn_c, ggsn_c;
    PDPSession *session;
    NSAPIMap_t *nsapiMap = it->second;

    for(NSAPIMap_t::iterator nsapiIter = nsapiMap->begin();
            nsapiIter != nsapiMap->end(); nsapiIter++) {
        session = nsapiIter->second;
        sgsn_c = session->sgsn_c;
        ggsn_c = session->ggsn_c;
        // Clear out the user plane mapping
        userPDPSessionMap.erase(session->userPlaneTunnelId);
        clearExpectedSequenceMap(session);
        delete session;
    }

    delete nsapiMap;
    controlPDPSessionMap.erase(sgsn_c);
    controlPDPSessionMap.erase(ggsn_c);
}

int addPDPSession(PDPSession *session) {
    // Verify that we have a fully constructed PDP Session, no point adding a half created one.
    if(session->sgsn_c == DEFAULT_FTEID) {
        LOG4CXX_DEBUG(loggerGtpcMap, "addPDPSession: sgsn_c == DEFAULT_FTEID");
        return 1;
    }

    if(session->ggsn_c == DEFAULT_FTEID) {
        LOG4CXX_DEBUG(loggerGtpcMap, "addPDPSession: ggsn_c == DEFAULT_FTEID");
        return 1;
    }

    if(session->userPlaneTunnelId.teids[0] == DEFAULT_FTEID || session->userPlaneTunnelId.teids[1] == DEFAULT_FTEID) {
        LOG4CXX_DEBUG(loggerGtpcMap, "addPDPSession: userPlaneTunnelId == DEFAULT_FTEID");
        return 1;
    }

    NSAPIMap_t *nsapiMap = NULL;
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    ControlPDPSessionMap_t::iterator controlIterator = controlPDPSessionMap.find(session->sgsn_c);

    if(controlIterator != controlPDPSessionMap.end()) {
        nsapiMap = controlIterator->second;

        if(nsapiMap->count(session->nsapi)) {
            LOG4CXX_DEBUG(loggerGtpcMap, "addPDPSession: Conflicting sgsn_c & nsapi found, not added to the control map");
            pthread_mutex_unlock(&controlPDPSessionMapMutex); // EEMTS FIX
            return 1;
        } else if(verifyNSAPIMap(session->sgsn_c, session->ggsn_c, nsapiMap)) {
            LOG4CXX_DEBUG(loggerGtpcMap, "addPDPSession: NSAPIMap verification failed");
            teardownPDNConnection(session->sgsn_c);
            teardownPDNConnection(session->ggsn_c);
            nsapiMap = new NSAPIMap_t;
            controlPDPSessionMap[session->sgsn_c] = nsapiMap;
        }
    } else {
        nsapiMap = new NSAPIMap_t;
        controlPDPSessionMap[session->sgsn_c] = nsapiMap;
    }

    (*nsapiMap)[session->nsapi] = session;
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    associateControlPDPSession(session->sgsn_c, session->ggsn_c);
    addUserPDPSession(session);
    return 0;
}

/**
 * Using the provided ip, teid and nsapi, this function searches the control plane side of the
 * PDP session tracking for the appropriate PDP Session.  If a session matching the given parameters
 * does not exist then the appropriate entries will be added.
 *
 * Returns a LOCKED PDPSession, the user must unlock the mutex when completed
 */
struct PDPSession *createControlPDPSession(FTEID &teid_c,
        unsigned int &messageTEID, int &nsapi, char *imsi) {
    NSAPIMap_t *nsapiMap = NULL;
    bool isSecondaryPDPContext = false;
    bool createNewSession = false;
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    ControlPDPSessionMap_t::iterator controlIterator = controlPDPSessionMap.find(teid_c);

    if(controlIterator != controlPDPSessionMap.end() && messageTEID == 0) {  // Trying to create a new session when one already exists
        LOG4CXX_DEBUG(loggerGtpcMap, "createControlPDPSession: " << controlIterator->second->size() << " conflicting GTPC session(s) found and torn down (" << teid_c << ")");
        deleteNSAPIMap(controlIterator->second); // Teardown existing sessions
        createNewSession = true;
    } else if(controlIterator == controlPDPSessionMap.end()) {  // Nothing exists for this FTEID
        createNewSession = true;
    } else { // messageTeid != 0 && controlIterator != controlPDPSessionMap.end()
        // This will be a secondary PDPContext, need to validate that
        //   1) The other PDPContexts that are in nsapiMap are to do with the same user
        //   2) The linked NSAPI points to a valid session
        //   3) If there is a conflict in the NSAPI, the GGSN should reject the request.  We should teardown the existing session regardless.
        nsapiMap = controlIterator->second;
        isSecondaryPDPContext = true;
    }

    if(createNewSession) {
        nsapiMap = new NSAPIMap_t;
        controlPDPSessionMap[teid_c] = nsapiMap;
    }

    struct PDPSession *pdpSession = NULL;

    NSAPIMap_t::iterator nsapiIterator;

    nsapiIterator = nsapiMap->find(nsapi);

    if(nsapiIterator == nsapiMap->end()) {
        pdpSession = new PDPSession(imsi);
        (*nsapiMap)[nsapi] = pdpSession;
    } else if(isSecondaryPDPContext) {
        // Conflicting NSAPI for secondaryPDPContext
        LOG4CXX_WARN(loggerGtpcMap,
                     "createControlPDPSession: Conflicting NSAPI found for existing PDPSession, tearing down existing session (" << nsapiIterator->second->sgsn_c << "|" << nsapiIterator->second->ggsn_c);
        deleteNSAPIMap(nsapiMap);
        pthread_mutex_unlock(&controlPDPSessionMapMutex);
        return createControlPDPSession(teid_c, messageTEID, nsapi, imsi);
    } else { // This should never happen
        LOG4CXX_ERROR(loggerGtpcMap,
                      "createControlPDPSession: Unknown error creating PDPSession");
    }

    if(pdpSession != NULL) {
        pthread_mutex_lock(&pdpSession->pdpSessionMutex);
    }

    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    return pdpSession;
}



/**
 * Used to associate a new ip/teid combination (newIP, newTEID) to an existing NSAPIMap_t, identified by oldIP and oldTEID
 */
int associateControlPDPSession(FTEID &oldFTEID, FTEID &newFTEID) {
    NSAPIMap_t *nsapiMap = NULL;
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    ControlPDPSessionMap_t::iterator oldIterator = controlPDPSessionMap.find(oldFTEID);

    if(oldIterator != controlPDPSessionMap.end()) {
        nsapiMap = oldIterator->second;
    } else {
        // Critical section
        pthread_mutex_unlock(&controlPDPSessionMapMutex);
        LOG4CXX_DEBUG(loggerGtpcMap, "associateControlPDPSession: Old session does not exist (" << oldFTEID << ")");
        return ASSOCIATE_OLD_SESSION_DOESNT_EXIST;
    }

    if(nsapiMap != NULL) {
        ControlPDPSessionMap_t::iterator newIterator = controlPDPSessionMap.find(newFTEID);

        if(newIterator != controlPDPSessionMap.end()) {
            LOG4CXX_DEBUG(loggerGtpcMap, "associateControlPDPSession: Conflicting entry found for newFTEID (" << newFTEID << "), tearing down control session");
            teardownPDNConnection(newFTEID);
        }

        controlPDPSessionMap[newFTEID] = nsapiMap;
    } else {
        pthread_mutex_unlock(&controlPDPSessionMapMutex); // EEMTS
        LOG4CXX_DEBUG(loggerGtpcMap, "associateControlPDPSession:  NSAPI MAP NULL for newFTEID (" << newFTEID << ")");
        return ASSOCIATE_NSAPI_MAP_NULL;
    }

    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    return EXIT_SUCCESS;
}

/**
 * Finds and returns the appropriate PDP Session, returns NULL if it doesn't exist.
 */
struct PDPSession *getControlPDPSession(const FTEID &searchStruct, const int &nsapi) {
    NSAPIMap_t *nsapiMap = NULL;
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    ControlPDPSessionMap_t::iterator controlIterator =
        controlPDPSessionMap.find(searchStruct);

    if(controlIterator != controlPDPSessionMap.end()) {
        nsapiMap = controlIterator->second;
    }

    NSAPIMap_t::iterator nsapiIterator;
    struct PDPSession *pdpSession = NULL;

    if(nsapiMap != NULL) {
        nsapiIterator = nsapiMap->find(nsapi);

        if(nsapiIterator != nsapiMap->end()) {
            pdpSession = nsapiIterator->second;
            pthread_mutex_lock(&pdpSession->pdpSessionMutex);
        }
    }

    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    return pdpSession;
}

struct PDPSession *getUserPDPSession(const struct UserPlaneTunnelId &searchStruct) {
    struct PDPSession *pdpSession = NULL;
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    UserPDPSessionMap_t::iterator userIterator = userPDPSessionMap.find(
                searchStruct);

    if(userIterator != userPDPSessionMap.end()) {
        pdpSession = userIterator->second;
    }

    if(pdpSession != NULL) {
        pthread_mutex_lock(&pdpSession->pdpSessionMutex);
    }

    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    return pdpSession;
}

void lockPDPSession(struct PDPSession *session) {
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    pthread_mutex_lock(&session->pdpSessionMutex);
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
}

// Adds locking to the above function, for use by external modules (i.e. gtpv1_message_handler)
void teardownPDNConnection(struct PDPSession *session) {
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    pthread_mutex_lock(&session->pdpSessionMutex);
    FTEID sgsn_c, ggsn_c;
    sgsn_c = session->sgsn_c;
    ggsn_c = session->ggsn_c;
    teardownPDNConnection(sgsn_c);
    teardownPDNConnection(ggsn_c);
    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
}

void deleteSession(struct PDPSession *session) {
    NSAPIMap_t *nsapiMap;
    session->checkRedZone();

    if(controlPDPSessionMap.count(session->sgsn_c) > 0) {
        nsapiMap = controlPDPSessionMap.at(session->sgsn_c);
    } else if(controlPDPSessionMap.count(session->ggsn_c) > 0) {
        nsapiMap = controlPDPSessionMap.at(session->ggsn_c);
    } else {
        userPDPSessionMap.erase(session->userPlaneTunnelId);
        clearExpectedSequenceMap(session);
        delete session;
        return;
    }

    if(nsapiMap->count(session->nsapi) && nsapiMap->size() <= 1) {  // If it's the only entry in the map
        teardownPDNConnection(session->sgsn_c); // Delete the whole thing
        teardownPDNConnection(session->ggsn_c);
    } else {
        nsapiMap->erase(session->nsapi);
        userPDPSessionMap.erase(session->userPlaneTunnelId);
        clearExpectedSequenceMap(session);
        delete session;
    }
}


// Public version of above method
void deleteSinglePDPSession(struct PDPSession *session) {
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    deleteSession(session);
    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
}

void addUserPDPSession(struct PDPSession *pdpSession) {
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);

    if(userPDPSessionMap.count(pdpSession->userPlaneTunnelId)) {
        LOG4CXX_DEBUG(loggerGtpcMap, "addUserPDPSession: Conflicting session found and torn down");
        teardownPDNConnection(userPDPSessionMap.at(pdpSession->userPlaneTunnelId));
    }

    userPDPSessionMap[pdpSession->userPlaneTunnelId] = pdpSession;
    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
}

// Checks the given iteratorsNot thread safe, assumes maps are already locked.
// Return value of 1 indicates that the iterators have been invalidated (i.e. there were conflicts), or do not point to a session at all
// Return value of 0 indicates that the iterators have NOT been invalidated, that is to say that the NSAPI map which
// they point to is _valid_ and should be reused.
int prepareDestinationMappings(ControlPDPSessionMap_t::iterator &oldSGSNCIter,
                               ControlPDPSessionMap_t::iterator &oldGGSNCIter) {
    if(oldSGSNCIter != controlPDPSessionMap.end()
            && oldGGSNCIter != controlPDPSessionMap.end()
            && oldGGSNCIter->second == oldSGSNCIter->second
            && verifyNSAPIMap(oldSGSNCIter->first, oldGGSNCIter->first, oldSGSNCIter->second) == 0) {
        return 0;
    }

    if(oldSGSNCIter != controlPDPSessionMap.end()) {  // One of the mappings is wrong
        teardownPDNConnection(oldSGSNCIter->first);
    }

    if(oldGGSNCIter != controlPDPSessionMap.end()) {
        teardownPDNConnection(oldGGSNCIter->first);
    }

    return 1;
}

void removeControlSessionMapping(PDPSession *session) {
    NSAPIMap_t *nsapiMap;
    //ControlPDPSessionMap_t::iterator it = controlPDPSessionMap.find(session->sgsn_c);

    if(controlPDPSessionMap.count(session->sgsn_c) > 0) {
        nsapiMap = controlPDPSessionMap.at(session->sgsn_c);
    } else if(controlPDPSessionMap.count(session->ggsn_c) > 0) {
        nsapiMap = controlPDPSessionMap.at(session->ggsn_c);
    } else {
        return;
    }

    if(nsapiMap->count(session->nsapi) > 0) {
        PDPSession *stored = nsapiMap->at(session->nsapi);

        if(stored == session) {
            nsapiMap->erase(session->nsapi);
        } else {
            LOG4CXX_WARN(loggerGtpcMap, "removeControlSessionMapping: stored session not as expected");
            deleteSession(stored);
        }

        if(nsapiMap->empty()) {
            delete nsapiMap;
            controlPDPSessionMap.erase(session->sgsn_c);
            controlPDPSessionMap.erase(session->ggsn_c);
        }
    }
}


/**
 * NOTE: The session contained in messageData should be UNLOCKED before being
 * passed to this code.
 */
int updateSessionMapping(MessageData_t *messageData) {
    // Critical section
    pthread_mutex_lock(&controlPDPSessionMapMutex);
    UpdatePDPContextInfo_t *updateInfo = messageData->updateInfo;
    PDPSession *session = messageData->session;
    pthread_mutex_lock(&session->pdpSessionMutex);

    if(session->sgsn_c != updateInfo->sgsn_c
            || session->ggsn_c != updateInfo->ggsn_c) {
        // Clear our the existing CP mappings
        removeControlSessionMapping(session);
        // Get the NSAPIMap_t
        ControlPDPSessionMap_t::iterator sgsncIter;
        ControlPDPSessionMap_t::iterator ggsncIter;
        sgsncIter = controlPDPSessionMap.find(updateInfo->sgsn_c);
        ggsncIter = controlPDPSessionMap.find(updateInfo->ggsn_c);
        NSAPIMap_t *nsapiMap;

        if(prepareDestinationMappings(sgsncIter, ggsncIter) == 0) {  // Both point to the same nsapi map
            nsapiMap = sgsncIter->second;

            if(nsapiMap->count(updateInfo->nsapi) > 0) {
                PDPSession *conflictingSession = nsapiMap->at(updateInfo->nsapi);
                // EEMTS FIX
                LOG4CXX_WARN(loggerGtpcMap, "updateSessionMapping: conflicting session for PDP session : sgsn_c = " << conflictingSession->sgsn_c
                             << ": ggsn_c = " << conflictingSession->sgsn_c
                             << ": Sequence Number Info (conflicting session) = " << conflictingSession->sequenceNumbers.back()
                             << ": PDP session sgsn_c = " << session->sgsn_c
                             << ": PDP session ggsn_c = " << session->ggsn_c
                             << ": Sequence Number Info (PDP Session) = " << session->sequenceNumbers.back()
                             << ": Staging Area sgsn_c = " << updateInfo->sgsn_c
                             << ": Staging Area sgsn_c = " << updateInfo->ggsn_c
                            );
                pthread_mutex_lock(&conflictingSession->pdpSessionMutex); // EEMTS FIX
                clearExpectedSequenceMap(conflictingSession);    //EEMTS FIX (moved from below)
                deleteSession(conflictingSession);
                //nsapiMap->erase(session->updateStagingArea.nsapi); // EEMTS FIX  double or free corruption
                //userPDPSessionMap.erase(conflictingSession->userPlaneTunnelId); // EEMTS FIX double or free corruption
                //clearExpectedSequenceMap(conflictingSession); // EEMTS FIX double or free corruption
                //delete conflictingSession; // EEMTS FIX double or free corruption
            }
        } else { // Non 0 return, have to create a new NSAPIMap and add it to the controlPDPSessionMap
            nsapiMap = new NSAPIMap_t;
            controlPDPSessionMap[updateInfo->sgsn_c] = nsapiMap;
            controlPDPSessionMap[updateInfo->ggsn_c] = nsapiMap;
        }

        (*nsapiMap)[updateInfo->nsapi] = session;
    }

    if(session->userPlaneTunnelId.teids[SGSN] != updateInfo->sgsn_d
            || session->userPlaneTunnelId.teids[GGSN] != updateInfo->ggsn_d) {
        userPDPSessionMap.erase(session->userPlaneTunnelId);
        struct UserPlaneTunnelId uptid;
        uptid.teids[SGSN] = updateInfo->sgsn_d;
        uptid.teids[GGSN] = updateInfo->ggsn_d;
        userPDPSessionMap[uptid] = session;
    }

    // Critical section
    pthread_mutex_unlock(&controlPDPSessionMapMutex);
    return 0;
}

struct GTPSessionStats {
    double startTime;
    size_t messageCount;
    GTPSessionStats() {};
    GTPSessionStats(double st, size_t mc) : startTime(st), messageCount(mc) {};
};

// NOT THREAD SAFE!
void timeoutGTPSessions(const time_t &lastPacketTime, const EArgs &args) {
    static time_t lastTimeout = 0;
    // Boundary is 40s past the minute, in an effort to reduce interference with file writer
    time_t lastBoundaryTime = (lastPacketTime - (lastPacketTime % 60)) + 40;
    PDPSession *session;
    NSAPIMap_t *nsapiMap;
    int removedSessionCount = 0, totalSessionCount = 0;
    int nsapiSize = 0;
    std::tr1::unordered_map<size_t, struct GTPSessionStats> sessionTimeMap;

    if(lastBoundaryTime - lastTimeout >= args.gtpcSessionTimeoutFrequency) {
        LOG4CXX_INFO(loggerGtpcMap, "Purging old sessions");
        lastTimeout = lastBoundaryTime;
        pthread_mutex_lock(&controlPDPSessionMapMutex);

        for(auto it = controlPDPSessionMap.begin(); it != controlPDPSessionMap.end();) {
            nsapiMap = it->second;
            nsapiSize = (int)nsapiMap->size();
            totalSessionCount += nsapiSize;
            it++;

            for(auto nsapiIt = nsapiMap->begin(); nsapiSize > 0 && nsapiIt != nsapiMap->end();) {
                session = nsapiIt->second;
                nsapiIt++; // Advance the iterator first

                if(!session->loadedFromCache) {
                    GTPSessionStats stats;
                    stats.startTime = session->startTime;
                    stats.messageCount = session->sequenceNumbers.size();
                    sessionTimeMap[(size_t)session] = stats;
                }

                if(lastPacketTime - lrint(session->touch) > args.gtpcSessionTimeoutAge) {
                    removedSessionCount++;
                    deleteSession(session);
                    nsapiSize -= 1;
                }
            }
        }

        LOG4CXX_INFO(loggerGtpcMap,
                     "GTP-C purge stats: Total Sessions(" << totalSessionCount << ") Removed(" << removedSessionCount << ") Remaining(" << totalSessionCount - removedSessionCount << ")");
        pthread_mutex_unlock(&controlPDPSessionMapMutex);

        if(loggerGtpcStats->isInfoEnabled() && sessionTimeMap.size() > 0) {
            double st_min = DBL_MAX, st_max = DBL_MIN, st_mean = 0, st_sum = 0, st_sum_sqrd = 0, st_std_dev = 0;
            unsigned long long mc_sum = 0;
            unsigned int mc_min = UINT_MAX, mc_max = 0;
            double mc_mean = 0, mc_sum_sqrd = 0, mc_std_dev = 0;
            LOG4CXX_INFO(loggerGtpcStats, "--->GTPC stats (" << lastPacketTime << ")");

            for(auto it = sessionTimeMap.begin(); it != sessionTimeMap.end(); it++) {
                double age = ((double)lastPacketTime - it->second.startTime);
                st_sum += age;
                st_min = min(st_min, age);
                st_max = max(st_max, age);
                mc_sum += it->second.messageCount;
                mc_min = min(mc_min, (unsigned int)it->second.messageCount);
                mc_max = max(mc_max, (unsigned int)it->second.messageCount);
                LOG4CXX_DEBUG(loggerGtpcStats, it->second.startTime << "\t" << it->second.messageCount);
            }

            st_mean = st_sum / (double)sessionTimeMap.size();
            mc_mean = (double)mc_sum / (double)sessionTimeMap.size();

            for(auto it = sessionTimeMap.begin(); it != sessionTimeMap.end(); it++) {
                st_sum_sqrd += pow((double)lastPacketTime - it->second.startTime - st_mean, 2.0);
                mc_sum_sqrd += pow((double)it->second.messageCount - mc_mean, 2.0);
            }

            st_std_dev = sqrt(st_sum_sqrd / ((double)sessionTimeMap.size()));
            mc_std_dev = sqrt(mc_sum_sqrd / ((double)sessionTimeMap.size()));
            LOG4CXX_INFO(loggerGtpcStats, std::fixed << std::setprecision(4) << "sessionTimeMap.size()[" << sessionTimeMap.size() << "] lastPacket[" << lastPacketTime << "]");
            LOG4CXX_INFO(loggerGtpcStats, std::fixed << std::setprecision(4) << "st_sum[" << st_sum << "] st_mean[" << st_mean << "] st_sum_sqrd["
                         << st_sum_sqrd << "] mc_sum[" << mc_sum << "] mc_mean[" << mc_mean << "] mc_sum_sqrd[" << mc_sum_sqrd << "]");
            LOG4CXX_INFO(loggerGtpcStats, "PDPSessionStats[min/max/mean/sigma]: Age[" << std::fixed << std::setprecision(4) << st_min << "/"
                         << st_max << "/" << st_mean << "/" << st_std_dev << "] MessageCount[" << mc_min << "/" << mc_max << "/" << mc_mean << "/" << mc_std_dev << "]");
            LOG4CXX_INFO(loggerGtpcStats, "<---GTPC stats");
        }
    }
}

void logSequenceStats() {
    LOG4CXX_INFO(loggerGtpcParser,
                 "expectedSequenceNumberMap: size(" << expectedSequenceNumberMap.size() << ") ")
}

void timeoutSequenceNumbers(const time_t &lastPacketTime, GTPV1MessageHandlerStats &stats) {
    // NOT THREAD SAFE!
    static time_t lastTimeout = 0;
    // Boundary is 40s past the minute, in an effort to reduce interference with file writer
    time_t lastBoundaryTime = (lastPacketTime - (lastPacketTime % 60)) + 40;
    static const int seqNumPurgeTime = 60; // 1 minute
    static const int seqNumTimeout = 30; // 30 seconds
    PDPSession *session;
    MessageData_t *messageData;
    int removedCreate = 0, removedUpdate = 0, removedDelete = 0,
        totalSessionCount = 0;
    std::set<PDPSession *> sessionsToRemove;

    if(lastBoundaryTime - lastTimeout >= seqNumPurgeTime) {
        lastTimeout = lastBoundaryTime;

        for(auto it = expectedSequenceNumberMap.begin(); it != expectedSequenceNumberMap.end();) {
            totalSessionCount++;
            messageData = it->second;

            if(messageData == NULL) {
                it = expectedSequenceNumberMap.erase(it);
                continue;
            }

            session = messageData->session;

            if(session == NULL) {
                delete messageData;
                it = expectedSequenceNumberMap.erase(it);
                continue;
            }

            const SequenceNumber_t *seqNum = &(it->first);

            if(lastPacketTime - lrint(seqNum->time) >= seqNumTimeout) {
                switch(seqNum->messageType) {
                    case GTPMessageTypes::CREATE_PDP_CONTEXT_REQUEST:
                        removedCreate++;
                        stats.pendingCreateResponses--;
                        stats.unmatchedCreateRequests--;
                        sessionsToRemove.insert(session);
                        break;

                    case GTPMessageTypes::UPDATE_PDP_CONTEXT_REQUEST:
                        // Rollback the update
                        removedUpdate++;
                        stats.pendingUpdateResponses--;
                        break;

                    case GTPMessageTypes::DELETE_PDP_CONTEXT_REQUEST:
                        // Teardown the session (i.e. default action)
                        removedDelete++;
                        stats.pendingDeleteResponses--;
                        sessionsToRemove.insert(session);
                        break;

                    default:
                        // Other message types shouldn't end up in the seq num map. Tear it down!
                        LOG4CXX_ERROR(loggerGtpcParser,
                                      "Unknown message type in sequence number map: " << seqNum->messageType);
                        break;
                }

                it = expectedSequenceNumberMap.erase(it);
                delete messageData;
            } else {
                it++;
            }
        }

        pthread_mutex_lock(&controlPDPSessionMapMutex);

        for(auto it = sessionsToRemove.begin(); it != sessionsToRemove.end(); it++) {
            deleteSession(*it);
        }

        pthread_mutex_unlock(&controlPDPSessionMapMutex);
        LOG4CXX_INFO(loggerGtpcParser, "SequenceNumberMap purge stats: Create(" << removedCreate << ") Update(" << removedUpdate
                     << ") Delete(" << removedDelete << ") Total Removed(" << removedCreate + removedUpdate + removedDelete << ") Remaining("
                     << totalSessionCount - (removedCreate + removedUpdate + removedDelete) << ") Sessions Deleted(" << sessionsToRemove.size() << ")");
    }
}

int addSequenceNumber(const SequenceNumber_t &seqNumber, MessageData_t *messageData) {
    size_t preAd = expectedSequenceNumberMap.size();
    expectedSequenceNumberMap[seqNumber] = messageData; // Add to the expected sequence numbers

    if(expectedSequenceNumberMap.size() != preAd + 1) {
        return 1; // Overwrote an existing entry
    }

    return 0;
}

MessageData_t *getSequenceNumber(SequenceNumber_t &seqNumber) {
    SequenceNumberMap_t::iterator seqNumMapIter = expectedSequenceNumberMap.find(seqNumber);

    if(seqNumMapIter == expectedSequenceNumberMap.end()) {
        return NULL;
    }

    MessageData_t *messageData = seqNumMapIter->second;
    size_t removed = expectedSequenceNumberMap.erase(seqNumber);

    if(removed != 1) {
        LOG4CXX_ERROR(loggerGtpcMap,
                      "getSequenceNumber: Didn't remove session from sequence number map!");
    }

    if(messageData->session != NULL) {
        messageData->session->checkRedZone();
    }

    return messageData;
}

/**
 * GtpcCacheIntervalWriterThreadCloseCleanup
 *
 * This function is to be pushed back onto the pthread_cleanup_push function.
 */
void gtpcCacheIntervalWriterThreadCloseCleanup(void *init) {
    LOG4CXX_INFO(loggerGtpcMap, "Stopping GTP-C cache interval writer.");
}

void writeGtpcCache() {
    writeGTPCCache(userPDPSessionMap);
}

/**
 * GtpcWriteTimer
 *
 * This function calls the writeGtpcCache() function on a time interval.
 * This allows the GTP-C cache to be relatively up to date should the system crash.
 */
void *gtpcWriteTimer(void *init) {
    prctl(PR_SET_NAME, "pectGtpc_writer", 0, 0, 0);
    LOG4CXX_INFO(loggerGtpcMap, "Starting GTP-C cache interval writer.");
    // Thread setup
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_cleanup_push(gtpcCacheIntervalWriterThreadCloseCleanup, NULL);
    // Set up timers.
    time_t before;
    // Base time to start from is 0230:30
    time_t timeNow;
    struct tm scheduleTime;
    time(&timeNow);
    localtime_r(&timeNow, &scheduleTime);
    scheduleTime.tm_hour = 2;
    scheduleTime.tm_min = 30;
    scheduleTime.tm_sec = 30;
    time_t nextTime = mktime(&scheduleTime);
    char tmbuf[64];

    while(1) {
        pthread_testcancel();       // Create an cancellation point for the thread.

        while(nextTime <= timeNow) {
            // Add the write interval
            scheduleTime.tm_sec += evaluatedArguments.gtpcCacheWriteInterval;
            nextTime = mktime(&scheduleTime);
        }

        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", &scheduleTime);
        LOG4CXX_INFO(loggerGtpcMap, "GTP-C cache scheduled to be written at " << tmbuf);

        while(timeNow < nextTime - 30) {
            // Wait for 90% of the time
            unsigned int sleepTime = static_cast<unsigned int>((double)(nextTime - timeNow) * 0.9);
            LOG4CXX_DEBUG(loggerGtpcMap, "GTP-C Cache: Sleeping for " << sleepTime << " seconds");
            sleep(sleepTime);
            time(&timeNow);
        }

        while(timeNow < nextTime) {
            // Wait in 1 seconds intervals until we're ready to write the cache
            sleep(1);
            time(&timeNow);
        }

        time(&before);              // Get the time before the write.
        LOG4CXX_INFO(loggerGtpcMap, "----------------------------------------------------");
        LOG4CXX_INFO(loggerGtpcMap, "Writing GTP-C cache to file.");
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        pthread_mutex_lock(&controlPDPSessionMapMutex);
        writeGtpcCache();
        pthread_mutex_unlock(&controlPDPSessionMapMutex);
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        time(&timeNow);               // Get the time after the write.
        LOG4CXX_DEBUG(loggerGtpcMap, "Seconds taken to write the GTP-C cache: " << (int) difftime(timeNow, before));
        LOG4CXX_INFO(loggerGtpcMap, "----------------------------------------------------");
    }

    pthread_cleanup_pop(1);         // When the thread is cancelled, execution will jump here.
    LOG4CXX_INFO(loggerGtpcMap, "Stopped GTP-C cache interval writer.");
    return NULL;
}
