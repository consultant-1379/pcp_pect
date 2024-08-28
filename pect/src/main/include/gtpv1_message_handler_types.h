/*
 * gtpv1_message_handler_types.h
 *
 *  Created on: 18 Feb 2014
 *      Author: ericker
 */

#ifndef GTPV1_MESSAGE_HANDLER_TYPES_H_
#define GTPV1_MESSAGE_HANDLER_TYPES_H_

typedef struct GTPV1MessageHandlerStats {
    unsigned int createRequestCount, createResponseCount, updateRequestCount, updateResponseCount, deleteRequestCount, deleteResponseCount;
    unsigned int failedCreateCount, failedUpdateCount;
    unsigned int createResponseUnmatchedSeqCount, updateResponseUnmatchedSeqCount, deleteResponseUnmatchedSeqCount;
    unsigned int pendingCreateResponses, pendingUpdateResponses, pendingDeleteResponses;
    unsigned int updateRequestUnmatchedSession, deleteRequestUnmatchedSession;
    unsigned int unmatchedCreateRequests;
    void reset();
} GTPV1MessageHandlerStats_t;


#endif /* GTPV1_MESSAGE_HANDLER_TYPES_H_ */
