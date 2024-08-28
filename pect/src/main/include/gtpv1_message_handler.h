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

#ifndef GTPV1_MESSAGE_HANDLER_H_
#define GTPV1_MESSAGE_HANDLER_H_

#include "gtpv1_message_handler_types.h"

void handleGTPV1CreatePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void handleGTPV1CreatePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void handleGTPV1UpdatePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void handleGTPV1UpdatePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void handleGTPV1DeletePDPContextRequest(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void handleGTPV1DeletePDPContextResponse(DecodedMsg *message, GTPV1MessageHandlerStats_t &stats);

void logSequenceStats();

void timeoutSequenceNumbers(const time_t &lastPacketTime, GTPV1MessageHandlerStats &stats);

#endif
