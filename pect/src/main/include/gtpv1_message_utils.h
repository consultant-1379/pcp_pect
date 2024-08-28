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

#ifndef GTPV1_MESSAGE_UTILS_H_
#define GTPV1_MESSAGE_UTILS_H_

#include "GTPv1_packetFields.h"

void FillLoc(PDPSession *s, DecodedMsg *pmsg);

void fillLoc(PDPLocationInfo_t &locationInfo, DecodedMsg *pmsg);

void FillQoS(PDPSession *s, DecodedMsg *pmsg);

void fillQoS(PDPQOSInfo_t &qosInfo, DecodedMsg *pmsg);


#endif
