/*
 * gtpv1_message_utils.cpp
 *
 *  Created on: 28 Jan 2014
 *      Author: ericker
 */

#include "gtp_ie.h"
#include "gtpv1_message_utils.h"


void fillLoc(PDPLocationInfo_t &locationInfo, DecodedMsg *pmsg) {
    if(strcmp(pmsg->mcc, MCC_INIT_STRING)) {
        memcpy(locationInfo.mcc, pmsg->mcc, MCC_MAX_CHARS);
        locationInfo.mcc[MCC_MAX_CHARS - 1] = '\0';
    }

    if(strcmp(pmsg->mnc, MNC_INIT_STRING)) {
        memcpy(locationInfo.mnc, pmsg->mnc, MNC_MAX_CHARS);
        locationInfo.mnc[MNC_MAX_CHARS - 1] = '\0';
    }

    if(pmsg->lac != -1) {
        locationInfo.lac = pmsg->lac;
    }

    if(pmsg->rac != -1) {
        locationInfo.rac = pmsg->rac;
    }

    if(pmsg->cid != -1) {
        locationInfo.cid = pmsg->cid;
    }

    if(pmsg->sac != -1) {
        locationInfo.sac = pmsg->sac;
    }
}

void FillLoc(PDPSession *s, DecodedMsg *pmsg) {
    fillLoc(s->locationInfo, pmsg);
    s->checkRedZone();
}


void FillQoS(PDPSession *s, DecodedMsg *pmsg) {
    s->qosInfo.arp = pmsg->arp;
    s->qosInfo.delay_class = pmsg->delay_class;
    s->qosInfo.reliability_class = pmsg->reliability_class;
    s->qosInfo.precedence = pmsg->precedence;
    s->qosInfo.thp = pmsg->thp;
    s->qosInfo.max_ul = pmsg->max_ul;
    s->qosInfo.max_dl = pmsg->max_dl;
    s->qosInfo.gbr_ul = pmsg->gbr_ul;
    s->qosInfo.gbr_dl = pmsg->gbr_dl;
    s->qosInfo.sdu = pmsg->sdu;
    s->qosInfo.traffic_class = pmsg->traffic_class;
    s->checkRedZone();
}

void fillQoS(PDPQOSInfo_t &qosInfo, DecodedMsg *pmsg) {
    qosInfo.arp = pmsg->arp;
    qosInfo.delay_class = pmsg->delay_class;
    qosInfo.reliability_class = pmsg->reliability_class;
    qosInfo.precedence = pmsg->precedence;
    qosInfo.thp = pmsg->thp;
    qosInfo.max_ul = pmsg->max_ul;
    qosInfo.max_dl = pmsg->max_dl;
    qosInfo.gbr_ul = pmsg->gbr_ul;
    qosInfo.gbr_dl = pmsg->gbr_dl;
    qosInfo.sdu = pmsg->sdu;
    qosInfo.traffic_class = pmsg->traffic_class;
}


