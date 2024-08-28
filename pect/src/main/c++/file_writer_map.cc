/*
 * file_writer_map.cc
 *
 *  Created on: 21 Jan 2014
 *      Author: ericker
 */

#include "GTPv1_packetFields.h"
#include "file_writer_map.hpp"
#include "flow.h"
#include "logger.hpp"

extern struct EArgs evaluatedArguments;
extern u32 _flow_data_offset;

FileWriterMap::FileWriterMap() {
    pthread_mutex_init(&fileWriterFlowMutex, NULL);
}

u8 FileWriterMap::ipqHashForEachCallback(u8 *unique_buffer, u8 *user_buffer, u32 last_timestamp, void *user_data) {
    IpqHashForEachCallbackStruct_t *ipqCallbackStruct = (IpqHashForEachCallbackStruct_t *) user_data;
    FileWriterMap *map = ipqCallbackStruct->map;
    struct flow_data *flow = (struct flow_data *)(((u8 *) user_buffer) + _flow_data_offset);  // get the flow from ipoque table
    map->mapStatistics.totalFlows++;
	//efitleo:  Multiple Timeout Queues
    if(loggerClassify->isDebugEnabled()) {
		switch(flow->flowTimeoutClass) {
			case 0: // MEDIUM
				map->mapStatistics.numMediumTimeout++;
				break;
		   case 1:  // SHORT
				map->mapStatistics.numShortTimeout++;
				break;
			case 2: // LONG
				map->mapStatistics.numLongTimeout++;
				break;
			default:
				map->mapStatistics.numUnknownTimeout++;
				break;
		}
	}

    if(flow->bytes >= evaluatedArguments.minFlowSize) {
        map->fileWriterFlows[flow->tunnelId].push_back(*flow); //push the flow onto the map
        auto rbeg = map->fileWriterFlows[flow->tunnelId].rbegin(); //returns pointer to last flow put into the map, i.e the one we just put in
        rbeg->tcpPktLossInfo.expectedSeqNumReceived_ue = NULL;
        rbeg->tcpPktLossInfo.expectedSeqNumReceived_inet = NULL;
        rbeg->tcpPktLossInfo.resetPerRop = 1;
        flow->resetFlowPerRop();
        unsigned long long curPktTime_uS = (unsigned long long) ipqCallbackStruct->tv.tv_sec * PKTLOSS_RESOLUTION + ipqCallbackStruct->tv.tv_usec;
        handleThroughPutStats(flow, &curPktTime_uS);
        map->mapStatistics.flowsCopied++;

        if(loggerClassify->isTraceEnabled()) {
            map->mapStatistics.ueSeqMapMaxedCount += flow->tcpPktLossInfo.numTimesSeqMap_ue_maxed;
            flow->tcpPktLossInfo.numTimesSeqMap_ue_maxed = 0;
            map->mapStatistics.inetSeqMapMaxedCount += flow->tcpPktLossInfo.numTimesSeqMap_inet_maxed;
            flow->tcpPktLossInfo.numTimesSeqMap_inet_maxed = 0;
        }
    }

    flow->ropCounter++;
    return 0;
}
