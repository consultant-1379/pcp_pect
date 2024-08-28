/*
 * file_writer_map.hpp
 *
 *  Created on: 21 Jan 2014
 *      Author: ericker
 */

#ifndef FILE_WRITER_MAP_HPP_
#define FILE_WRITER_MAP_HPP_

#include <boost/tr1/unordered_map.hpp>
#include <list>
#include "flow.h"

using namespace std::tr1;
using namespace std;

class FileWriterMap {
    typedef struct FileWriterMapStatistics {
        unsigned int totalFlows;
        unsigned long flowsCopied;
        unsigned int ueSeqMapMaxedCount;
        unsigned int inetSeqMapMaxedCount;
        //efitleo  Multiple Timeout Queues
		unsigned long numShortTimeout; 
		unsigned long numMediumTimeout;
		unsigned long numLongTimeout;
		unsigned long numUnknownTimeout;
    } FileWriterMapStatistics_t;

public:
    typedef unordered_map<struct UserPlaneTunnelId, std::list<flow_data>, UserPlaneTunnelIdOperators_t, UserPlaneTunnelIdOperators_t> FileWriterFlowMap_t;
    typedef struct IpqHashForEachCallbackStruct {
        FileWriterMap *map;
        struct timeval tv;
    } IpqHashForEachCallbackStruct_t;

    FileWriterMapStatistics_t mapStatistics;
    FileWriterMap();
    FileWriterFlowMap_t &getFileWriterFlowMap() {
        return fileWriterFlows;
    };
    void lockMap() {
        pthread_mutex_lock(&fileWriterFlowMutex);
    };
    void unlockMap() {
        pthread_mutex_unlock(&fileWriterFlowMutex);
    };
    static u8 ipqHashForEachCallback(u8 *unique_buffer, u8 *user_buffer, u32 last_timestamp, void *user_data);
    void resetMapStatistics() {
        mapStatistics.totalFlows = 0;
        mapStatistics.flowsCopied = 0;
        mapStatistics.ueSeqMapMaxedCount = 0;
        mapStatistics.inetSeqMapMaxedCount = 0;
        //efitleo  Multiple Timeout Queues
        mapStatistics.numShortTimeout = 0;
        mapStatistics.numMediumTimeout = 0;
        mapStatistics.numLongTimeout = 0;
        mapStatistics.numUnknownTimeout = 0;
    }

private:
    FileWriterFlowMap_t fileWriterFlows;
    pthread_mutex_t fileWriterFlowMutex;
};
#endif /* FILE_WRITER_MAP_HPP_ */
