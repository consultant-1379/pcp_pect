/*
 * UE_map.hpp
 *
 *  Created on: 16 Jan 2013
 *      Author: emilawl
 */

#ifndef UE_MAP_HPP_
#define UE_MAP_HPP_

#include <boost/tr1/unordered_map.hpp>
#include <algorithm>
#include <vector>
#include <list>
#include <map>
#include <functional>
#include <sstream>
#include "flow.h"
#include "mutex.hpp"
#include "map_utils.hpp"
#include "GTPv1_packetFields.h"
#include "logger.hpp"

using std::map;
using std::list;
using namespace log4cxx;

#define MAX_NUM_FLOWS_SUPPORTED (20)

extern EArgs evaluatedArguments;

//void copy_map_to_buffer_every_minute(int queue_num, UEFlowMap_t &UE_IP_map, const struct timeval &packetTime);
void calculateFlowDataFields(flow_data *fd);
void resetFlowDataCounters(flow_data *fd);

bool operator<(const timeval &lhs, const timeval &rhs);

bool operator>(const timeval &lhs, const timeval &rhs);

/**
 * This is the data structure we used to store the flow data in string format
 */
class FlowDataString {
private:
    unsigned int ueIP;
    string flowData;
    string headerInfo;
    unsigned int ropCtr;
    double firstPacketInRopTime;

public:
    FlowDataString(flow_data &flow_data) {
        convertToFlowString(flow_data);
    }

    FlowDataString() {
    }

    void convertToFlowString(flow_data &flow_data) {
        // Do per-ROP calculation before converting to string.
        calculateFlowDataFields(&flow_data);
        ueIP = flow_data.fourTuple.ueIP;
        char theFlowData[MAX_GTPU_FLOW_LENGTH];
        printFlowToString(&flow_data, theFlowData, MAX_GTPU_FLOW_LENGTH);
        firstPacketInRopTime = flow_data.firstPacketTime;
        flowData = string(theFlowData);
        getRopCounter(&flow_data, &ropCtr);
        // Reinitialise per-ROP counters in flow_data.
        flow_data.resetFlowPerRop();
    }

    string *getFlowDataString() {
        return &flowData;
    }

    string *getFlowHeaderString() {
        char theFlowHeaderData[MAX_GTPU_FLOW_LENGTH + 1];
        printHeaderFlowToString(theFlowHeaderData);
        headerInfo = string(theFlowHeaderData);
        return &headerInfo;
    }

    unsigned int getRopCtr() {
        return ropCtr;
    }

    unsigned int getUEIP() {
        return ueIP;
    }

    /**
     * Gets the first packet time.
     *
     * The private variable is populated from the flow_data in the constructor.
     */
    double getFirstPacketInRopTime() {
        return firstPacketInRopTime;
    }
};

#endif /* UE_MAP_HPP_ */
