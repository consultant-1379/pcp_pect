/*
 * Converter.hpp
 *
 *  Created on: 17 May 2013
 *      Author: ezhelao
 */

#ifndef CONVERTER_HPP_
#define CONVERTER_HPP_
#include <boost/tr1/unordered_map.hpp>
#include "classification13A.h"
#include "throughput13A.h"
#include "flow.h"
class Converter {
    std::tr1::unordered_map<int, V13AProtocol::V13AProtocolEnum> protocol13Bto13A;
    std::tr1::unordered_map<int, V13AFunction::V13AFunctionEnum> function13Bto13A;
    void initProtocolMap();
    void initFunctionMap();
    void getPacketLossValueAsString(unsigned int pktLossValue, char *retValue);
    void convertTo13AProtocol(Classification13A *v13A, const flow_data *flow);
    void convertTo13AFunction(Classification13A *v13A, const flow_data *flow);
    void convertTo13AEncryption(Classification13A *v13A, const flow_data *flow);
    void convertTo13AEncapsulation(Classification13A *v13A, const flow_data *flow);

public:
    Converter() {
        initProtocolMap();
        initFunctionMap();
    }
    void get13AClassifcationFrom13BFlow(Classification13A *v13A, const flow_data *flow);
    void get13AThroughputFrom13BFlow(Throughput13A *v13A, flow_data *flow);
};

void fileWriterPrintTP_Header();
int checkROPTime(const flow_data *flow); //PLMEEH-720
#endif /* CONVERTER_HPP_ */
