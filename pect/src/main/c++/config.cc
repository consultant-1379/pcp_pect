/************************************************************************
 * COPYRIGHT (C) Ericsson 2012                                           *
 * The copyright to the computer program(s) herein is the property       *
 * of Telefonaktiebolaget LM Ericsson.                                   *
 * The program(s) may be used and/or copied only with the written        *
 * permission from Telefonaktiebolaget LM Ericsson or in accordance with *
 * the terms and conditions stipulated in the agreement/contract         *
 * under which the program(s) have been supplied.                        *
 *************************************************************************
 *************************************************************************
 * File: config.cc
 * Date: Feburary 20, 2013
 * Author: LMI/LXR/PE Richard Kerr
 ************************************************************************/

/**********************************************************************
 * This code handles all the functionality around the reading and storing
 * of configuration parameters through a XML file
 **********************************************************************/

#include "pcpglue.hpp"
#include "UE_map.hpp"
#include "gtpv1_utils.h"
#include <string.h>
#include "logger.hpp"

using namespace log4cxx;

LoggerPtr logger(log4cxx::Logger::getLogger("pect.config"));

extern EArgs evaluatedArguments;

/* Global configuration parameters */
packet_source config_source_array;
int config_source_count;
packet_sink config_sink_array;
int config_sink_count;

int configureSource(EArgs &arguments) {
    int i, sourceIndex;
    config_source_count = arguments.packetBufferSourceCount;

    if(arguments.packetBufferSourceCount == 0) {
        LOG4CXX_ERROR(logger, "Must specify at least one source in the properties file[-packetBufferGtpuSourceName]");
        LOG4CXX_ERROR(logger, "Current value of packetBuffer_source_count is: " << arguments.packetBufferSourceCount);
        return (1);
    }

    config_source_array = (packet_source_struct *) calloc(config_source_count, sizeof(struct packet_source_struct));
    list<string>::iterator j;
    i = 0;

    for(j = arguments.packetBufferGtpuSourceName.begin(); j != arguments.packetBufferGtpuSourceName.end(); ++j) {
        LOG4CXX_INFO(logger, *j);
        config_source_array[i].source_name = (*j).c_str();
        LOG4CXX_INFO(logger, config_source_array[i].source_name);
        i++;
    }

    LOG4CXX_INFO(logger, "config_source_count = " << config_source_count);

    for(int i = 0; i < config_source_count; i++) {
        if(arguments.useMultiplePacketBuffers) {
            sourceIndex = 0;
            config_source_array[i].packetBufferNum = i + 1;
        } else {
            sourceIndex = i;
            config_source_array[i].packetBufferNum = 1;
        }

        config_source_array[i].capture_type = (capture_from) arguments.packetBufferCaptureType;
        config_source_array[i].queue = sourceIndex + 1;
        LOG4CXX_INFO(logger,
                     "config_source " << i + 1 << ": config_source_array.queue = " << config_source_array[i].queue);
        LOG4CXX_INFO(logger,
                     "config_source " << i + 1 << ": config_source_array.packetBufferNum = " << config_source_array[i].packetBufferNum);

        if(config_source_array[i].capture_type == CAPTURE_LIVE) {
            LOG4CXX_INFO(logger, "config_source " << i + 1 << ": config_source_array.capture_type = LIVE");
        } else {
            LOG4CXX_INFO(logger, "config_source " << i + 1 << ": config_source_array.capture_type = FILE");
        }

        LOG4CXX_INFO(logger,
                     "config_source " << i + 1 << ": config_source_array[" << i << "].source_name = " << config_source_array[i].source_name)
        config_source_array[i].pbFull = false;
    }

    return 0;
}

void configureSink(EArgs &arguments) {
    if(arguments.packetBufferSinkCount == 0 || arguments.useMultiplePacketBuffers == true) { // 0 means track source count
        arguments.packetBufferSinkCount = arguments.packetBufferSourceCount;
        LOG4CXX_INFO(logger, "config_sink_count (tracking source)  = " << arguments.packetBufferSinkCount);
    } else {
        LOG4CXX_INFO(logger, "config_sink_count (NOT tracking source)  = " << arguments.packetBufferSinkCount);
    }

    // When updating the number of sinks, make sure to update the number at the end of the queue variable in source_next_packet function.
    // efitleo  : updated source_next_packet as requested
    config_sink_count = arguments.packetBufferSinkCount;
    config_sink_array = (packet_sink_struct *) calloc(config_sink_count, sizeof(struct packet_sink_struct));
    int sinkIndex = 0;

    for(int i = 0; i < config_sink_count; i++) {
        if(arguments.useMultiplePacketBuffers) {
            sinkIndex = 0;
            config_sink_array[i].packetBufferNum = i + 1;
        } else {
            sinkIndex = i;
            config_sink_array[i].packetBufferNum = 1;
        }

        config_sink_array[i].queue = sinkIndex + 1;
        LOG4CXX_INFO(logger,
                     "config_sink_array " << i + 1 << ": config_sink_array.queue = " << config_sink_array[i].queue);
        LOG4CXX_INFO(logger,
                     "config_sink_array " << i + 1 << ": config_sink_array.packetBufferNum = " << config_sink_array[i].packetBufferNum);
    }
}

// efitleo : updated as per DEFTFTS 3319
int configurePacketBuffer() {
    int isSourceConfigurationFailed = configureSource(evaluatedArguments);
    configureSink(evaluatedArguments);
    list<unsigned long>::iterator itr;

    for(itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
            itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++itr) {
        LOG4CXX_INFO(logger, "MAC Addresses = 0x" << std::hex << *itr << " ");
    }

    return isSourceConfigurationFailed;
}
