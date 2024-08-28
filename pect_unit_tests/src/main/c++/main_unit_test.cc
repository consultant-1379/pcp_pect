/*
 * main_unit_test.cc
 *
 *  Created on: 13 Mar 2013
 *      Author: elukpot
 */

// Test Includes
#include "file_writer_unit_test.hpp"
#include "ArgProcessor_unit_test.hpp"
#include "UE_map_unit_test.hpp"
#include "regex_client_finder_test.hpp"
#include "Classify_unit_test.hpp"
#include "gtpv1_test.hpp"
#include "logger.hpp"
#include "config_test.hpp"
#include "converter_unit_test.hpp"

// Cute Includes
#include "cute.h"
#include "ide_listener.h"
#include "cute_runner.h"
#include "file_output_listener.h"



int main() {
    initializeLogging();
    cute::suite fw, ap, uem, clas, gtpv1IE, gtpv1PacketFields, gtpv1Utils, gtpv2Ie, config, clientFinder, converter;
    cute::file_output_listener<cute::ide_listener> lis;
    cute::makeRunner(lis)(runArgProcessorSuite(ap),                     "Arg Processor Suite");
    cute::makeRunner(lis)(runGTPV1IESuite(gtpv1IE),                     "GTPV1 IE Suite");
    cute::makeRunner(lis)(runGTPV1PacketFieldsSuite(gtpv1PacketFields), "GTPV1 Packet Fields Suite");
    cute::makeRunner(lis)(runGTPV1UtilsSuite(gtpv1Utils),               "GTPV1 Utils Suite");
    cute::makeRunner(lis)(runGTPV2IESuite(gtpv2Ie),                     "GTPV2 IE Suite");
    cute::makeRunner(lis)(runConfigSuite(config),                       "Config Suite");
    cute::makeRunner(lis)(runUeMapSuite(uem),                           "UE Map Suite");
    cute::makeRunner(lis)(runFileWriterSuite(fw),                       "File Writer Suite");
    cute::makeRunner(lis)(runClassifySuite(clas),                       "Classify Suite");
    cute::makeRunner(lis)(runCLientFinderTest(clientFinder),            "ClientFinder Suite");
    cute::makeRunner(lis)(runConverterTestSuite(converter),             "Converter Suite");
    return 0;
}
