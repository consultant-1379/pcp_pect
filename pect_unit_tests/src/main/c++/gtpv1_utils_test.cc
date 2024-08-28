
// Includes
#include <iostream>
#include "cute.h"
#include "GTPv1_packetFields.h"
#include "gtpv1_utils.h"
#include "gtp_ie_gtpv2.h"
#include "Information_Elements_GTPv2.h"
#include "gtp_ie.h"

//#include <pcap.h>

// Ignore the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"
using std::cout;
using std::endl;

// --------------- START OF gtpv1_utils.cc TESTS --------------------------
void testIs_Dir_withRealDirectoryPath() {
    char *path = (char *)"/home";
    ASSERTM("Not detecting an existing directory.",
            isDir(path) != 0
           );
}
void testIs_Dir_withFalseDirectoryPath() {
    char *path = (char *)"/false_directory";
    ASSERTM("Function detecting a non-existing directory.",
            isDir(path) == 0
           );
}
void testIs_Dir_withFilePath() {
    char *path = (char *)"../../probe_gtpc/test_gtpv1/cute/cute_base.h";
    ASSERTM("Function is saying that a file is a directory.",
            isDir(path) == 0
           );
}


void testParseArgs_withCorrectArgs() {
    char *fileInputArgs[] = { "Program",
                              "-version",     "both",
                              "-input",       "/shared_app/testLocation/gtpc.pcap",
                              "-interval",    "1",
                              "-instance_tag", "1",
                              "-live",        "false",
                              "-hash_size",   "1000000",
                              "-packetBuffer_capture_type", "FILE",
                              "-packetBuffer_gtpu_source_name", "/mnt/storage/pcapFiles/stream28_23032012_5Mins.pcap",
                              "-packetBuffer_sink_count", "0",
                              "-packetBuffer_macOfKnownElement", "00:21:59:bd:31:fe,00:21:59:bd:30:00",
                              "-outputLocation", "/tmp/",
                              "-tempOutputLocation", "/tmp/tmp/",
                              "-reportOutputPeriod", "1",
                              "-minFlowSize", "10000"
                            };
    pcap_t *descrPtr;
    ASSERTM("Unable to parse correct args when using a file input, something wrong.",
            parseArgs(LENGTHOF(fileInputArgs), fileInputArgs, &descrPtr) == 0
           );
    char *liveInputArgs[] = { "Program",
                              "-version",     "both",
                              "-input",       "/shared_app/testLocation/gtpc.pcap",
                              "-interval",    "1",
                              "-instance_tag", "1",
                              "-live",        "true",
                              "-hash_size",   "1000000",
                              "-packetBuffer_capture_type", "LIVE",
                              "-packetBuffer_gtpu_source_name", "/mnt/storage/pcapFiles/stream28_23032012_5Mins.pcap",
                              "-packetBuffer_sink_count", "0",
                              "-packetBuffer_macOfKnownElement", "00:21:59:bd:31:fe,00:21:59:bd:30:00",
                              "-outputLocation", "/tmp/",
                              "-tempOutputLocation", "/tmp/tmp/",
                              "-reportOutputPeriod", "1",
                            };
    ASSERTM("Unable to parse correct args when using live input, something wrong.",
            parseArgs(LENGTHOF(liveInputArgs), liveInputArgs, &descrPtr) == 0
           );
    char *propertiesInputArgs[] = { "Program",
                                    "-properties",  "properties.xml"
                                  };
    ASSERTM("Unable to parse correct args when using Properties file, something wrong.",
            parseArgs(LENGTHOF(propertiesInputArgs), propertiesInputArgs, &descrPtr) == 0
           );
}
void testParseArgs_withIncorrectArgs() {
    /*
     * Test notes:
     *      Unable to test for invalid pcap file, as program exits.
     *      Unable to test for invalid properties.xml file, as program exits.
     *      Unable to test for text Instance Tag, as program exits.
     *
     *      The test below are not working.
     */
    pcap_t *descrPtr;
    // Invalid output1
    cout << "  [INFO]  Starting testing invalid output 1 directory" << endl;
    char *argWrongOut1Dir[] = { "Program",
                                "-version",     "both",
                                "-input",       "/shared_app/testLocation/gtpc.pcap",
                                "-output1",     "/shared_app/testLocation/output1Fake",
                                "-output2",     "/shared_app/testLocation/output2Dump",
                                "-log",         "/shared_app/testLocation/logs",
                                "-interval",    "1",
                                "-instance_tag", "1",
                                "-v",           "off",
                                "-live",        "false",
                                "-hash_size",   "1000000"
                              };
    ASSERTM("Function not detecting the non-existent Output 1 directory, something wrong.",
            parseArgs(LENGTHOF(argWrongOut1Dir), argWrongOut1Dir, &descrPtr) == 1
           );
    // Invalid output2
    cout << "  [INFO]  Starting testing invalid output 2 directory" << endl;
    char *argWrongOut2Dir[] = { "Program",
                                "-version",     "both",
                                "-input",       "/shared_app/testLocation/gtpc.pcap",
                                "-output1",     "/shared_app/testLocation/output1Dump",
                                "-output2",     "/shared_app/testLocation/output2Fake",
                                "-log",         "/shared_app/testLocation/logs",
                                "-interval",    "1",
                                "-instance_tag", "1",
                                "-v",           "off",
                                "-live",        "false",
                                "-hash_size",   "1000000"
                              };
    ASSERTM("Function not detecting the non-existent Output 2 directory, something wrong.",
            parseArgs(LENGTHOF(argWrongOut2Dir), argWrongOut2Dir, &descrPtr) == 1
           );
    // Invalid log
    cout << "  [INFO]  Starting testing invalid log directory" << endl;
    char *argWrongLogFile[] = { "Program",
                                "-version",     "both",
                                "-input",       "/shared_app/testLocation/gtpc.pcap",
                                "-output1",     "/shared_app/testLocation/output1Dump",
                                "-output2",     "/shared_app/testLocation/output2Dump",
                                "-log",         "/shared_app/testLocation/Fakelogs",
                                "-interval",    "1",
                                "-instance_tag", "1",
                                "-v",           "off",
                                "-live",        "false",
                                "-hash_size",   "1000000"
                              };
    ASSERTM("Function not detecting the non-existent Log output file, something wrong.",
            parseArgs(LENGTHOF(argWrongLogFile), argWrongLogFile, &descrPtr) == 1
           );
    // Interval less than 1 Minute
    cout << "  [INFO]  Starting testing interval less than 1 minute" << endl;
    char *argSmallInterval[] = { "Program",
                                 "-version",     "both",
                                 "-input",       "/shared_app/testLocation/gtpc.pcap",
                                 "-output1",     "/shared_app/testLocation/output1Dump",
                                 "-output2",     "/shared_app/testLocation/output2Dump",
                                 "-log",         "/shared_app/testLocation/logs",
                                 "-interval",    "0",
                                 "-instance_tag", "1",
                                 "-v",           "off",
                                 "-live",        "false",
                                 "-hash_size",   "1000000"
                               };
    ASSERTM("Function is accepting a value less than one for interval, something wrong.",
            parseArgs(LENGTHOF(argSmallInterval), argSmallInterval, &descrPtr) == 1
           );
}

void testCheckDataMatches_withMatchingValues() {
    ASSERTM("42L expected, is not matching 42L obtained, something wrong.",
            checkDataMatches("Forty-Two", 42L, 42L)
           );
}
void testCheckDataMatches_withNonMatchingValues() {
    ASSERTM("35L expected, is matching 42L obtained, something wrong.",
            checkDataMatches("35L ex vs 42L ob", 35L, 42L) == 0
           );
}

void testCheckDataGE_withEqualValues() {
    ASSERTM("Condition not passing with 42L expected, 42L obtained, something wrong.",
            checkDataGE("Forty-Two", 42L, 42L)
           );
}
void testCheckDataGE_withGreaterExpectedValue() {
    ASSERTM("Condition not passing with 42L expected, 35L obtained, something wrong.",
            checkDataGE("42L ex vs 35L ob", 35L, 42L)
           );
}
void testCheckDataGE_withLesserExpectedValue() {
    ASSERTM("Condition passing with 35L expected, 42L obtained, something wrong.",
            checkDataGE("35L ex vs 42L ob", 42L, 35L) == 0
           );
}

void testGetPacketPointerAndLength_withCorrectValues() {
    const unsigned char *packetETHERNET = (unsigned char *)"testEthernet";
    const unsigned char *packetNONETHERNET = (unsigned char *) "TestNonEthernet";
    bool cookedTRUE = true;
    bool cookedFALSE = false;
    struct my_ip **iPP;
    int length;
    pcap_pkthdr *packetheader;
    packetheader->ts.tv_sec = 15;
    packetheader->ts.tv_usec = 1;
    packetheader->caplen = 213;
    packetheader->len = 234;
    // Cooked = true
    ASSERTM("Error executing the function with a cooked header",
            GetPacketPointerAndLength(packetETHERNET, cookedTRUE, (const my_ip **) iPP,
                                      &length, packetheader) == true
           );
    // Cooked = false, ethernet packet and lengthP bigger than my_ip
    ASSERTM("Error executing the function with an uncooked header",
            GetPacketPointerAndLength(packetETHERNET, cookedFALSE, (const my_ip **) iPP, &length, packetheader) == true
           );
    // Cooked = false and non-ethernet packet
    ASSERTM("Error in executing function with an uncooked header and a non-Ethernet packet",
            GetPacketPointerAndLength(packetNONETHERNET, cookedFALSE, (const my_ip **) iPP, &length, packetheader) == false
           );
}
void testGetPacketPointerAndLength_withIncorrectValues() {
    const unsigned char *packetETHERNET = (unsigned char *)"test";
    const unsigned char *packetNONETHERNET;
    bool cookedTRUE = true;
    bool cookedFALSE = false;
    struct my_ip **iPP;
    int *lengthP;
    pcap_pkthdr *packetheader;
    // todo Ask someone what happens in this test with a cookedTRUE and non-Ethernet packet
    // Cooked = true and non-Ethernet packet
    ASSERTM("With Cooked set to TRUE, it's processing a Non-Ethernet packet",
            GetPacketPointerAndLength(packetNONETHERNET, cookedTRUE, (const my_ip **) iPP, lengthP, packetheader) == true
           );
    // Cooked = False and LenghtP smaller than my_ip, this should exit the program
    ASSERTM("With Cooked set to FALSE and lenghtP smaller than my_ip, it's not exiting the program like it should.",
            GetPacketPointerAndLength(packetETHERNET, cookedFALSE, (const my_ip **)iPP, lengthP, packetheader)
           );
}

// todo Add operator overload tests

void testNetworkShortAt_withNumber() {
    unsigned short result = 0x1234;
    unsigned char passingArg [] = { 0x12, 0x34 };
    ASSERTM("The unsigned char* is not matching the unsigned short, that should be returned.",
            NetworkShortAt(passingArg) == result
           );
}
void testNetworkShortAt_withString() {
    unsigned char *failingArg = (unsigned char *)"Blow up";
    ASSERTM("The unsigned char* is not matching the unsigned short, that should be returned",
            NetworkShortAt(failingArg) != 0
           );
}
void testNetworkIntAt_withNumber() {
    unsigned int result = 0x78563412;
    unsigned char passingArg[] = {0x78, 0x56, 0x34, 0x12};
    ASSERTM("The unsigned char* is not matching the unsigned integer, that should be returned.",
            NetworkIntAt(passingArg) == result
           );
}
void testNetworkIntAt_withString() {
    unsigned char *failingArg = (unsigned char *)"Blow up";
    ASSERTM("The unsigned char* is not matching the unsigned integer, that should be returned",
            NetworkIntAt(failingArg) != 0
           );
}


cute::suite runGTPV1UtilsSuite(cute::suite s) {
    // --------------- START OF gtpv1_utils.cc TESTS ---------------------------
    s.push_back(CUTE(testIs_Dir_withRealDirectoryPath));                            // Passing
    s.push_back(CUTE(testIs_Dir_withFalseDirectoryPath));                           // Passing
    s.push_back(CUTE(testIs_Dir_withFilePath));                                     // Passing
    s.push_back(CUTE(testParseArgs_withCorrectArgs));                               // Passing
    s.push_back(CUTE(testParseArgs_withIncorrectArgs));                             // Will pass once Output 2 and log file are given exit codes for failures
    s.push_back(CUTE(testCheckDataMatches_withMatchingValues));                     // Passing
    s.push_back(CUTE(testCheckDataMatches_withNonMatchingValues));                  // Passing
    s.push_back(CUTE(testCheckDataGE_withEqualValues));                             // Passing
    s.push_back(CUTE(testCheckDataGE_withGreaterExpectedValue));                    // Passing
    s.push_back(CUTE(testCheckDataGE_withLesserExpectedValue));                     // Passing
    //s1.push_back( CUTE( testGetPacketPointerAndLength_withCorrectValues ) );      // Getting segmentation fault here, need to mock packets
    //s1.push_back( CUTE( testGetPacketPointerAndLength_withIncorrectValues ) );        // Getting segmentation fault here, need to mock packets
    s.push_back(CUTE(testNetworkShortAt_withNumber));                               // Passing
    s.push_back(CUTE(testNetworkShortAt_withString));                               // No error checking in function
    s.push_back(CUTE(testNetworkIntAt_withNumber));                                 // Passing
    s.push_back(CUTE(testNetworkIntAt_withString));                                 // No error checking in function
    return s;
}

// Re-enable the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
