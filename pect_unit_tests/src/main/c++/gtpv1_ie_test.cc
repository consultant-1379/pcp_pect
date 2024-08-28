
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

void testDecodeIMSI_IE() {
    unsigned char buffer[] = { 0x02, 0x12, 0x44, 0x54, 0xF3, 0xd5, 0x1f, 0x5d, 0x3c };
    int pos = 0, datalen = 8;
    //cerr << "Enter imsi test" << endl;
    DecodedMsg message;
    const char *expectedIMSI = "2144453";
    int result = DecodeIMSI_IE(buffer, pos, datalen, &message);
    //cerr << "Exit imsi test" << endl;
    ASSERTM("DecodeIMSI_IE not returning correct value for position",
            result == 9
           );
    ASSERTM("DecodeIMSI_IE returned IMSI not matching expected result",
            !strcmp(message.imsi, expectedIMSI)
           );
}

void testDecodeIMEISV_IE() {
    unsigned char buffer[] = { 0x9A, 0x00, 0x08, 0x12, 0x44, 0x54, 0xF3, 0xd5, 0x1f, 0x5d, 0x3c };
    int pos = 0, datalen = 8;
    DecodedMsg message;
    const char *expectedIMEI = "2144453";
    int result = DecodeIMEISV_IE(buffer, pos, datalen, &message);
    ASSERTM("Not returning correct value for position",
            result = 9
           );
    ASSERTM("IMEI does not match expected value",
            !strcmp(message.imei, expectedIMEI)
           );
}

void testDecodeMSISDN_IE() {
    unsigned char buffer[] = { 0x86, 0x00, 0x08, 0x12, 0x44, 0x54, 0xF3, 0xd5, 0x1f, 0x5d, 0x3c };
    int pos = 0, datalen = 8;
    DecodedMsg message;
    const char *expectedMSISDN = "44453";
    int result = DecodeMSISDN_IE(buffer, pos, datalen, &message);
    ASSERTM("Not returning correct value for position",
            result = 9
           );
    ASSERTM("Returned MSISDN not matching expected result",
            !strcmp(message.msisdn, expectedMSISDN)
           );
}

void testReadMaxBitrate() {
    unsigned int i = 0;
    ASSERTM("Read Max Bit rate is not returning the expected value.",
            ReadMaxBitrate(i) == (unsigned int)0
           );
    i = 0xff;
    ASSERTM("Read Max Bit rate is not returning the expected value.",
            ReadMaxBitrate(i) == (unsigned int)0
           );
    i = 0x3a;
    ASSERTM("Read Max Bit rate is not returning the expected value.",
            ReadMaxBitrate(i) == (unsigned int)58000
           );
    i = 0x6a;
    ASSERTM("Read Max Bit rate is not returning the expected value.",
            ReadMaxBitrate(i) == (unsigned int)400000
           );
    i = 0x80;
    ASSERTM("Read Max Bit rate is not returning the expected value.",
            ReadMaxBitrate(i) == (unsigned int)576000
           );
}

void testReadExtensionBitrate() {
    unsigned int i = 0;
    ASSERTM("Read Max Extension Bit rate is not returning the expected value.",
            ReadExtensionBitrate(i) == (unsigned int)0
           );
    i = 0xff;
    ASSERTM("Read Max Extension Bit rate is not returning the expected value.",
            ReadExtensionBitrate(i) == (unsigned int)0
           );
    i = 0x3a;
    ASSERTM("Read Max Extension Bit rate is not returning the expected value.",
            ReadExtensionBitrate(i) == (unsigned int)14400000
           );
    i = 0xaa;
    ASSERTM("Read Max Extension Bit rate is not returning the expected value.",
            ReadExtensionBitrate(i) == (unsigned int)112000000
           );
    i = 0xf0;
    ASSERTM("Read Max Extension Bit rate is not returning the expected value.",
            ReadExtensionBitrate(i) == (unsigned int)236000000
           );
}
// --------------- END OF   gtp_ie.cc TESTS -------------------------------

cute::suite runGTPV1IESuite(cute::suite s) {
    // --------------- START OF gtp_ie.cc TESTS --------------------------------
    s.push_back(CUTE(testDecodeIMSI_IE));                                           // Passing
    s.push_back(CUTE(testDecodeIMEISV_IE));                                         // Passing
    s.push_back(CUTE(testDecodeMSISDN_IE));                                         // Passing
    s.push_back(CUTE(testReadMaxBitrate));                                          // Passing
    s.push_back(CUTE(testReadExtensionBitrate));                                    // Passing
    // --------------- END OF   gtp_ie.cc TESTS --------------------------------
    return s;
}

// Re-enable the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
