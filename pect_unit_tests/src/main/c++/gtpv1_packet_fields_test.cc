
// Includes
#include <iostream>
#include <sstream>
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


void testDecodeMNC_withCorrectValues() {
    unsigned char *p = (unsigned char *) "\0\0";
    char mnc[MNC_MAX_CHARS];
    decodeMNC(p, mnc);
    ASSERTM("failed on input 00 returns 000 in decodeMNC", !strcmp(mnc, "000"));
    // esirich DEFTFTS-1825 fixed these inputs
    p = (unsigned char *)"\0\x21";
    decodeMNC(p, mnc);
    ASSERTM("failed on input \\0\\x21 returns 120 in decodeMNC", !strcmp(mnc, "120"));
    unsigned char n[2] = {0x30, 0x21};
    decodeMNC(n, mnc);
    ASSERTM("failed on input \\x30\\x21 returns 123 in decodeMNC", !strcmp(mnc, "123"));
    n[0] = 0x90;
    n[1] = 0x89;
    decodeMNC(n, mnc);
    ASSERTM("failed on input \\x90\\x89 returns 989 in decodeMNC", !strcmp(mnc, "989"));
}

void testDecodeMNC_withIncorrectValues() {
    unsigned char *str = (unsigned char *) "Blow up";
    char mnc[MNC_MAX_CHARS];
    bzero(mnc, MNC_MAX_CHARS);
    decodeMNC(str, mnc);
    ASSERTM("The value \"Blow up\" is being parsed correctly",
            strlen(mnc)
           );
}

void testDecodeMCC_withCorrectValues() {
    unsigned char *p = (unsigned char *) "\0\0";
    char mcc[MCC_MAX_CHARS];
    decodeMCC(p, mcc);
    ASSERTM("failed on input 00 returns 000 in decodeMCC", !strcmp(mcc, "000"));
    p = (unsigned char *)"\x10\x2";
    decodeMCC(p, mcc);
    ASSERTM("failed on input \\x10\\x2 returns 012 in decodeMCC", !strcmp(mcc, "012"));
    unsigned char n[2] = {0x23, 0x1};
    decodeMCC(n, mcc);
    ASSERTM("failed on input \\x23\\x1 returns 321 in decodeMCC", !strcmp(mcc, "321"));
}

void testDecodeMCC_withIncorrectValues() {
    unsigned char *str = (unsigned char *) "blow up";
    char mcc[MCC_MAX_CHARS];
    bzero(mcc, MCC_MAX_CHARS);
    decodeMCC(str, mcc);
    ASSERTM("The value \"Blow up\" is being parsed correctly",
            strlen(mcc)
           );
}


void testExtractPortFromPacket_withCorrectPort() {
    unsigned char port[] = { 0x50, 0x50 };
    unsigned short result = 0x5050;
    ASSERTM("Port called 8080 is not being extracted correctly, something wrong here!",
            extractPortFromPacket(port) == result
           );
}

void testExtractPortFromPacket_withIncorrectPort() {
    unsigned char *port = (unsigned char *) "blow up";
    unsigned short result = 0;
    ASSERTM("Port called \"blow up\" is being extracted correctly, something wrong here!",
            extractPortFromPacket(port) != result
           );
}

void testPDPSessionStreamOperator() {
    PDPSession session;
    session.time_pdn_response = 1;
    session.time_update_request = 2;
    session.time_update_response = 3;
    session.active_update_start = 4;
    strcpy(session.imsi, "0123456789");
    session.pdn_cause = 201;
    session.update_cause = 202;
    strcpy(session.msisdn, "0987654321");
    session.pdp_type = "pdp_type";
    session.rat = "WCDMA";
    session.traffic_class = "traffic_class";
    session.nsapi = 5;
    strcpy(session.imei, "0192837465");
    session.ue_addr = 6;
    session.sdu = 7;
    session.max_ul = 8;
    session.max_dl = 9;
    session.gbr_ul = 10;
    session.gbr_dl = 11;
    session.thp = 12;
    session.arp = 13;
    session.delay_class = 14;
    session.reliability_class = 15;
    session.precedence = 16;
    strcpy(session.mcc, "345");
    strcpy(session.mnc, "123");
    session.lac = 17;
    session.rac = 18;
    session.cid = 19;
    session.sac = 20;
    session.dtflag = 1;
    session.ggsn_d.addr = 12345;
    session.sgsn_c.addr = 54321;
    session.apn = "apn";
    std::stringstream s;
    s << &session;
    string expected = "0.000,REJECT,pdp_type,WCDMA,MANDATORY IE INCORRECT,345,123,17,18,19,20,0123456789,0192837465,0.0.48.57,apn,0987654321,5,0.0.0.6,13,14,15,16,traffic_class,12,8,9,10,11,7,1,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,";
    ASSERTM("PDPSession stream operator returned unexpected string, expected: \n" + expected + "\ngot: \n" + s.str(), !expected.compare(s.str().c_str()));
}

void testGTPCCaptoolString() {
    PDPSession session;
    strcpy(session.imei, "0123456789876543");
    //strcpy(session.imsi,"888");
    std::stringstream ss;
    getGTPCCaptoolMiddleString(ss, &session);
    string output = ss.str();
    string expected = "\\N|01234567|43||\\N|\\N:\\N:\\N:\\N|\\N:\\N:\\N:\\N|\\N:\\N:\\N:\\N";
    ASSERTM("Captool GTPC string incorrect. Expected: " + expected + " Got: " + output, !expected.compare(output));
}

cute::suite runGTPV1PacketFieldsSuite(cute::suite s) {
    s.push_back(CUTE(testDecodeMNC_withCorrectValues));                             // Passing
    s.push_back(CUTE(testDecodeMNC_withIncorrectValues));                           // No error checking in function
    s.push_back(CUTE(testDecodeMCC_withCorrectValues));                             // Passing
    s.push_back(CUTE(testDecodeMCC_withIncorrectValues));                           // No error checking in function
    s.push_back(CUTE(testExtractPortFromPacket_withCorrectPort));                   // Passing
    s.push_back(CUTE(testExtractPortFromPacket_withIncorrectPort));                 // No error checking in function
    s.push_back(CUTE(testPDPSessionStreamOperator));
    s.push_back(CUTE(testGTPCCaptoolString));
    return s;
}

// Re-enable the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
