/*
 * converter_unit_test.cc
 *
 *  Created on: 20 May 2013
 *      Author: ezhelao
 */


#include "cute.h"
#include "converter.h"
#include <iostream>


// Ignore the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"
using std::cout;
using std::endl;

#pragma GCC diagnostic ignored "-Wwrite-strings"


flow_data* getFlowData()
{
    flow_data* flow = new flow_data();
    bzero(flow,sizeof (flow_data));
    flow->init();
    flow->firstPacketTime=11;
    flow->lastPacketTime=22;
    flow->clientLatency=199999;
    flow->serverLatency=200000;
    flow->fourTuple.ueIP=1;
    flow->fourTuple.uePort=2;
    flow->fourTuple.serverIP=3;
    flow->fourTuple.serverPort=4;
    flow->durationThisRop=19.12;
    flow->throughput=3999UL;
    flow->sessionThroughput=4999UL;
    flow->maxPacketLength=33;
    flow->dataReceived=999;
    flow->packetsDown=1999;
    flow->packetsUp=1000;
    flow->ueMaxReceiverWindowSize=100;
    flow->serverMaxReceiverWindowSize=99;
    flow->internetToUeDataBytes=90;
    flow->ueToInternetDataBytes =9000;
    flow->internetToUeDataBytes=9999;
    strcpy(flow->client,"GTalk");
    strcpy(flow->contentType,"text");
    strcpy(flow->uriExtension,"xml");
    strcpy(flow->host,"www.google.com");

    return flow;

}

void testConverter_ClassificationFields_HTTP()
{
    Converter c;
    flow_data* flow = getFlowData();
    Classification13A summary;
    flow->protocol=IPOQUE_PROTOCOL_HTTP;
    string expected ="11    11.000000   22.000000   123:123:123 123:123:123 123:123:123 0.0.0.1 1999    1000    9999    9000    HTTP    \\N  HTTP    \\N  \\N  GTalk";

    c.get13AClassifcationFrom13BFlow(&summary,flow);
    char buf[1000];
    string gtpcCaptoolMiddleStr= "123:123:123\t123:123:123\t123:123:123";
    summary.getAsString(buf,1000,gtpcCaptoolMiddleStr);
    ASSERTM("expecting "+expected,  expected.compare(buf));

    std::cout <<"got: "<<buf;


}

void testConverter_ThroguputFields()
{
    Converter c;
    flow_data* flow = getFlowData();
    Throughput13A tcpta;
    string expected ="11.000000 19.120000   0.0.0.1 2   0.0.0.3 4   \\N  999 3999    4999    0   0   0   0   0.199999    0.200000    33   0   0   text    www.google.com  xml";

    c.get13AThroughputFrom13BFlow(&tcpta,flow);

    char buf[1000];
    tcpta.getAsString(buf,1000);

    ASSERTM("expecting "+expected,  expected.compare(buf));
    std::cout <<"got: "<<buf;
}




cute::suite runConverterTestSuite(cute::suite s)
{
    s.push_back(CUTE(testConverter_ClassificationFields_HTTP));
    s.push_back(testConverter_ThroguputFields);
    return s;
}

#pragma GCC diagnostic warning "-Wwrite-strings"
