/*
 * UE_map_unit_test.cc
 *
 *  Created on: 13 Mar 2013
 *      Author: emilawl
 */

#include "UE_map_unit_test.hpp"
// System Includes
#include <string.h>
#include <stdio.h>
#include <iostream>

// Test files includes
#include "UE_map.hpp"
#include "classify.h"
#include <pcap.h>
#include "ipq_api.h"
#include "gtpv1_utils.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <map>

// Shared objects
extern int terminateProgram;
extern EArgs evaluatedArguments;
extern ClassifierMapMutex classifierMutexLockArray[MAX_NUM_FLOWS_SUPPORTED];

UEFlowMap_t *ue_Map_Classification = new UEFlowMap_t();
extern int kRopDurationInMinutes;

// Ignore the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"

void testTrueUeMap() {
    ASSERTM("Test Case should Pass", true);
}

void testUeIpInseration() {
    kRopDurationInMinutes = 1;
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    //a new element of greater then 0 indicates a new flow
    int new_element = 1;
    flow_data *flow = new flow_data();
    flow->lastPacketTime = 444;
    int protocol = 21;
    unsigned long long UE_addr = 0x2a3b4c5d;
    insertIntoUeFlowTracker(1, new_element, flow, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    ASSERTM("The entry has been placed in the map", ue_Map_Classification->size() == 1);
    ue_Map_Classification->clear();
}

void testMoreThenOneUeIpInseration() {
    kRopDurationInMinutes = 1;
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    //a new element of greater then 0 indicates a new flow
    int new_element = 1;
    flow_data *flow = new flow_data();
    flow_data *flow2 = new flow_data();
    unsigned long long UE_addr = 0x2a3b4c5d;
    unsigned long long UE_addr2 = 0x11223344;
    insertIntoUeFlowTracker(1, new_element, flow, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    insertIntoUeFlowTracker(1, new_element, flow2, *ue_Map_Classification, UE_addr2, theImatationTimeValue);
    ASSERTM("The entry has been placed in the map", ue_Map_Classification->size() == 2);
    ue_Map_Classification->clear();
}

void testSameFlowOnAUeIpInseration() {
    kRopDurationInMinutes = 1;
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    //a new flow is indicated by a value greater then 0
    int new_flow = 1;
    int not_new_flow = 0;
    flow_data *flow = new flow_data();
    FlowList_t *theCurrentFlowMap;
    unsigned long long UE_addr = 0x2a3b4c5d;
    insertIntoUeFlowTracker(1, new_flow, flow, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    insertIntoUeFlowTracker(1, not_new_flow, flow, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    int ue_map_size = ue_Map_Classification->size();
    theCurrentFlowMap = ue_Map_Classification->find(UE_addr)->second;
    int flowMapSize = theCurrentFlowMap->size();
    ASSERTM("The entry has been placed in the map", (ue_map_size == 1) && (flowMapSize == 1));
    ue_Map_Classification->clear();
}

void testMoreThenOneFlowOnAUeIpInseration() {
    kRopDurationInMinutes = 1;
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    //a new flow is indicated by a value greater then 0
    int new_flow = 1;
    flow_data *flow = new flow_data();
    flow_data *flow2 = new flow_data();
    FlowList_t *theCurrentFlowMap;
    unsigned long long UE_addr = 0x2a3b4c5d;
    insertIntoUeFlowTracker(1, new_flow, flow, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    insertIntoUeFlowTracker(1, new_flow, flow2, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    int ue_map_size = ue_Map_Classification->size();
    theCurrentFlowMap = ue_Map_Classification->find(UE_addr)->second;
    int flowMapSize = theCurrentFlowMap->size();
    ASSERTM("The entry has been placed in the map", (ue_map_size == 1) && (flowMapSize == 2));
    ue_Map_Classification->clear();
    delete flow;
    delete flow2;
}
/* A function used by this test has been removed
void testtoh_timeout_cleanupUEmap_removeFlows() {
    //a new flow is indicated by a value greater then 0
    kRopDurationInMinutes = 1;
    UEFlowMap_t *myMap = new UEFlowMap_t();
    int new_flow = 1;
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    flow_data *fd = new flow_data();
    flow_data *fd2 = new flow_data();
    FlowList_t *theCurrentFlowMap;
    unsigned long long UE_addr = 0x2a3b4c5d;
    unsigned long long UE_addr2 = 0x2a3b4c5e;
    flow_data *fd3 = new flow_data();
    flow_data *fd4 = new flow_data();
    struct in_addr ueip;
    fd->fourTuple.ueIP = UE_addr;
    fd->firstPacketTime = 1.0;
    fd->protocol = 0;
    fd->ue_Map_Classification = myMap;
    fd->queueNumber = 0;
    fd->group = 0;
    fd2->firstPacketTime = 2.0;
    fd2->fourTuple.ueIP = UE_addr;
    fd2->protocol = 1;
    fd2->ue_Map_Classification = myMap;
    fd2->queueNumber = 0;
    fd2->group = 0;
    fd3->firstPacketTime = 3.0;
    fd3->fourTuple.ueIP = UE_addr2;
    fd3->protocol = 0;
    fd3->ue_Map_Classification = myMap;
    fd3->queueNumber = 0;
    fd3->group = 0;
    fd4->firstPacketTime = 4.0;
    fd4->fourTuple.ueIP = UE_addr2;
    fd4->protocol = 1;
    fd4->ue_Map_Classification = myMap;
    fd4->queueNumber = 0;
    fd4->group = 0;
    // put 2 flow into the map for UEIP 0x2a3b4c5d
    insertIntoUeFlowTracker(1, new_flow, fd, *myMap, UE_addr, theImatationTimeValue);
    insertIntoUeFlowTracker(1, new_flow, fd2, *myMap, UE_addr, theImatationTimeValue);
    // put 2 flow into the map for UEIP 0x2a3b4c5e
    insertIntoUeFlowTracker(1, new_flow, fd3, *myMap, UE_addr2, theImatationTimeValue);
    insertIntoUeFlowTracker(1, new_flow, fd4, *myMap, UE_addr2, theImatationTimeValue);
    // map size should be 2
    int ue_map_size = myMap->size();
    theCurrentFlowMap = myMap->find(UE_addr)->second;
    int flowMapSize = theCurrentFlowMap->size();
    theCurrentFlowMap = myMap->find(UE_addr2)->second;
    flowMapSize = flowMapSize + theCurrentFlowMap->size();
    ASSERTM("RemoveFlow: Expecting 2 UEIP and 4 Flows in UE MAP", (ue_map_size == 2) && (flowMapSize == 4));
    // Search through  the UE MAP and FIND the UEIP. Remove a flow
    int returnVal = 0;
    int flowRemoved = 0;
    FlowList_t *RemoveFromMap;
    int queueNumber = 0;
    classifierMutexLockArray[queueNumber].lockMapMutex();
    UEFlowMap_t::iterator UE_it = myMap->find(fd->fourTuple.ueIP);
    int mapRemoved = 0;
    ASSERTM("RemoveFlow:Expecting 1 UEIP in UE MAP", (UE_it != myMap->end()));
    RemoveFromMap = UE_it->second;
    // Remove FLOW fd, should still be one flow left in UE MAP for this ueip.
    mapRemoved = toh_timout_cleanUp_UEFlowMap_removeFlows(fd, RemoveFromMap, &ueip, &UE_it);
    ASSERTM("RemoveFlow: Expecting 1 UEIP & 1 Flow in UE MAP", (mapRemoved == 0));
    // check that the flow fd is removed.
    flowRemoved = toh_timout_cleanUp_UEFlowMap_checkFlowRemoved(fd, RemoveFromMap, mapRemoved);
    ASSERTM("RemoveFlow: Expecting 1 UEIP & 1 Flow in UE MAP. Flow fd not removed ", (flowRemoved == 0));
    // check that the flow  fd2 is present in flow map.
    printf("Expecting an ERROR message here [Test for Fail]--->");
    flowRemoved = toh_timout_cleanUp_UEFlowMap_checkFlowRemoved(fd2, RemoveFromMap, mapRemoved);
    printf("FlowRemoved = %d", flowRemoved);
    ASSERTM("RemoveFlow: Expecting 1 UEIP & 1 Flow in UE MAP. Flow fd2 not found ", (flowRemoved == 1));
    mapRemoved = 0;
    //mapRemoved = toh_timout_cleanUp_UEFlowMap_removeFlows(fd2, RemoveFromMap, &ueip, &UE_it);
    //ASSERTM("RemoveFlow: Expecting 1 UEIP & 1 Flow in UE MAP", (mapRemoved == -1));
    mapRemoved = toh_timout_cleanUp_UEFlowMap_removeFlows(fd2, RemoveFromMap, &ueip, &UE_it);
    ASSERTM("RemoveFlow: Expecting 0 UEIP & 0 Flow in UE MAP", (mapRemoved == 1));
    // map size should be 2
    ue_map_size = myMap->size();
    theCurrentFlowMap = myMap->find(UE_addr2)->second;
    flowMapSize = theCurrentFlowMap->size();
    ASSERTM("RemoveFlow: Expecting 1 UEIP and 2 Flows in UE MAP", (ue_map_size == 1) && (flowMapSize == 2));
    myMap->clear();
    classifierMutexLockArray[queueNumber].unlockMapMutex();
    delete fd2;
    delete fd;
    delete fd3;
    delete fd4;
}
*/




void testtoh_timeout_cleanupUEmap_findUEIPinUEMAP() {
    kRopDurationInMinutes = 1;
    ue_Map_Classification = new UEFlowMap_t();
    struct timeval theImatationTimeValue;
    gettimeofday(&theImatationTimeValue, NULL);
    // A new flow is indicated by a value greater then 0.
    int new_flow = 1;
    flow_data *fd = new flow_data();
    flow_data *fd2 = new flow_data();
    FlowList_t *theCurrentFlowMap;
    unsigned long long UE_addr = 0x2a3b4c5d;
    int queueNumber = 1;
    fd->init();
    fd->fourTuple.ueIP = 0x2a3b4c5d;
    fd->hashKey = fd->fourTuple.ueIP;
    fd->protocol = 0;
    fd->ue_Map_Classification = ue_Map_Classification;
    fd->queueNumber = queueNumber;
    fd->firstPacketTime = 4.0;
    fd2->init();
    fd2->fourTuple.ueIP = 0x2a3b4c5d;
    fd2->hashKey = fd2->fourTuple.ueIP;
    fd2->protocol = 1;
    fd2->ue_Map_Classification = ue_Map_Classification;
    fd2->queueNumber = queueNumber;
    fd2->firstPacketTime = 4.0;
    int ue_map_size = ue_Map_Classification->size();
    // put 2 flows into the map
    insertIntoUeFlowTracker(queueNumber, new_flow, fd, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    insertIntoUeFlowTracker(queueNumber, new_flow, fd2, *ue_Map_Classification, UE_addr, theImatationTimeValue);
    // map size should be 2
    ue_map_size = ue_Map_Classification->size();
    const char *errorMessage = "The UE Map Does not contain all entries expected 1 got " + ue_map_size;
    ASSERTM(errorMessage, ue_map_size == 1);
    theCurrentFlowMap = ue_Map_Classification->find(UE_addr)->second;
    int flowMapSize = 0;
    flowMapSize = theCurrentFlowMap->size();
    ASSERTM("FindUEIP: Expecting 1 UEIP and 2 Flows in UE MAP", ((ue_map_size == 1) && (flowMapSize == 2)));
    int retVal = toh_timout_cleanUp_UEFlowMap_findUEIPinMAP(fd);
    ASSERTM("FindUEIP: Failed to remove flow fd from UE MAP", (retVal == 0));
    retVal = toh_timout_cleanUp_UEFlowMap_findUEIPinMAP(fd2);
    ASSERTM("FindUEIP: Failed to remove flow fd2 from UE MAP", (retVal == 0));
    // map size should be 0
    ue_map_size = ue_Map_Classification->size();
    ASSERTM("RemoveFlow: Expecting 0 UEIP in UE MAP", (ue_map_size == 0));
    ue_Map_Classification->clear();
    delete fd2;
    delete fd;
}

void testGetFlowString() {
    //a new flow is indicated by a value greater then 0
    int new_flow = 1;
    flow_data *fd = new flow_data();
    FlowList_t *theCurrentFlowMap;
    unsigned long long UE_addr = 0x2a3b4c5d;
    unsigned long long UE_addr2 = 0x2a3b4c5e;
    fd->init();
    fd->ue_Map_Classification = ue_Map_Classification;
    string goodHeader = string("ID,firstPacketTime,lastPacketTime,ueIp,uePort,serverIp,serverPort,durationThisRop,ropCounter,bytes,maxPacketLength,packetsDown,packetsUp,protocol,hostName,contentType,uriExtension,direction,function,client,dataReceived,bytesUplink,bytesDownlink,sessionThroughput,throughput,clientLatency,serverLatency,maxReceiverWindow\n");
    fd->fourTuple.ueIP = 0x2a3b4c5d;
    fd->fourTuple.uePort = 1;
    fd->fourTuple.serverIP = 3;
    fd->fourTuple.serverPort = 4;
    fd->maxPacketLength = 500;
    fd->durationThisRop = 21.3;
    fd->ropCounter = 2;
    fd->packetsDown = 100;
    fd->packetsUp = 200;
    fd->bytes = 300;
    fd->protocol = 5;
    fd->firstPacketTime = 12345.123456789; // percision is 6
    fd->lastPacketTime = 98765.123456789;
    fd->group = 0;
    strcpy(fd->host, "hostName");
    strcpy(fd->contentType, "contentType");
    strcpy(fd->uriExtension, "uri");
    fd->dataReceived = 312;
    fd->ueToInternetDataBytes = 5;
    fd->internetToUeDataBytes = 5;
    fd->clientLatency = 3000;
    fd->serverLatency = 4500;
    fd->ueMaxReceiverWindowSize = 0;
    string goodData = string("12345.123457,12345.123457,98765.123457,42.59.76.93,1,0.0.0.3,4,21.300000,2,300,500,100,200,winmx,hostName,contentType,uri,\\N,generic,\\N,312,5,5,3,117,0.003000,0.004500,0");
    struct FlowDataString myflowData(*fd);
    stringstream gtpuHeader;
    gtpuHeader << *myflowData.getFlowHeaderString();
    cout << *myflowData.getFlowHeaderString();
    string testHeader = string(gtpuHeader.str());
    unsigned int resHeader = goodHeader.compare(testHeader);
    //cout << "myresult header is : " << testHeader << endl;
    //cout << "Test Header : " << gtpuHeader.str();
    //cout << "Good Header : " << goodHeader << endl;
    ASSERTM("\ntestGetFlowString: GTPU Header Miss Match", (resHeader == 0));
    stringstream gtpu;
    gtpu << *myflowData.getFlowDataString();
    string testData = string(gtpu.str());
    cout << "actual data:" << testData << endl;
    unsigned int resData = goodData.compare(testData);
    //cout << "   ACTUAL Test Data   : " << testData << endl;
    //cout << "   EXPECTED Good Data : " << goodData << endl;
    ASSERTM("\ntestGetFlowString: GTPU Data Miss Match.", (resData == 0));
    delete fd;
}

cute::suite runUeMapSuite(cute::suite s) {
    // Add all tests under here.
    s.push_back(CUTE(testTrueUeMap));
    s.push_back(CUTE(testUeIpInseration));
    s.push_back(CUTE(testMoreThenOneUeIpInseration));
    s.push_back(CUTE(testSameFlowOnAUeIpInseration));
    s.push_back(CUTE(testMoreThenOneFlowOnAUeIpInseration));
    //A function used by this test has been removed
    //s.push_back(CUTE(testtoh_timeout_cleanupUEmap_removeFlows));
    s.push_back(CUTE(testtoh_timeout_cleanupUEmap_findUEIPinUEMAP));
    s.push_back(CUTE(testGetFlowString));
    // Add all tests above here.
    return s;
}

// Re-enable the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"

