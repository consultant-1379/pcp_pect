/*
 *  ============================================================================
 *
 * Name        : file_writer_unit_test.cc
 * Author      : elukpot
 * Version     : 0.0.1
 * Copyright   : Ericsson
 * Description : This file contains only the unit tests associated with the
 *               "file_writer.cc" file in the "pect" project.
 *
 * ============================================================================
 */

#include "file_writer_unit_test.hpp"
// System Includes
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <unordered_map>
#include <map>
#include "gzstream.h"
#include <vector>
#include "logger.hpp"

// Test files includes
#include "file_writer.hpp"
#include "pect_file_writer.hpp"
#include "UE_map.hpp"

// Ignore the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"

using std::cout;
using std::endl;
using namespace std;
extern EArgs evaluatedArguments;
extern string kTempDirectory;
//extern OutputFileMap_t outMap;
extern string kOutputDirectory;
extern vector<MergedRecord *> *printingRecordList;
extern vector<MergedRecord *> *timeoutRecordList;
extern FileWriterFlowList file_writer_flows[MAX_NUM_FLOWS_SUPPORTED];
//extern FileCounters fileCounters;

/*
 * UEIP to PDPSession map and helper functions
 */
extern struct file_struct *fs;
extern int kRopDurationInMinutes;

UE_Session_maptype ueMap_GTPC;

// These have been included
int interval;
time_t file_time;
time_t last_maint;
char *instance_tag = NULL;
const char *base_dir = NULL;
ofstream f_out;
ofstream *v1_out;
ofstream *v2_out;
int terminateProgram;

pcap_t *pcap_open_live(const char *, int, int, int, char *) {
}

pcap_t *pcap_open_offline(const char *, char *) {
}

void testGetDateString() {
    char *date_expected = "20130305";
    char date_actual[10];
    double epoch = 1362498600; // EPOCH for 20130305
    getDateString(epoch, date_actual);
    ASSERTM("GetDateString not giving the correct date for epoch.", !strcmp(date_expected, date_actual));
}

void utilCleanUpTempDir() {
    DIR *dir;
    struct dirent *dir_contents;
    const char *dir_path = kTempDirectory.c_str();
    char dir_Temp_filename[strlen(dir_path) + MAX_FILENAME_LENGTH + 1];

    // Check that the directory is not null
    if((dir = opendir(kTempDirectory.c_str())) != NULL) {
        // Remove current contents
        int filename_count;

        for(filename_count = 0; (dir_contents = readdir(dir)) != NULL; filename_count++) {
            sprintf(dir_Temp_filename, "%s%s", dir_path, dir_contents->d_name);

            if((*dir_contents->d_name != '.') && strcmp(dir_contents->d_name, "..") != 0) {
                printf("CLEANUP: Removing file : %s \n", dir_Temp_filename);
                remove(dir_Temp_filename);
            }
        }
    }
}

void utilCleanUpOutputDir(char *myDir, char *myFile) {
    DIR *dir;
    struct dirent *dir_contents;
    const char *dir_path = kOutputDirectory.c_str();
    char dir_Temp_filename[strlen(dir_path) + MAX_FILENAME_LENGTH + 1];

    // Check that the directory is not null
    if((dir = opendir(kOutputDirectory.c_str())) != NULL) {
        // Remove current contents
        sprintf(dir_Temp_filename, "%s%s%s", dir_path, myDir, myFile);
        printf("CLEANUP: Removing file : %s \n", dir_Temp_filename);
        remove(dir_Temp_filename);
    }
}

int utilCreateFileForTest(char *myFile) {
    DIR *dir;
    struct dirent *dir_contents;
    const char *dir_path = kTempDirectory.c_str();
    char dir_Temp_filename[strlen(dir_path) + MAX_FILENAME_LENGTH + 1];
    struct stat fileStat;

    // Check that the directory is not null
    if((dir = opendir(kTempDirectory.c_str())) != NULL) {
        sprintf(dir_Temp_filename, "%s%s", dir_path, myFile);
        ofstream myFileStream;
        myFileStream.open(dir_Temp_filename);
        myFileStream << "This is a test file\n";
        myFileStream.flush();
        myFileStream.close();
        stat(dir_Temp_filename, &fileStat);

        if(stat(dir_Temp_filename, &fileStat) == -1) {   // FILE does not exist ..
            printf("utilCreateFileForTest: ERROR Creating file %s \n", dir_Temp_filename);
            return 1;
        } else {
            printf("utilCreateFileForTest: Created file %s \n", dir_Temp_filename);
        }
    }

    return 0;
}

int utilCreateAndAddAFileToAMapForTest(char *fileName, OutputFileMap_t &fileMap, char *directory) {
    DIR *dir;
    file_struct *fs;

    // Check that the directory is not null
    if((dir = opendir(directory)) != NULL) {
        char *key = new char[MAX_FILENAME_LENGTH + MAX_DIRECTORY_LENGTH];
        strcat(key, directory);
        strcat(key, fileName);
        fs = new file_struct();
        fs->zip_stream = new ogzstream(key);
        fs->file_number = 0;

        if(!(*(fs->zip_stream)).good()) {
            return 1;
        }

        fileMap[key] = fs;
        fs->zip_stream->open(key);
        (*fs->zip_stream) << "This is a test file\n";
        fs->zip_stream->flush();
        fs->zip_stream->close();
    }

    return 0;
}

void testWriteToFile() {
    string theData = "The quick brown fox jumped over the lazy dog.";
    char *fileName = "/tmp/tmp/theFileIWantToMake.test";
    struct FileCounters fileCounters;
    file_struct *fs = new file_struct();
    fs->file_number = 0;
    fs->records_in_file = 0;
    fs->zip_stream = new ogzstream(fileName);
    int checkGoodFile = writeToFile(&theData, fs, fileName, fileCounters);
    ASSERTM("\ntestWriteToFile failure to write to file", checkGoodFile == 1);
    remove(fileName);
    fs->zip_stream->setstate(ios::badbit);
    int checkBadFile = writeToFile(&theData, fs, fileName, fileCounters);
    ASSERTM("\ntestWriteToFile wrote to a file which it should not have been able to", checkBadFile == 0);
}

void testWriteRecordToFile() {
    string theData = "The quick brown fox jumped over the lazy dog.";
    char *fileName = "/tmp/tmp/theFileForTestWriteRecordToFile.test";
    struct FileCounters fileCounters;
    OutputFileMap_t outMap;
    int checkGoodFileName = writeRecordToFile(fileName, &theData, outMap, fileCounters);
    ASSERTM("\ntestWriteToFile failure to write to file", checkGoodFileName == 1);
    remove(fileName);
}

void testMergeGTPCValidDataRecordListUpdated() {
    //set up the GTPC data, defaults are fine for the test.
    char *imsi = "0000000000000015";
    unsigned int ueIP = 345678;
    unsigned int ueIPBad = 876543;
    PDPSession *testSession = new PDPSession(imsi);
    struct FileCounters fileCounters;
    ueMap_GTPC[ueIP] = testSession;
    //set up the GTPU data
    flow_data *gtpuData = new flow_data();
    PectIP4Tuple fourTuple;
    bzero(gtpuData, sizeof(flow_data));
    gtpuData->init();
    fourTuple.serverIP = 1;
    fourTuple.serverPort = 1;
    fourTuple.ueIP = 3;
    fourTuple.uePort = 3;
    gtpuData->fourTuple.serverIP = 1;
    gtpuData->fourTuple.serverPort = 1;
    gtpuData->fourTuple.ueIP = 4;
    gtpuData->fourTuple.uePort = 3;
    gtpuData->firstPacketTime = 999.0;
    gtpuData->group = 0;
    gtpuData->dataReceived = 0;
    FlowDataString *gtpuDataString  = new FlowDataString(*gtpuData);
    FlowDataString *gtpuDataString2 = new FlowDataString(*gtpuData);
    FlowDataString *gtpuDataString3 = new FlowDataString(*gtpuData);
    std::vector<struct FlowDataString> flows_per_UE1;
    std::vector<struct FlowDataString> flows_per_UE2;
    flows_per_UE1.push_back(*gtpuDataString);
    flows_per_UE2.push_back(*gtpuDataString2);
    flows_per_UE2.push_back(*gtpuDataString3);
    printingRecordList->clear();
    file_writer_flows[0].flows[ueIP] = flows_per_UE1;
    mergeGTPC(file_writer_flows[0], fileCounters);
    int checkMergedRecordCreated = printingRecordList->size();
    ASSERTM("\ntestMergeRecord: Failed to merge a record", checkMergedRecordCreated == 1);
    file_writer_flows[1].flows[ueIP] = flows_per_UE2;
    printingRecordList->clear();
    mergeGTPC(file_writer_flows[1], fileCounters);
    int checkMulitpleMergedRecordCreated = printingRecordList->size();
    ASSERTM("\ntestMergeRecord: Failed to merge a list of ue flow records", checkMulitpleMergedRecordCreated == 2);
    file_writer_flows[2].flows[ueIPBad] = flows_per_UE2;
    printingRecordList->clear();
    mergeGTPC(file_writer_flows[2], fileCounters);
    int checkNoMergedRecordCreated = printingRecordList->size();
    ASSERTM("\ntestMergeRecord: Merged records that should not have been merged ", checkNoMergedRecordCreated == 0);
    delete gtpuData;
    delete gtpuDataString;
    delete gtpuDataString2;
    delete gtpuDataString3;
    delete testSession;
}

void testValidMergedRecord() {
    //set up the GTPC data, defaults are fine for the test.
    char *imsi = "0000000000000015";
    unsigned int ueIP = 345678;
    PDPSession *testSession = new PDPSession(imsi);
    struct FileCounters fileCounters;
    //vector<MergedRecord *> recordList;
    ueMap_GTPC[ueIP] = testSession;
    testSession->active_update_start = 1;
    testSession->apn = "the.fun.times.apn";
    testSession->arp = 2;
    testSession->cid = 3;
    testSession->delay_class = 4;
    testSession->dtflag = 5;
    testSession->gbr_dl = 6;
    testSession->gbr_ul = 7;
    strcpy(testSession->imei, "IMEI0000000001010");
    testSession->lac = 8;
    testSession->max_dl = 9;
    testSession->max_ul = 10;
    strcpy(testSession->mcc, "123");
    strcpy(testSession->mnc, "456");
    strcpy(testSession->msisdn, "MSISDN0000");
    testSession->nsapi = 11;
    testSession->pdn_cause = 204;
    testSession->pdp_type = "stringPDPType";
    testSession->precedence = 12;
    testSession->rac = 13;
    testSession->rat = "WCDMA";
    testSession->reliability_class = 14;
    testSession->sac = 15;
    testSession->sdu = 16;
    testSession->startTime = 17;
    testSession->thp = 18;
    testSession->time_pdn_response = 19;
    testSession->time_update_request = 20;
    testSession->time_update_response = 21;
    testSession->touch = 22;
    testSession->traffic_class = "traffic class";
    testSession->ue_addr = 23;
    testSession->update_cause = 206;
    //set up the GTPU data
    flow_data *gtpuData = new flow_data(); //TODO this one is not used here
    bzero(gtpuData, sizeof(flow_data));
    gtpuData->init();
    gtpuData->bytes = 1000;
    gtpuData->firstPacketTime = 666.0;
    gtpuData->lastPacketTime = 999.0;
    gtpuData->packetsDown = 1001;
    gtpuData->fourTuple.ueIP = ueIP;
    gtpuData->fourTuple.uePort = 3;
    gtpuData->fourTuple.serverIP = 4;
    gtpuData->fourTuple.serverPort = 5;
    gtpuData->durationThisRop = 21.3;
    gtpuData->ropCounter = 2;
    gtpuData->group = 0;
    gtpuData->ueToInternetDataBytes = 99;
    gtpuData->internetToUeDataBytes = 999;
    gtpuData->clientLatency = 987001;
    gtpuData->serverLatency = 1234567;
    strcpy(gtpuData->uriExtension, "uri");
    strcpy(gtpuData->host, "hostName");
    strcpy(gtpuData->contentType, "contentType");
    strcpy(gtpuData->client, "client");
    gtpuData->dataReceived = 1234;
    FlowDataString *gtpuDataString = new FlowDataString(*gtpuData);
    std::vector<struct FlowDataString> flows_per_UE1;
    flows_per_UE1.push_back(*gtpuDataString);
    file_writer_flows[1].flows.clear();
    file_writer_flows[1].flows[ueIP] = flows_per_UE1;
    mergeGTPC(file_writer_flows[1], fileCounters);
    MergedRecord *mergedData = printingRecordList->at(0);
    stringstream gtpcData;
    string expectedData = "17.000,REJECT,stringPDPType,WCDMA,SYSTEM FAILURE,123,456,8,13,3,15,0000000000000015,IMEI0000000001010,\\N,the.fun.times.apn,MSISDN0000,11,0.0.0.23,2,4,14,12,traffic class,18,10,9,7,6,16,5,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,666.000000,666.000000,999.000000,0.5.70.78,3,0.0.0.4,5,21.300000,2,1000,0,1001,0,ukn,hostName,contentType,uri,\\N,generic,client,1234,99,999,412,463,0.987001,1.234567,0";
    cout << "The string is now: " << mergedData->theData << endl;
    stringstream s;
    s << "testMergeRecord: expected:\n" << expectedData << "\ngot:\n" << mergedData->theData;
    ASSERTM(s.str().c_str(), expectedData == mergedData->theData);
    delete gtpuData;
    delete gtpuDataString;
    delete testSession;
}

/**
 * if direction is unknow , we should get ueMaxRwin
 */
void testValidMergedRecord_ueRwin() {
    //set up the GTPC data, defaults are fine for the test.
    char *imsi = "0000000000000015";
    unsigned int ueIP = 345678;
    PDPSession *testSession = new PDPSession(imsi);
    struct FileCounters fileCounters;
    ueMap_GTPC[ueIP] = testSession;
    testSession->active_update_start = 1;
    testSession->apn = "the.fun.times.apn";
    testSession->arp = 2;
    testSession->cid = 3;
    testSession->delay_class = 4;
    testSession->dtflag = 5;
    testSession->gbr_dl = 6;
    testSession->gbr_ul = 7;
    strcpy(testSession->imei, "IMEI0000000001010");
    testSession->lac = 8;
    testSession->max_dl = 9;
    testSession->max_ul = 10;
    strcpy(testSession->mcc, "123");
    strcpy(testSession->mnc, "456");
    strcpy(testSession->msisdn, "MSISDN0000");
    testSession->nsapi = 11;
    testSession->pdn_cause = 204;
    testSession->pdp_type = "stringPDPType";
    testSession->precedence = 12;
    testSession->rac = 13;
    testSession->rat = "WCDMA";
    testSession->reliability_class = 14;
    testSession->sac = 15;
    testSession->sdu = 16;
    testSession->startTime = 17;
    testSession->thp = 18;
    testSession->time_pdn_response = 19;
    testSession->time_update_request = 20;
    testSession->time_update_response = 21;
    testSession->touch = 22;
    testSession->traffic_class = "traffic class";
    testSession->ue_addr = 23;
    testSession->update_cause = 206;
    //set up the GTPU data
    flow_data *gtpuData = new flow_data(); //TODO this one is not used here
    bzero(gtpuData, sizeof(flow_data));
    gtpuData->init();
    gtpuData->bytes = 1000;
    gtpuData->firstPacketTime = 666.0;
    gtpuData->lastPacketTime = 999.0;
    gtpuData->packetsDown = 1001;
    gtpuData->fourTuple.ueIP = ueIP;
    gtpuData->fourTuple.uePort = 3;
    gtpuData->fourTuple.serverIP = 4;
    gtpuData->fourTuple.serverPort = 5;
    gtpuData->durationThisRop = 21.3;
    gtpuData->ropCounter = 2;
    gtpuData->group = 0;
    gtpuData->ueToInternetDataBytes = 99;
    gtpuData->internetToUeDataBytes = 999;
    gtpuData->ueMaxReceiverWindowSize = 9999;
    gtpuData->serverMaxReceiverWindowSize = 777;
    strcpy(gtpuData->uriExtension, "uri");
    strcpy(gtpuData->host, "hostName");
    strcpy(gtpuData->contentType, "contentType");
    strcpy(gtpuData->client, "client");
    gtpuData->dataReceived = 1234;
    FlowDataString *gtpuDataString = new FlowDataString(*gtpuData);
    std::vector<struct FlowDataString> flows_per_UE1;
    flows_per_UE1.push_back(*gtpuDataString);
    file_writer_flows[1].flows.clear();
    file_writer_flows[1].flows[ueIP] = flows_per_UE1;
    mergeGTPC(file_writer_flows[1], fileCounters);
    MergedRecord *mergedData = printingRecordList->at(1);
    stringstream gtpcData;
    string expectedData = "17.000,REJECT,stringPDPType,WCDMA,SYSTEM FAILURE,123,456,8,13,3,15,0000000000000015,IMEI0000000001010,\\N,the.fun.times.apn,MSISDN0000,11,0.0.0.23,2,4,14,12,traffic class,18,10,9,7,6,16,5,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,666.000000,666.000000,999.000000,0.5.70.78,3,0.0.0.4,5,21.300000,2,1000,0,1001,0,ukn,hostName,contentType,uri,\\N,generic,client,1234,99,999,412,463,\\N,\\N,9999";
    cout << "The string is now: " << mergedData->theData << endl;
    stringstream s;
    s << "testMergeRecord: expected:\n" << expectedData << "\ngot:\n" << mergedData->theData;
    ASSERTM(s.str().c_str(), expectedData == mergedData->theData);
    delete gtpuData;
    delete gtpuDataString;
    delete testSession;
}

void testTimeoutFlowData() {
    char *imsi = "0000000000000015";
    unsigned int ueIP = 345678;
    PDPSession testSession(imsi);
    ueMap_GTPC[ueIP] = &testSession;
    testSession.active_update_start = 1;
    testSession.apn = "the.fun.times.apn";
    testSession.arp = 2;
    testSession.cid = 3;
    testSession.delay_class = 4;
    testSession.dtflag = 5;
    testSession.gbr_dl = 6;
    testSession.gbr_ul = 7;
    strcpy(testSession.imei, "IMEI0000000001010");
    testSession.lac = 8;
    testSession.max_dl = 9;
    testSession.max_ul = 10;
    strcpy(testSession.mcc, "123");
    strcpy(testSession.mnc, "456");
    strcpy(testSession.msisdn, "MSISDN0000");
    testSession.nsapi = 11;
    testSession.pdn_cause = 204;
    testSession.pdp_type = "stringPDPType";
    testSession.precedence = 12;
    testSession.rac = 13;
    testSession.rat = "WCDMA";
    testSession.reliability_class = 14;
    testSession.sac = 15;
    testSession.sdu = 16;
    testSession.startTime = 17;
    testSession.thp = 18;
    testSession.time_pdn_response = 19;
    testSession.time_update_request = 20;
    testSession.time_update_response = 21;
    testSession.touch = 22;
    testSession.traffic_class = "traffic class";
    testSession.ue_addr = 23;
    testSession.update_cause = 206;
    flow_data gtpuData;
    bzero(&gtpuData, sizeof(flow_data));
    gtpuData.init();
    gtpuData.bytes = 1000;
    gtpuData.firstPacketTime = 666.0;
    gtpuData.lastPacketTime = 999.0;
    gtpuData.packetsDown = 1001;
    gtpuData.fourTuple.ueIP = ueIP;
    gtpuData.fourTuple.uePort = 3;
    gtpuData.fourTuple.serverIP = 4;
    gtpuData.fourTuple.serverPort = 5;
    gtpuData.durationThisRop = 21.3;
    gtpuData.ropCounter = 2;
    gtpuData.group = 0;
    gtpuData.ueToInternetDataBytes = 99;
    gtpuData.internetToUeDataBytes = 999;
    gtpuData.clientLatency = 987001;
    gtpuData.serverLatency = 1234567;
    strcpy(gtpuData.uriExtension, "uri");
    strcpy(gtpuData.host, "hostName");
    strcpy(gtpuData.contentType, "contentType");
    strcpy(gtpuData.client, "client");
    gtpuData.dataReceived = 1234;
    struct FileCounters fileCounters;
    timeoutFlowData(&gtpuData, fileCounters);
    FlowDataString gtpuDataString(gtpuData);
    int timedOutRecordListSize = timeoutRecordList->size();
    MergedRecord *mergedData = timeoutRecordList->at(0);
    stringstream gtpcData;
    string expectedData = "17.000,REJECT,stringPDPType,WCDMA,SYSTEM FAILURE,123,456,8,13,3,15,0000000000000015,IMEI0000000001010,\\N,the.fun.times.apn,MSISDN0000,11,0.0.0.23,2,4,14,12,traffic class,18,10,9,7,6,16,5,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,\\N,666.000000,666.000000,999.000000,0.5.70.78,3,0.0.0.4,5,21.300000,2,1000,0,1001,0,ukn,hostName,contentType,uri,\\N,generic,client,1234,99,999,412,463,0.987001,1.234567,0";
    stringstream s;
    s << "testTimeoutFlowData: expected:\n" << expectedData << "\ngot:\n" << mergedData->theData;
    ASSERTM(s.str().c_str(), expectedData == mergedData->theData);
    //ueMap_GTPC.remove(ueIP);
}

/*
 * Remove the file from the kTempDirectory
 * Create some Files in there
 * read the number of files back and see what we get
 *
 * Actually reads the temp dir at a test
 */
void testReadOutputDir() {
    file_struct *fs;
    kTempDirectory = "/var/opt/ericsson/pcp/temp/pect/";
    printf("testReadOutputDir: kTempDirectory  = %s\n", kTempDirectory.c_str());
    char *file1 = "454_06_8900-A20120323.0401-0402_pcpUnitTest_1332475320_000.log-1.gz";
    char *file2 = "454_06_8900-A20120323.0402-0403_pcpUnitTest_1332475320_001.log-1.gz";
    char *file3 = "454_06_8900-A20120323.0403-0404_pcpUnitTest_1332475320_002.log-1.gz";
    char *file4 = "454_06_8900-A20120323.0404-0405_pcpUnitTest_1332475320_003.log-1.gz";
    utilCleanUpTempDir();
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0401-0402_pcpUnitTest_1332475320_000.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0402-0403_pcpUnitTest_1332475320_001.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0403-0404_pcpUnitTest_1332475320_002.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0404-0405_pcpUnitTest_1332475320_003.log-1.gz");

    if(utilCreateFileForTest(file1)) {
        printf("ERROR creating file %s", file1);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    if(utilCreateFileForTest(file2)) {
        printf("ERROR creating file %s", file2);
        ASSERTM("\ntestReadOutputDir: ERROR creating file ", 0);
    }

    if(utilCreateFileForTest(file3)) {
        printf("ERROR creating file %s", file3);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    if(utilCreateFileForTest(file4)) {
        printf("ERROR creating file %s", file4);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    OutputFileMap_t fileMap;
    int files_in_output;
    struct FileCounters fileCounters;
    readOutputDirHashMap(kTempDirectory.c_str(), fileMap, files_in_output, fileCounters);
    printf("testReadOutputDir: files_in_output = %d \n", files_in_output);
    ASSERTM("\ntestReadOutputDir: Error Reading Files in /var/opt/ericsson/pcp/temp/pect/ Directory; Should be 4 files",
            (files_in_output == 4));
}

/*
 * Remove the file from the kTempDirectory
 * Create some Files in there
 * move them to the output directory
 *
 */
void testMoveFilesFromTempDirToOutputDir() {
    OutputFileMap_t fileMapTempDir;
    system("rm -rf /var/opt/ericsson/pcp/output/pect/3g/*");
    system("rm -rf /var/opt/ericsson/pcp/temp/pect/*");
    kRopDurationInMinutes = 1;
    kTempDirectory = "/var/opt/ericsson/pcp/temp/pect/";
    kOutputDirectory = "/var/opt/ericsson/pcp/output/pect/3g/";
    printf("testMoveFilesFromTempDirToOutputDir: kTempDirectory  = %s\n", kTempDirectory.c_str());
    printf("testMoveFilesFromTempDirToOutputDir: kTempDirectory  = %s\n", kOutputDirectory.c_str());
    char *file1 = "454_06_8900-A20120323.0401-0402_pcpUnitTest_1332475320_000.log-1.gz";
    char *file2 = "454_06_8900-A20120323.0402-0403_pcpUnitTest_1332475320_001.log-1.gz";
    char *file3 = "454_06_8900-A20120323.0403-0404_pcpUnitTest_1332475320_002.log-1.gz";
    char *file4 = "454_06_8900-A20120323.0404-0405_pcpUnitTest_1332475320_003.log-1.gz";
    char *opDir = "454_06_8900/";
    utilCleanUpTempDir();
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0401-0402_pcpUnitTest_1332475320_000.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0402-0403_pcpUnitTest_1332475320_001.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0403-0404_pcpUnitTest_1332475320_002.log-1.gz");
    system("touch /var/opt/ericsson/pcp/temp/pect/454_06_8900-A20120323.0404-0405_pcpUnitTest_1332475320_003.log-1.gz");

    if(utilCreateAndAddAFileToAMapForTest(file1, fileMapTempDir, (char *)kTempDirectory.c_str())) {
        printf("ERROR creating file %s", file1);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    if(utilCreateAndAddAFileToAMapForTest(file2, fileMapTempDir, (char *)kTempDirectory.c_str())) {
        printf("ERROR creating file %s", file2);
        ASSERTM("\ntestReadOutputDir: ERROR creating file ", 0);
    }

    if(utilCreateAndAddAFileToAMapForTest(file3, fileMapTempDir, (char *)kTempDirectory.c_str())) {
        printf("ERROR creating file %s", file3);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    if(utilCreateAndAddAFileToAMapForTest(file4, fileMapTempDir, (char *)kTempDirectory.c_str())) {
        printf("ERROR creating file %s", file4);
        ASSERTM("\ntestReadOutputDir: ERROR creating file", 0);
    }

    cout << "The file map contains: " << fileMapTempDir.size() << endl;
    struct FileCounters fileCounters;
    int files_moved = 0;
    files_moved = moveFilesFromTempDirToOutputDir(0, kTempDirectory, kOutputDirectory, fileMapTempDir, fileCounters, loggerFileWriter);
    // files_moved = moveFilesFromTempDirToOutputDir(0, kTempDirectory, fileCounters);
    cout << "Files in ROP: " << fileCounters.filesInRop << endl;
    printf("testMoveFilesFromTempDirToOutputDir: files_moved = %d \n", files_moved);
    ASSERTM(
        "\ntestMoveFilesFromTempDirToOutputDir: Error MOVING Files in /var/opt/ericsson/pcp/temp/pect/ Directory; Should have moved 4 files",
        (files_moved == 4));
    utilCleanUpOutputDir(opDir, file1);
    utilCleanUpOutputDir(opDir, file2);
    utilCleanUpOutputDir(opDir, file3);
    utilCleanUpOutputDir(opDir, file4);
    utilCleanUpOutputDir("", opDir);
    eraseOutMapAfterROP(fileMapTempDir);
}

void testOutmap() {
    OutputFileMap_t outMap;
    file_struct *fs;
    kTempDirectory = "/var/opt/ericsson/pcp/pect/temp/";
    printf("testReadOutputDir: kTempDirectory  = %s\n", kTempDirectory.c_str());
    char *file1 = "454_06_8900-A20120323.0401-0402_pcpUnitTest_1332475320_000.log-1.gz";
    char *file2 = "454_06_8900-A20120323.0402-0403_pcpUnitTest_1332475320_001.log-1.gz";
    char *file3 = "454_06_8900-A20120323.0403-0404_pcpUnitTest_1332475320_002.log-1.gz";
    char *file4 = "454_06_8900-A20120323.0404-0405_pcpUnitTest_1332475320_003.log-1.gz";
    eraseOutMapAfterROP(outMap);
    int num_Entries_In_OutMap = checkIfOutMapIsEmpty("UNIT TESTS", outMap);
    printf("testReadOutputDir: num_Entries_In_OutMap = %d \n", num_Entries_In_OutMap);
    ASSERTM("\ntestReadOutputDir: ERROR Number of entries in outmap should be 0", (num_Entries_In_OutMap == 0));
    char *key = new char[MAX_FILENAME_LENGTH];
    strcpy(key, file1);
    fs = new file_struct();
    fs->zip_stream = new ogzstream(key);
    fs->file_number = 0;
    cout << "OPENING  " << file1 << ": fs->zip_stream = " << *(fs->zip_stream) << endl;

    if(!(*(fs->zip_stream)).good()) {
        cout << "DATA LOSS due to UNABLE to opening file " << file1;
    }

    fs->records_in_file = 1;
    outMap[key] = fs;
    num_Entries_In_OutMap = checkIfOutMapIsEmpty("UNIT TESTS", outMap);
    printf("testReadOutputDir: num_Entries_In_OutMap = %d \n", num_Entries_In_OutMap);
    ASSERTM("\ntestReadOutputDir: ERROR Number of entries in outmap should be 1", (num_Entries_In_OutMap == 1));
    eraseOutMapAfterROP(outMap);
    num_Entries_In_OutMap = checkIfOutMapIsEmpty("UNIT TESTS", outMap);
    printf("testReadOutputDir: num_Entries_In_OutMap = %d \n", num_Entries_In_OutMap);
    ASSERTM("\ntestReadOutputDir: ERROR Number of entries in outmap should be 0", (num_Entries_In_OutMap == 0));
}

cute::suite runFileWriterSuite(cute::suite s) {
    // Initialise file writer
    initPectFileWriter();
    // Add all tests under here.
    s.push_back(CUTE(testGetDateString));
    s.push_back(CUTE(testReadOutputDir));
    s.push_back(CUTE(testMoveFilesFromTempDirToOutputDir));
    s.push_back(CUTE(testOutmap));
    s.push_back(CUTE(testWriteToFile));
    s.push_back(CUTE(testWriteRecordToFile));
    s.push_back(CUTE(testMergeGTPCValidDataRecordListUpdated));
    s.push_back(CUTE(testValidMergedRecord));
    s.push_back(CUTE(testTimeoutFlowData));
    s.push_back(CUTE(testValidMergedRecord_ueRwin));
    // Add all tests above here.
    return s;
}

// Re-enable the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
