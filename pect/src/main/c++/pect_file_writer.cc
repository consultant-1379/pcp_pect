#include "UE_map.hpp"
#include "logger.hpp"
#include "file_writer.hpp"
#include "file_writer_map.hpp"
#include "gtpv1_maps.h"

#define PCP_FILE_TYPE_NAME "pcp"

using std::vector;

struct FileCounters pectFileCounters;
vector<struct MergedRecord *> recordList[2];
//vector<struct MergedRecord *> recordListTimedOut;
vector<struct MergedRecord *> *printingRecordList;
vector<struct MergedRecord *> *timeoutRecordList;

pthread_mutex_t recordListMutex;
OutputFileMap_t outMap;

string kOutputDirectory;
string kTempDirectory;

void initPectFileWriter() {
    kOutputDirectory = evaluatedArguments.outputlocation + "/pect/3g/";
    kTempDirectory = evaluatedArguments.tempOutputLocation + "/pect/";
    pthread_mutex_init(&recordListMutex, 0);
    printingRecordList = &recordList[0];
    timeoutRecordList = &recordList[1];
}

void timeoutFlowData(flow_data *data, struct FileCounters &fileCounters) {
	fileCounters.total++;
    PDPSession *session = getUserPDPSession(data->tunnelId);

    if(session == NULL) {   // not found
        return;
    }

    fileCounters.merged++;
    FlowDataString dataString(*data);
    stringstream s;
    s << session;
    string gtpcString = s.str();
    pthread_mutex_lock(&recordListMutex);
    mergeRecord(gtpcString, session, dataString, *timeoutRecordList);
    pthread_mutex_unlock(&recordListMutex);
    pthread_mutex_unlock(&session->pdpSessionMutex);
}

/*
 * This function looks up each IP which has classified data, the gtpc record for that IP is then looked up.
 * If valid GTPC data is found for that IP the each flow belonging to that IP is merged with the GTPC.
 * Each merged record is stored in a list of records with the necessary data for further processing extracted.
 *
 * @param theFlowsToMerge, integer value of the flow buffer which is to be merged
 */
void mergeGTPC(FileWriterMap *rawFlowData, struct FileCounters &fileCounters) {
    if(fileWriterTimers) {
        time(&fileCounters.startOfMerge);
    }

    FileWriterMap::FileWriterFlowMap_t map = rawFlowData->getFileWriterFlowMap();
    UserPlaneTunnelId tunnelId;
    list<flow_data> *data;
    PDPSession *pdpSession;

    for(auto iter = map.begin(); iter != map.end(); iter++) {
        tunnelId = iter->first;
        data = &iter->second;
        fileCounters.total += iter->second.size();
        pdpSession = getUserPDPSession(tunnelId);

        if(pdpSession == NULL) {   // not found
            continue;
        } else if(evaluatedArguments.excludeRATs.find(pdpSession->rat) != evaluatedArguments.excludeRATs.end()) {
            LOG4CXX_DEBUG(loggerPectFileWriter, "Excluded RAT (" << pdpSession->rat << ") found, skipping record");
            fileCounters.ratExcluded++;
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        } else {
            LOG4CXX_TRACE(loggerFileWriter, "MERGING " << pdpSession->rat);
            fileCounters.merged += iter->second.size();
            stringstream s;
            s << pdpSession;
            string gtpcString = s.str();

            for(auto flowIter = data->begin(); flowIter != data->end(); flowIter++) {
            	int ropCheck = checkROPTime(&(*flowIter));
            	if (ropCheck)
            		continue;
                pdpSession->touch = std::max((*flowIter).lastPacketTime, pdpSession->touch);
                FlowDataString datastring = FlowDataString(*flowIter);
                mergeRecord(gtpcString, pdpSession, datastring, *printingRecordList);
            }

            pdpSession->loadedFromCache = 0;
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        }
    }

    if(fileWriterTimers) {
        time(&fileCounters.endOfMerge);
        fileCounters.timeToMerge = fileCounters.timeToMerge
                                   + (difftime(fileCounters.endOfMerge, fileCounters.startOfMerge));
    }
}

/*
 * Print UE Map function
 *
 *
 * A Function that controls the printing process of the UE_Map.
 */

void printUeMap(list<FileWriterMap *> *rop) {
    LOG4CXX_INFO(loggerPectFileWriter, "Starting to print UE Map.");
    // Switch the pointers
    pthread_mutex_lock(&recordListMutex);
    vector<struct MergedRecord *> *temp;
    temp = printingRecordList;
    printingRecordList = timeoutRecordList;
    timeoutRecordList = temp;
    pthread_mutex_unlock(&recordListMutex);
    // Iterate through the euMap
    // Check if the outMap is empty "BEFORE" the attempt fsto write to file.
    checkIfOutMapIsEmpty("BEFORE", outMap);
    // Plan is that if sink count > 0 then only one queue in operation.
    // If more than one queue in operation then sink count should be 1
    int loop_count = 0;

    if(evaluatedArguments.packetBufferSinkCount >= 1) {
        loop_count = evaluatedArguments.packetBufferSinkCount + 1;
    } else {
        loop_count = MAX_NUM_FLOWS_SUPPORTED;
    }

    pectFileCounters.startOfPrintAllRecordsToFile = time(0);

    for(auto iter = rop->begin(); iter != rop->end(); iter++) {
        //LOG4CXX_DEBUG(loggerFileWriter,
        //              "Printing queue No." << i << " : Number of records is " << file_writer_flows[i].flows.size());
        mergeGTPC(*iter, pectFileCounters);
        generateFileNamesForRecords(*printingRecordList, PCP_FILE_TYPE_NAME, kTempDirectory, outMap, pectFileCounters); // Also writes the records to disk
        cleanUpRecordList(*printingRecordList);
    }

    pectFileCounters.filesInOutMap = outMap.size();
    // The section of the code that prints the map to the screen & closes the stream
    int files_in_output = 0;

    if(readOutputDirHashMap(kOutputDirectory.c_str(), outMap, files_in_output, pectFileCounters)) {
        LOG4CXX_TRACE(loggerPectFileWriter, "Reading output directory" << kOutputDirectory);
    }

    LOG4CXX_INFO(loggerPectFileWriter, "Number of files in output = " << files_in_output);
    // Remove .tmp extension from files, maybe this can incorporate the moving of files to the LAC filtered directories.
    moveFilesFromTempDirToOutputDir(files_in_output, kTempDirectory, kOutputDirectory, outMap, pectFileCounters, loggerFileWriter);
    // Free up the memory of outMap.
    eraseOutMapAfterROP(outMap);
    //remove the merged records which have now been printed.
    // Check if outMap is empty "AFTER" the write to file.
    checkIfOutMapIsEmpty("AFTER", outMap);
    logFileWriterStats(pectFileCounters, loggerPectFileWriter);
}
