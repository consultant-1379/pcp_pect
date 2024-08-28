#include "UE_map.hpp"
#include "logger.hpp"
#include "file_writer.hpp"
#include "file_writer_map.hpp"
#include "gtpv1_maps.h"
#include <sys/prctl.h>
#include "classify.h"

#define STAPLE_FILE_TYPE_NAME "staple_tcpta-partial"

using std::vector;

struct FileCounters stapleFileCounters;

pthread_mutex_t stapleRecordListMutex;

vector<struct MergedRecord *> stapleRecordList[2];
vector<struct MergedRecord *> *staplePrintingRecordList;
vector<struct MergedRecord *> *stapleTimeoutRecordList;

OutputFileMap_t stapleOutMap;

string stapleOutputDirectory;
string stapleTempDirectory;
extern int kRopDurationInMinutes;
extern LoggerPtr loggerStapleFileWriter;

struct StapleConverterResource STAPLE_TIMEOUT , STAPLE_FILE_WRITER;



void initStapleFileWriter() {
    staplePrintingRecordList = new vector<struct MergedRecord *>();
    stapleTimeoutRecordList = new vector<struct MergedRecord *>();
    stapleOutputDirectory = evaluatedArguments.outputlocation + "/staple/3g/tcpta-partial/";
    stapleTempDirectory = evaluatedArguments.tempOutputLocation + "/staple/";
    pthread_mutex_init(&stapleRecordListMutex, 0);
}

void stapleTimeoutFlowData(flow_data *data, struct FileCounters &fileCounters) {
	fileCounters.total++;
    PDPSession *session = getUserPDPSession(data->tunnelId);

    if(session == NULL) {  // not found
        return;
    }

    fileCounters.merged++;
    stringstream s;
    getGTPCStapleEndingString(s, session);
    // EQEV-5039 TEST with GTPC = \N in most fields
    // getGTPCString_Test(s, gtpc);
    string gtpcString(s.str());
    pthread_mutex_lock(&stapleRecordListMutex);
    mergeStapleRecord(gtpcString, session, data, *stapleTimeoutRecordList, STAPLE_TIMEOUT);
    pthread_mutex_unlock(&stapleRecordListMutex);
    pthread_mutex_unlock(&session->pdpSessionMutex);
}

/*
 * This function looks up each IP which has classified data, the gtpc record for that IP is then looked up.
 * If valid GTPC data is found for that IP the each flow belonging to that IP is merged with the GTPC.
 * Each merged record is stored in a list of records with the necessary data for further processing extracted.
 *
 * @param theFlowsToMerge, integer value of the flow buffer which is to be merged
 */


void stapleMergeGTPC(FileWriterMap *rawFlowData, struct FileCounters &fileCounters) {
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
        fileCounters.total += data->size();
        pdpSession = getUserPDPSession(tunnelId);

        if(pdpSession == NULL) { // One or both of the endpoints can't be found
            LOG4CXX_DEBUG(loggerStapleFileWriter, "Unable to identify the tunnel endpoints (ue->wan: " << tunnelId.teids[HEADING_TO_INTERNET]
                          << ", wan->ue: " << tunnelId.teids[HEADING_TO_USER_EQUIPMENT] << ")");
        } else if(evaluatedArguments.excludeRATs.find(pdpSession->rat) != evaluatedArguments.excludeRATs.end()) {
            LOG4CXX_DEBUG(loggerStapleFileWriter, "Excluded RAT (" << pdpSession->rat << ") found, skipping record");
            fileCounters.ratExcluded++;
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        } else {
            // Do the merge
            stringstream s;
            fileCounters.merged += data->size();
            getGTPCStapleEndingString(s, pdpSession);
            string gtpcString(s.str());

            for(auto flowIter = data->begin(); flowIter != data->end(); flowIter++) {
                pdpSession->touch = std::max((*flowIter).lastPacketTime, pdpSession->touch);
                mergeStapleRecord(gtpcString, pdpSession, &(*flowIter), *staplePrintingRecordList, STAPLE_FILE_WRITER);
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

/**
 * This function may be thread safe if kRopDurationInMinutes is read only.
 */
void mergeStapleRecord(string &gtpcString, PDPSession *session, flow_data *gtpu,
                       vector<struct MergedRecord *> &destination, StapleConverterResource cResource) {
    if(evaluatedArguments.excludeRATs.find(session->rat) == evaluatedArguments.excludeRATs.end()) {
        if(gtpu->isTcpFlow == true) {  //EQEV-1416 merge only TCP records for staple
            session->checkRedZone();
            LOG4CXX_TRACE(loggerStapleFileWriter, "MERGING " << session->rat);
            int ropCheck = checkROPTime(gtpu);
            if (ropCheck)
            	return;
            cResource.stapleConverter.get13AThroughputFrom13BFlow(&cResource.stapleRecordTemp, gtpu);
            cResource.stapleRecordTemp.getAsString(cResource.stapleRecordStrBuf, STAPLE_RECORD_LEN);
            struct MergedRecord *thisRecord = new MergedRecord();
            memcpy(thisRecord->mcc, session->locationInfo.mcc, MCC_MAX_CHARS);
            thisRecord->mcc[MCC_MAX_CHARS - 1] = '\0';
            session->checkRedZone();
            memcpy(thisRecord->mnc, session->locationInfo.mnc, MNC_MAX_CHARS);
            thisRecord->mnc[MNC_MAX_CHARS - 1] = '\0';
            session->checkRedZone();
            thisRecord->lac = session->locationInfo.lac;
            //Moved fix for Invalid Start time EQEV-1014 to get13AThroughputFrom13BFlow
            thisRecord->recordStartTime = cResource.stapleRecordTemp.ropStartTime;
            thisRecord->theData =  string(cResource.stapleRecordStrBuf) + gtpcString;
            destination.push_back(thisRecord);

            // This is just for debug.  We can pull it out later after the BUG EQEV-1001 is fixed
            if(loggerStapleFileWriter->isDebugEnabled()) {
                if(cResource.stapleRecordTemp.ropCounter) {
                    //LOG4CXX_DEBUG(loggerStapleFileWriter,"ROP CTR = " << cResource.stapleRecordTemp.ropCounter << ": " << gtpcString << cResource.stapleRecordStrBuf);
                }
            }

            // Temp just for debug of Invalid start time. Can remove later.
            thisRecord->theRopCounter = cResource.stapleRecordTemp.ropCounter;
            thisRecord->theFirstPacketinROPTime = cResource.stapleRecordTemp.firstPacketTime;
        }
    } else {
        LOG4CXX_TRACE(loggerStapleFileWriter, "NOT MERGING " << session->rat);
    }
}

void *printUPDataStaple(void *data) {
    prctl(PR_SET_NAME, "fileWriter_staple", 0, 0, 0);
    list<FileWriterMap *> *rop = (list<FileWriterMap *> *) data;
    checkIfOutMapIsEmpty("BEFORE", stapleOutMap);
    stapleFileCounters.startOfPrintAllRecordsToFile = time(0);
    vector<struct MergedRecord *> *temp;
    temp = staplePrintingRecordList;
    staplePrintingRecordList = stapleTimeoutRecordList;
    stapleTimeoutRecordList = temp;

    for(auto iter = rop->begin(); iter != rop->end(); iter++) {
        stapleMergeGTPC(*iter, stapleFileCounters);
        generateFileNamesForRecords(*staplePrintingRecordList, STAPLE_FILE_TYPE_NAME, stapleTempDirectory, stapleOutMap, stapleFileCounters);  // Also writes the records to disk
        cleanUpRecordList(*staplePrintingRecordList);
    }

    stapleFileCounters.filesInOutMap = stapleOutMap.size();
    // The section of the code that prints the map to the screen & closes the stream
    int files_in_output = 0;

    if(readOutputDirHashMap(stapleOutputDirectory.c_str(), stapleOutMap, files_in_output, stapleFileCounters)) {
        LOG4CXX_TRACE(loggerStapleFileWriter, "Reading output directory" << stapleOutputDirectory << ".");
    }

    LOG4CXX_INFO(loggerStapleFileWriter, "Number of Staple files in output  = " << files_in_output << ".");
    // Remove .tmp extension from files, maybe this can incorporate the moving of files to the LAC filtered directories.
    moveFilesFromTempDirToOutputDir(files_in_output, stapleTempDirectory, stapleOutputDirectory, stapleOutMap, stapleFileCounters, loggerStapleFileWriter);
    // Free up the memory of outMap.
    eraseOutMapAfterROP(stapleOutMap);
    // remove the merged records which have now been printed.
    // Check if outMap is empty "AFTER" the write to file.
    checkIfOutMapIsEmpty("AFTER", stapleOutMap);
    logFileWriterStats(stapleFileCounters, loggerStapleFileWriter);
    printNoPacketLossRateStats();
    return NULL;
}
