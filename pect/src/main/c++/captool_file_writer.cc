#include "UE_map.hpp"
#include "logger.hpp"
#include "file_writer.hpp"
#include "file_writer_map.hpp"
#include "gtpv1_maps.h"
#include <sys/prctl.h>


#define CAPTOOL_FILE_TYPE_NAME "summary"

using std::vector;

struct FileCounters captoolFileCounters;

pthread_mutex_t captoolRecordListMutex;

vector<struct MergedRecord *> captoolRecordList[2];
vector<struct MergedRecord *> *captoolPrintingRecordList;
vector<struct MergedRecord *> *captoolTimeoutRecordList;

OutputFileMap_t captoolOutMap;

string captoolOutputDirectory;
string captoolTempDirectory;
extern int kRopDurationInMinutes;
struct CaptoolConverterResource CAPTOOL_TIMEOUT , CAPTOOL_FILE_WRITER;
extern LoggerPtr loggerCaptoolFileWriter;

void initCaptoolFileWriter() {
    captoolPrintingRecordList = new vector<struct MergedRecord *>();
    captoolTimeoutRecordList = new vector<struct MergedRecord *>();
    captoolOutputDirectory = evaluatedArguments.outputlocation + "/captool/3g/";
    captoolTempDirectory = evaluatedArguments.tempOutputLocation + "/captool/";
    pthread_mutex_init(&captoolRecordListMutex, 0);
}

void captoolTimeoutFlowData(const flow_data *data, struct FileCounters &fileCounters) {
    
    fileCounters.total++;
    PDPSession *session = getUserPDPSession(data->tunnelId);

    if(session == NULL) {    // not found
        return;
    }

    fileCounters.merged++;
    stringstream sGtpcEnd;
    stringstream sGtpcMiddle;
    getGTPCCaptoolEndingString(sGtpcEnd, session);
    // EQEV-5039 TEST with GTPC = \N in most fields
    // getGTPC_captoolString_Test(sGtpcEnd, gtpc);
    getGTPCCaptoolMiddleString(sGtpcMiddle, session);
    string gtpcEndString = sGtpcEnd.str();
    string gtpcMiddleString = sGtpcMiddle.str();
    pthread_mutex_lock(&captoolRecordListMutex);
    mergeCaptoolRecord(gtpcEndString, session, gtpcMiddleString, data, *captoolTimeoutRecordList, CAPTOOL_TIMEOUT);
    pthread_mutex_unlock(&captoolRecordListMutex);
    pthread_mutex_unlock(&session->pdpSessionMutex);
}

/*
 * This function looks up each IP which has classified data, the gtpc record for that IP is then looked up.
 * If valid GTPC data is found for that IP the each flow belonging to that IP is merged with the GTPC.
 * Each merged record is stored in a list of records with the necessary data for further processing extracted.
 *
 * @param theFlowsToMerge, integer value of the flow buffer which is to be merged
 */

void captoolMergeGTPC(FileWriterMap *rawFlowData, struct FileCounters &fileCounters) {
    if(fileWriterTimers) {
        time(&fileCounters.startOfMerge);
    }

    FileWriterMap::FileWriterFlowMap_t map = rawFlowData->getFileWriterFlowMap();
    UserPlaneTunnelId tunnelId;
    list<flow_data> *data;
    PDPSession *pdpSession;
    string gtpcEndString;
    string gtpcMiddleString;
        
    for(auto iter = map.begin(); iter != map.end(); iter++) {
        tunnelId = iter->first;
        data = &iter->second;
        fileCounters.total += data->size();
        pdpSession = getUserPDPSession(tunnelId);

        if(pdpSession == NULL) { // One or both of the endpoints can't be found
            LOG4CXX_DEBUG(loggerCaptoolFileWriter, "Unable to identify the tunnel endpoints (ue->wan: " << tunnelId.teids[HEADING_TO_INTERNET]
                          << ", wan->ue: " << tunnelId.teids[HEADING_TO_USER_EQUIPMENT] << ")");
        } else if(evaluatedArguments.excludeRATs.find(pdpSession->rat) != evaluatedArguments.excludeRATs.end()) {
            LOG4CXX_DEBUG(loggerCaptoolFileWriter, "Excluded RAT (" << pdpSession->rat << ") found, skipping record");
            fileCounters.ratExcluded++;
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        } else {
            fileCounters.merged += data->size();
            stringstream sGtpcEnd;
            stringstream sGtpcMiddle;
            getGTPCCaptoolEndingString(sGtpcEnd, pdpSession);
            getGTPCCaptoolMiddleString(sGtpcMiddle, pdpSession);
            gtpcEndString = sGtpcEnd.str();
            gtpcMiddleString = sGtpcMiddle.str();

            for(auto flowIter = data->begin(); flowIter != data->end(); flowIter++) {
                pdpSession->touch = std::max((*flowIter).lastPacketTime, pdpSession->touch);
                mergeCaptoolRecord(gtpcEndString, pdpSession, gtpcMiddleString, &(*flowIter), *captoolPrintingRecordList, CAPTOOL_FILE_WRITER);
            }

            pdpSession->loadedFromCache = 0;
            pthread_mutex_unlock(&pdpSession->pdpSessionMutex);
        }
    }

    time(&fileCounters.endOfMerge);
    fileCounters.timeToMerge = fileCounters.timeToMerge + (difftime(fileCounters.endOfMerge, fileCounters.startOfMerge));
}


/**
 * this function may be thread safe if  kRopDurationInMinutes is read only
 */
void mergeCaptoolRecord(const string &gtpcString, const PDPSession *session, const string &gtpcCaptoolMiddleStr, const flow_data *gtpu,
                        vector<struct MergedRecord *> &destination, CaptoolConverterResource cResource) {
    if(evaluatedArguments.excludeRATs.find(session->rat) == evaluatedArguments.excludeRATs.end()) {
        LOG4CXX_TRACE(loggerCaptoolFileWriter, "MERGING " << session->rat);
        int ropCheck = checkROPTime(gtpu);
        if (ropCheck)
        	return;
        cResource.captoolConverter.get13AClassifcationFrom13BFlow(&cResource.captoolRecordTemp, gtpu);

        if(loggerCaptoolExtendedOutput->isDebugEnabled()) {
            cResource.captoolRecordTemp.getAsDebugString(cResource.captoolRecordStrBuf, STAPLE_RECORD_LEN, gtpcCaptoolMiddleStr);
        } else {
            cResource.captoolRecordTemp.getAsString(cResource.captoolRecordStrBuf, STAPLE_RECORD_LEN, gtpcCaptoolMiddleStr);
        }

        struct MergedRecord *thisRecord = new MergedRecord();

        memcpy(thisRecord->mcc, session->locationInfo.mcc, MCC_MAX_CHARS);

        thisRecord->mcc[MCC_MAX_CHARS - 1] = '\0';

        memcpy(thisRecord->mnc, session->locationInfo.mnc, MNC_MAX_CHARS);

        thisRecord->mnc[MNC_MAX_CHARS - 1] = '\0';

        thisRecord->lac = session->locationInfo.lac;

        //efitleo: moved fix for EQEV-1014 to get13AClassifcationFrom13BFlow
        thisRecord->recordStartTime = cResource.captoolRecordTemp.ropStartTime;

        thisRecord->theData =  string(cResource.captoolRecordStrBuf) + gtpcString;

        destination.push_back(thisRecord);

        // This is just for debug.  We can pull it out later after the BUG EQEV-1001 is fixed
        if(loggerCaptoolFileWriter->isDebugEnabled()) {
            if(cResource.captoolRecordTemp.ropCounter) {
                LOG4CXX_DEBUG(loggerCaptoolFileWriter,
                              "ROP CTR = " << cResource.captoolRecordTemp.ropCounter << ": " << gtpcString << cResource.captoolRecordStrBuf);
            }
        }

        //Temp just for debug of Invalid start time. Can remove later.
        thisRecord->theRopCounter = cResource.captoolRecordTemp.ropCounter;
        thisRecord->theFirstPacketinROPTime = cResource.captoolRecordTemp.firstPacketTime;
    } else {
        LOG4CXX_TRACE(loggerCaptoolFileWriter, "NOT MERGING " << session->rat);
    }
}

/*
 * Print UE Map function
 *
 *
 * A Function that controls the printing process of the UE_Map.
 */

void *printUPDataCaptool(void *data) {
    prctl(PR_SET_NAME, "fileWriter_captool", 0, 0, 0);
    checkIfOutMapIsEmpty("BEFORE", captoolOutMap);
    captoolFileCounters.startOfPrintAllRecordsToFile = time(0);
    list<FileWriterMap *> *rop = (list<FileWriterMap *> *) data;
    vector<struct MergedRecord *> *temp;
    temp = captoolPrintingRecordList;
    captoolPrintingRecordList = captoolTimeoutRecordList;
    captoolTimeoutRecordList = temp;

    for(auto iter = rop->begin(); iter != rop->end(); iter++) {
        captoolMergeGTPC(*iter, captoolFileCounters);
        generateFileNamesForRecords(*captoolPrintingRecordList, CAPTOOL_FILE_TYPE_NAME, captoolTempDirectory, captoolOutMap,
                                    captoolFileCounters);
        cleanUpRecordList(*captoolPrintingRecordList);
    }

    int files_in_output = 0;

    if(readOutputDirHashMap(captoolOutputDirectory.c_str(), captoolOutMap, files_in_output, captoolFileCounters)) {
        LOG4CXX_TRACE(loggerCaptoolFileWriter, "Reading output directory" << captoolOutputDirectory << ".");
    }

    LOG4CXX_INFO(loggerCaptoolFileWriter, "Number of Captool files in output = " << files_in_output << ".");
    // Remove .tmp extension from files, maybe this can incorporate the moving of files to the LAC filtered directories.
    moveFilesFromTempDirToOutputDir(files_in_output, captoolTempDirectory, captoolOutputDirectory, captoolOutMap,
                                    captoolFileCounters, loggerCaptoolFileWriter);
    // Free up the memory of outMap.
    eraseOutMapAfterROP(captoolOutMap);
    checkIfOutMapIsEmpty("AFTER", captoolOutMap);
    logFileWriterStats(captoolFileCounters, loggerCaptoolFileWriter);
    return NULL;
}
