/*
 * TODO Add Ericsson code file header.
 *
 * file_writer.hpp
 *
 *  Created on: 20 Feb 2013
 *      Author: elukpot
 */

#ifndef FILE_WRITER_HPP_
#define FILE_WRITER_HPP_

#define MAX_FILENAME_LENGTH 512
#define MAX_DIRECTORY_LENGTH 512
#define MAX_LAC_DIR_SIZE 100
#define START_TIME_MAX 32  //DBL_MAX is way to big a buffer to allocate.. Large length START prevented in GenerateThroughputFileName
#define UEIP_SIZE 8


// Includes
#include "gtpv1_utils.h"
#include "UE_map.hpp"
#include "gzstream.h"
#include "converter.h"

#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>

using std::cout;
using std::cerr;
using std::endl;
using std::ofstream;
using std::string;
using std::list;
using std::stringstream;
using std::ostream;
using std::ofstream;
using std::vector;


using std::string;

struct hash_char_star {
    size_t operator()(const char *str) const {
        if(str == NULL) {
            return 0;
        }

        unsigned long hash = 5381;
        int c = *str;

        while(c != 0) {
            c = *str++;
            hash = ((hash << 5) + hash) + c;
        }

        return (size_t) hash;
    }
};

struct char_star_equals {
    bool operator()(char *s1, char *s2) const {
        return strcmp(s1, s2) == 0;
    }
};

struct file_struct {
    ogzstream *zip_stream;
    unsigned long records_in_file;
    unsigned int file_number;

    file_struct() {
        file_number = 0;
        records_in_file = 0;
        zip_stream = NULL;
    }
};

/*
 * Data structure used to store a merged record and the data necessary to generate a file name.
 */
struct MergedRecord {
    double recordStartTime;
    char mnc[MNC_MAX_CHARS];
    char mcc[MCC_MAX_CHARS];
    int lac;
    string theData;
    unsigned int theRopCounter;
    double theFirstPacketinROPTime;

};
struct FileCounters {
    long total;
    long merged;
    long ratExcluded;
    long filesInRop;
    long filesReaccesed;
    long recordsInRop;
    double timeForGenerateFileName;
    double timeForGettingGzipStreamReference;
    double timeToWriteToFile;
    double timeTakenToMoveFiles;
    double timeTakenToReadOutput;
    double timeToMerge;
    long filesCreatedOgz;
    long filesReusedOgz;
    long filesInOutMap;
    time_t startOfFileWriter, endOfFileWriter;
    time_t startOfGenerateFileName, endOfGenerateFileName;
    time_t startCreatingStreams, finishedCreatingStreams;
    time_t startOfPrintAllRecordsToFile;
    time_t startOfMerge;
    time_t endOfMerge;
    int printMergeMessage;

    void resetToZero() {
        total = 0;
        merged = 0;
        ratExcluded = 0;
        filesInRop = 0;
        filesReaccesed = 0;
        recordsInRop = 0;
        timeForGenerateFileName = 0;
        timeForGettingGzipStreamReference = 0;
        timeToWriteToFile = 0;
        filesCreatedOgz = 0;
        filesReusedOgz = 0;
        filesInOutMap = 0;
        timeTakenToMoveFiles = 0;
        timeTakenToReadOutput = 0;
        startOfPrintAllRecordsToFile = 0;
        timeToMerge = 0;
        printMergeMessage = 0;
    }
};

typedef std::tr1::unordered_map<char *, file_struct *, hash_char_star, char_star_equals> OutputFileMap_t;

extern EArgs evaluatedArguments;

extern int fileWriterTimers;
static const int FILE_CLEANUP_INTERVAL = 60;
//static const int FILE_CLEANUP_INTERVAL = 1;  // FOR TEST ONLY

// Constant definitions
// Call defineKconstants function to define constants that take thier value from "evaluatedArguments" [properties.xml]


#define STAPLE_RECORD_LEN 3000

struct StapleConverterResource {
    char stapleRecordStrBuf[STAPLE_RECORD_LEN];
    Throughput13A stapleRecordTemp;
    Converter stapleConverter;

} ; //one thread each


struct CaptoolConverterResource {
    char captoolRecordStrBuf[STAPLE_RECORD_LEN];
    Classification13A captoolRecordTemp;
    Converter captoolConverter;

} ; //one thread each



#define kOutputFileVersion "log-1.gz" // Maybe we should read the software version from a config file.
#define kUnknownMNCMCCLAC "UNKNOWN"
#define kDelimiter "|"

void roundDownEpoch(double *theEpochTimeIN, double *theEpochTimeOUT);
void getDateString(double epoch, char *the_date);
void *threadForPrintUeMap(void *init) ;
void defineKconstants(void);
int readOutputDirHashMap(const char *dir_path, OutputFileMap_t &fileMap, int &files_in_output, struct FileCounters &fileCounters);
int moveFilesFromTempDirToOutputDir(int numFilesInOutput, string tempDirectory, string outputDirectory, OutputFileMap_t &fileMap, struct FileCounters &fileCounters, LoggerPtr loggerPtr);
void eraseOutMapAfterROP(OutputFileMap_t &fileMap);
int checkIfOutMapIsEmpty(const char *when, OutputFileMap_t &fileMap);
int writeToFile(string *theData, file_struct *fs, char *outputFileName, struct FileCounters &fileCounters);
int writeRecordToFile(char *fileName, string *theData, OutputFileMap_t &fileMap, struct FileCounters &fileCounters);
//void mergeGTPC(FileWriterFlowList &fileWriterFlowList, struct FileCounters &fileCounters);
void timeoutFlowData(flow_data *data, struct FileCounters &fileCounters) ;
void mergeRecord(string &gtpc, PDPSession *session, FlowDataString &gtpu, std::vector<struct MergedRecord *> &destination);
void logFileWriterStats(struct FileCounters &fileCounters, LoggerPtr loggerPtr);
int writeRecordToFile(char *fileName, string *theData, OutputFileMap_t &fileMap, struct FileCounters &fileCounters);
void cleanUpRecordList(vector<struct MergedRecord *> &list);
void generateFileNamesForRecords(std::vector<struct MergedRecord *> &recordsToPrint, const char *fileTypeName, string tempDirectory, OutputFileMap_t &fileMap, struct FileCounters &fileCounters);
void mergeStapleRecord(string &gtpcString, PDPSession *session, flow_data *gtpu,
                       vector<struct MergedRecord *> &destination, StapleConverterResource cResource);

void mergeCaptoolRecord(const string &gtpcString, const PDPSession *session, const string &gtpcCaptoolMiddleStr, const flow_data *gtpu,
                        vector<struct MergedRecord *> &destination, CaptoolConverterResource cResource) ;
void sleepTillNextRop(time_t &printedRop);
int removeEmptyDirectoriesUnderPath(string &path);
#endif /* FILE_WRITER_HPP_ */
