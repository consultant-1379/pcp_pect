/*
 * TODO Add Ericsson code file header.
 *
 * file_writer.cc
 *
 *  Created on: 20 Feb 2013
 *      Author: elukpot, efitleo
 */

#include "file_writer.hpp"
#include "mutex.hpp"
#include "GTPv1_packetFields.h"
#include "gzstream.h"
#include "logger.hpp"
#include "classify.h"
#include "pect_file_writer.hpp"
#include "captool_file_writer.hpp"
#include "staple_file_writer.hpp"
#include "file_writer_map_manager.hpp"

#include <algorithm>
#include <errno.h>
#include <cfloat>
#include <climits>
#include <cstring>
#include <ctime>
#include <ctype.h>
#include <dirent.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <sstream>
#include <stdlib.h>
#include <string>
#include <sys/prctl.h>
#include <sys/stat.h> /* struct stat, fchmod (), stat (), S_ISREG, S_ISDIR */
#include <sys/types.h>
#include <boost/tr1/unordered_map.hpp>
#include <sched.h> 
#include <sys/wait.h>
#include <linux/wait.h>
#include <unistd.h>

using std::endl;
using std::ofstream;
using std::string;
using std::list;
using std::stringstream;
using std::ostream;
using std::ofstream;
using std::vector;
using namespace log4cxx;
// TODO If the output file size reaches a maximum, close the file and open a new one.

extern int terminateProgram;

extern LoggerPtr loggerFileWriter;
extern LoggerPtr loggerConsole;
extern string captoolOutputDirectory;
extern string stapleOutputDirectory;
extern string kOutputDirectory;
extern int pectFileOutputFormat_isPect;
/*
 * Provides a method of hiding the timers throughout the file writer.
 * This variable is set by checking the current log level which has been set for the fileWriter logger.
 */
int fileWriterTimers = 0;

int waitForFileWriter;

int kRopDurationInMinutes;
char outputDirectoryPath[MAX_DIRECTORY_LENGTH];


// Functions
/*
 * Used to define constants that take their value from "evaluatedArguments" [properties.xml]
 */
void defineKconstants(void) {
    kRopDurationInMinutes = evaluatedArguments.outputReportingPeriod;
    snprintf(outputDirectoryPath, sizeof(outputDirectoryPath), "%s", evaluatedArguments.outputlocation.c_str());
}

/*
 * Get Date String function.
 * Converts an epoch time to a char * of the format YYYYMMDD.
 */
void getDateString(double epoch, char *the_date) {
    time_t t = static_cast<time_t>(epoch);
    struct tm current_date;
    gmtime_r(&t, &current_date);
    sprintf(the_date, "%4d%02d%02d", current_date.tm_year + 1900,
            current_date.tm_mon + 1, current_date.tm_mday);
}

/*
 * Round Down Time function.
 * Rounds the time down to hhm0 or hhm5.
 */
void roundDownTime(struct tm *date) {
    int ropTime = (int) kRopDurationInMinutes;
    int mod_mins = date->tm_min % ropTime;

    if(mod_mins != 0) {
        date->tm_min -= mod_mins;
    }
}

/*
 * Tool for debug: convert epoch to time function.
 * Converts an epoch time to HHMMSS.
 */
void epochToTime(double epoch, char *the_time) {
    time_t t = static_cast<time_t>(epoch);
    struct tm current_date;
    gmtime_r(&t, &current_date);
    sprintf(the_time, "%02d%02d%02d", current_date.tm_hour, current_date.tm_min,
            current_date.tm_sec);
}

/*
 * Get Start ROP Time function
 */
void getStartRopTime(double epoch, char *start_time) {
    time_t t = static_cast<time_t>(epoch);
    struct tm current_date;
    gmtime_r(&t, &current_date);
    roundDownTime(&current_date);
    sprintf(start_time, "%02d%02d", current_date.tm_hour, current_date.tm_min);
}

/*
 * Get End ROP Time function
 *
 * A function that takes in the epoch time and populates the times for the end of the ROP.
 * It also populates the end of ROP epoch time.
 */
void getEndRopTime(double epoch, char *end_time, time_t *timeSinceEpoch) {
    time_t t = static_cast<time_t>(epoch);
    struct tm current_date;
    gmtime_r(&t, &current_date);
    roundDownTime(&current_date);
    int hour = current_date.tm_hour;
    int mins = current_date.tm_min + kRopDurationInMinutes;

    if(mins >= 60) {
        // Up to the next hour
        mins -= 60;
        hour++;

        if(hour >= 24) {
            // Reset the hour to 00 if it's 24 or greater.
            hour = 0;
        }
    }

    // Reuse current_date to represent the end rop time
    current_date.tm_min = mins;
    current_date.tm_sec = 0;
    *timeSinceEpoch = timegm(&current_date);
    sprintf(end_time, "%02d%02d", hour, mins);
}

void roundDownEpoch(double *theEpochTimeIN, double *theEpochTimeOUT) {
    *theEpochTimeOUT = (int(*theEpochTimeIN / 60) * 60);
    //printf("theEpochTimeIN = %.6f, theEpochTimeOUT = %.6f\n",*theEpochTimeIN,*theEpochTimeOUT);
}

/**
 * Validate the values of the session's MCC, MNC and LAC.
 */
int validateLocationInformation(MergedRecord *session) {
    if(session->lac <= 0) {
        LOG4CXX_WARN(loggerFileWriter,
                     "Record not processed, LAC not found in LAI or RAI. Invalid session->lac : " << session->lac);
        return 1;
    }

    if(session->mcc == NULL) {
        LOG4CXX_WARN(loggerFileWriter,
                     "Record not processed, Invalid session->mcc : " << session->mcc);
        return 1;
    }

    if(session->mnc == NULL) {
        LOG4CXX_WARN(loggerFileWriter,
                     "Record not processed, Invalid session->mnc : " << session->mnc);
        return 1;
    }

    size_t i;

    for(i = 0; i < strlen(session->mnc); i++) {
        if(!isdigit(session->mnc[i])) {
            LOG4CXX_WARN(loggerFileWriter,
                         "Record not processed, Invalid session->mnc : " << session->mnc);
            return 1;
            break;
        }
    }

    for(i = 0; i < strlen(session->mcc); i++) {
        if(!isdigit(session->mcc[i])) {
            LOG4CXX_WARN(loggerFileWriter,
                         "Record not processed, Invalid session->mcc : " << session->mcc);
            return 1;
            break;
        }
    }

    return 0;
}

/*
 * A function to populate the output file name for the ROP.
 *
 * @returns 0 for valid filename
 * @returns 1 for invalid filename
 *
 * It populates the required fields for the filename.
 *
 * File name should look like:
 *     325_764_35243-A20130214.1825-1830_pcp_1360866600_000.log-1.gz
 * or
 *     UNKNOW-A20130214.1825-1830_pcp_1360866600_000.log-1.gz
 */
int generateFileName(MergedRecord &mergedFlow, char *filename, double now_time,
                     string &tempDirectory, const char *fileTypeName,
                     FileCounters &fileCounters) {
    if(fileWriterTimers) {
        time(&fileCounters.startOfGenerateFileName);
    }

    // Populate FileName Parameters
    char date[32];
    char start_rop_time[16];
    char end_rop_time[16];
    time_t end_rop_epoch_time;
    int filenumber = 0;

    // FIX for invalid start time in PDP Session .. see JIRA DEFTFTS-3358
    if(mergedFlow.recordStartTime > now_time) {
        LOG4CXX_WARN(loggerFileWriter,
                     "Invalid start time in flow record, it exceeds the current time. Current time is " << std::fixed << now_time << ": Invalid Start Time is " << std::fixed << mergedFlow.recordStartTime << ": ROP Counter = " << mergedFlow.theRopCounter << ": First Packet Start time [Flow Start] =" << std::fixed << mergedFlow.theFirstPacketinROPTime);
        return 1;
    }

    if(mergedFlow.recordStartTime == 0) {
        LOG4CXX_WARN(loggerFileWriter,
                     "Invalid start time for filename, it is zero.");
        return 1;
    }

    getDateString(mergedFlow.recordStartTime, date);
    getStartRopTime(mergedFlow.recordStartTime, start_rop_time);
    getEndRopTime(mergedFlow.recordStartTime, end_rop_time,
                  &end_rop_epoch_time);
    validateLocationInformation(&mergedFlow);

    if((strcmp(mergedFlow.mnc, "\\N") != 0)
            && (strcmp(mergedFlow.mcc, "\\N") != 0) && mergedFlow.lac != 0
            && strlen(mergedFlow.mnc) != 0 && strlen(mergedFlow.mcc) != 0
            && mergedFlow.lac != -1) {
        // For a known MCC_MNC_LAC combo.
        // just pass in the bare filename with no output directory structure to checkFileExists
        char bare_filename[MAX_FILENAME_LENGTH + 1];
        snprintf(bare_filename, MAX_FILENAME_LENGTH,
                 "%s_%s_%d-A%s.%s-%s_%s_%ld_%03d.%s", mergedFlow.mcc,
                 mergedFlow.mnc, mergedFlow.lac, date, start_rop_time,
                 end_rop_time, fileTypeName, end_rop_epoch_time, filenumber,
                 kOutputFileVersion);

        // Check if the filename is too long
        if((strlen(tempDirectory.c_str()) + strlen(bare_filename))
                > (MAX_DIRECTORY_LENGTH + MAX_FILENAME_LENGTH)) {
            const char *dir_path = tempDirectory.c_str();
            LOG4CXX_WARN(loggerFileWriter,
                         "Filename = " << dir_path << bare_filename << " is INVALID as original file name is " << strlen(filename) << " characters which exceeds max file length of " << (MAX_DIRECTORY_LENGTH + MAX_FILENAME_LENGTH) << " characters. Check directory " << dir_path);

            if(fileWriterTimers) {
                time(&fileCounters.endOfGenerateFileName);
                fileCounters.timeForGenerateFileName =
                    fileCounters.timeForGenerateFileName
                    + ((difftime(fileCounters.endOfGenerateFileName,
                                 fileCounters.startOfGenerateFileName)));
            }

            return (1);
        } else {
            // Now prefix with the temp directory structure.
            snprintf(filename,
                     (strlen(tempDirectory.c_str()) + strlen(bare_filename) + 2),
                     "%s%s", tempDirectory.c_str(), bare_filename);

            // Return 0 as filename is valid.
            if(fileWriterTimers) {
                time(&fileCounters.endOfGenerateFileName);
                fileCounters.timeForGenerateFileName =
                    fileCounters.timeForGenerateFileName
                    + ((difftime(fileCounters.endOfGenerateFileName,
                                 fileCounters.startOfGenerateFileName)));
            }

            return (0);
        }
    } else { // For an UNKNOWN MCC_MNC_LAC combos.
        // just pass in the bare filename with no output directory structure to checkFileExists
        char bare_filename[MAX_FILENAME_LENGTH + 1];
        snprintf(bare_filename, MAX_FILENAME_LENGTH,
                 "%s-A%s.%s-%s_%s_%ld_%03d.%s", kUnknownMNCMCCLAC, date,
                 start_rop_time, end_rop_time, fileTypeName, end_rop_epoch_time,
                 filenumber, kOutputFileVersion);

        if((strlen(tempDirectory.c_str()) + strlen(bare_filename))
                > (MAX_DIRECTORY_LENGTH + MAX_FILENAME_LENGTH)) {
            const char *dir_path = tempDirectory.c_str();
            LOG4CXX_WARN(loggerFileWriter,
                         "Filename = " << dir_path << bare_filename << " is INVALID as original file name is " << strlen(filename) << " characters which exceeds max file length of " << (MAX_DIRECTORY_LENGTH + MAX_FILENAME_LENGTH) << " characters. Check directory " << dir_path);

            if(fileWriterTimers) {
                time(&fileCounters.endOfGenerateFileName);
                fileCounters.timeForGenerateFileName =
                    fileCounters.timeForGenerateFileName
                    + ((difftime(fileCounters.endOfGenerateFileName,
                                 fileCounters.startOfGenerateFileName)));
            }

            return (1);
        } else {
            // Now prefex with the temp directory structure.
            snprintf(filename,
                     (strlen(tempDirectory.c_str()) + strlen(bare_filename) + 2),
                     "%s%s", tempDirectory.c_str(), bare_filename);

            // Return 0 as filename is valid.
            if(fileWriterTimers) {
                time(&fileCounters.endOfGenerateFileName);
                fileCounters.timeForGenerateFileName =
                    fileCounters.timeForGenerateFileName
                    + ((difftime(fileCounters.endOfGenerateFileName,
                                 fileCounters.startOfGenerateFileName)));
            }

            return (0);
        }
    }
}

/*
 * A function to read the files in the output directory into a hash map of filename to file number.
 * This list is referenced in printUeMap
 * Run once per ROP
 * Return Number of files in output dir
 * Returns "-1" for failure.
 */
int readOutputDirHashMap(const char *dir_path, OutputFileMap_t &fileMap,
                         int &files_in_output, struct FileCounters &fileCounters) {
    time_t startOfReadOutput, endOfReadOutput;

    if(fileWriterTimers) {
        time(&startOfReadOutput);
    }

    LOG4CXX_DEBUG(loggerFileWriter, "Reading output directories" << dir_path);
    file_struct *fs1;
    DIR *dir;
    struct stat filestat;
    char dirTempFileName[strlen(dir_path) + MAX_FILENAME_LENGTH + 1];
    struct dirent dirContents;
    struct dirent *result = NULL;
    // Check that the directory is not null
    dir = opendir(dir_path);

    if(dir != NULL) {
        while((readdir_r(dir, &dirContents, &result) == 0) && result != NULL) {
            //for(filename_count = 0; (dir_contents = readdir(dir)) != NULL; filename_count++) {
            sprintf(dirTempFileName, "%s%s", dir_path, dirContents.d_name);

            if(stat(dirTempFileName, &filestat) == -1) {
                continue;    // file does not exist
            }

            if((*dirContents.d_name != '.')
                    && strcmp(dirContents.d_name, "..") != 0) {
                if(S_ISDIR(filestat.st_mode)) {
                    // its a directory.. read it
                    char dirTempFileNameWithSlash[strlen(dirTempFileName) + 2];
                    sprintf(dirTempFileNameWithSlash, "%s%s", dirTempFileName,
                            "/");

                    // Recurse through subdirectories
                    if(readOutputDirHashMap(dirTempFileNameWithSlash, fileMap,
                                            files_in_output, fileCounters) < 0) {
                        LOG4CXX_ERROR(loggerFileWriter,
                                      "Unable to read output directory " << dirTempFileNameWithSlash);
                        LOG4CXX_ERROR(loggerConsole,
                                      "Unable to read output directory " << dirTempFileNameWithSlash);
                    }
                } else { // its a file name  103_542_26500-A20130330.1614-1615_pcp_1364660100_018.log-1.gz
                    //Search Outmap for directory name;
                    LOG4CXX_TRACE(loggerFileWriter,
                                  "READ OUTPUT DIR: Search for file " << dirContents.d_name << " in Outmap");

                    for(OutputFileMap_t::const_iterator outMapIterator =
                                fileMap.begin(); outMapIterator != fileMap.end();
                            ++outMapIterator) {
                        size_t numCharToCompare = strlen(dirContents.d_name)
                                                  - strlen(kOutputFileVersion) - 3;
                        char *bareFileName;
                        bareFileName = strrchr(outMapIterator->first, '/') + 1;

                        if(bareFileName == NULL) {
                            LOG4CXX_ERROR(loggerFileWriter,
                                          "Unable to determine file number from" << outMapIterator->first << ", can't locate the bare file name");
                        }

                        LOG4CXX_TRACE(loggerFileWriter,
                                      "READ OUTPUT DIR: outMap_it4->first: bareFileName = " << bareFileName << " : " << numCharToCompare);

                        // don't compare the 018.log-1.gz at the end of each file as file number may be different.
                        if(strncmp(dirContents.d_name, bareFileName,
                                   numCharToCompare) == 0) {
                            fs1 = outMapIterator->second;
                            //fs1->file_number = 0;
                            char *fileName = dirContents.d_name;
                            char *pch;
                            pch = strstr(fileName, ".log");

                            if(pch != NULL) {
                                // atoi will convert 018.log-1.gz as 18, It stops conversion at first non decmal digit. Hence no strcpy needed.
                                unsigned int fileNum = atoi(pch - 3);
                                fs1->file_number = max(fs1->file_number,
                                                       fileNum + 1);
                                LOG4CXX_TRACE(loggerFileWriter,
                                              "READ OUTPUT DIR: Found file " << fileName << " in Outmap: File Number = " << fs1->file_number);
                            } else {
                                fs1->file_number = 99;
                                LOG4CXX_WARN(loggerFileWriter,
                                             "Unable to determine file number from" << dir_path << ": Setting to 099");
                            }

                            break;
                        }
                    }

                    files_in_output++;
                }
            }
        }
    } else {
        LOG4CXX_ERROR(loggerFileWriter,
                      "Error whilst reading output directory " << dir_path);
        LOG4CXX_ERROR(loggerConsole,
                      "Error whilst reading output directory " << dir_path);
        LOG4CXX_ERROR(loggerFileWriter, strerror(errno));
        LOG4CXX_ERROR(loggerConsole, strerror(errno));
        return -1;
    }

    if(fileWriterTimers) {
        time(&endOfReadOutput);
        fileCounters.timeTakenToReadOutput = difftime(endOfReadOutput,
                                             startOfReadOutput);
    }

    closedir(dir);
    return files_in_output;
}

/*
 * A function to move the files in the temp directory to the correct LAC filtered output directory.
 * This function should be run in a thread after the printUeMap() function finishes.
 *
 * moveFilesFromTempDirToOutputDir improved version of MoveFilesFromTempDirToOutputDir
 * Does not need to read all the filenames into an internal list. Process on the fly, one by one.
 * uses file number from Outmap
 * RETURNS Number of files moved or -1 on error
 */
int moveFilesFromTempDirToOutputDir(int numFilesInOutput, string tempDirectory,
                                    string outputDirectory, OutputFileMap_t &fileMap,
                                    struct FileCounters &fileCounters, LoggerPtr loggerPtr) {
    time_t startMovingFiles, endMovingFiles;

    if(fileWriterTimers) {
        time(&startMovingFiles);
    }

    LOG4CXX_INFO(loggerPtr,
                 "Starting to move the files in the temp directory to LAC filtered output directories.");
    /*
     * Get a list of filenames in the temp directory.
     * Extract the subdirectory from the newfilename.
     * If subdirectory doesn't exist,
     *     Make required LAC filtering subdirectories.
     * Finally, Move file contents to correct LAC Filtered Directory file.
     */
    int numFilesMoved;
    list<string> filenames;
    DIR *dir;
    struct stat filestat;
    const char *tempDirectoryPath = tempDirectory.c_str();
    char dir_Temp_filename[strlen(tempDirectoryPath) + MAX_FILENAME_LENGTH + 1];
    fileCounters.filesInRop = 0;
    numFilesMoved = 0;
    struct dirent dirContents;
    struct dirent *result = NULL;
    // Check that the directory is not null
    dir = opendir(tempDirectory.c_str());

    if(dir != NULL) {
        string fname;

        while((readdir_r(dir, &dirContents, &result) == 0) && result != NULL) {
            sprintf(dir_Temp_filename, "%s%s", tempDirectoryPath,
                    dirContents.d_name);
            LOG4CXX_TRACE(loggerPtr,
                          "MOVE FILES: dir_Temp_filename = " << dir_Temp_filename);

            if(stat(dir_Temp_filename, &filestat) == -1) {
                continue;    // file does not exist
            }

            // Flat directory structure, do not recurse
            if(S_ISDIR(filestat.st_mode)) {
                continue;
            }

            // Don't process '.' and '..'
            if((*dirContents.d_name != '.')
                    && strcmp(dirContents.d_name, "..") != 0) {
                string fname(dirContents.d_name);
                size_t pos = fname.find("-A20"); // Grab the start of the string (MCC_MNC_LAC-A20131231...)

                if(pos != std::string::npos) {
                    fileCounters.filesInRop++;
                    string mcc_mnc_lac = fname.substr(0, pos);
                    int filenumber;
                    LOG4CXX_TRACE(loggerPtr,
                                  "MOVE FILES: File name = :  " << fname << " : mcc_mnc_lac = " << mcc_mnc_lac);
                    const char *dir_output_path = outputDirectory.c_str();
                    char fullOutputDirectory[strlen(dir_output_path)
                                             + strlen(mcc_mnc_lac.c_str()) + 1];
                    struct stat new_dirstat;
                    sprintf(fullOutputDirectory, "%s%s", dir_output_path,
                            mcc_mnc_lac.c_str());

                    if(stat(fullOutputDirectory, &new_dirstat) == -1) {  // DIR does not exist .. create it
                        mkdir(fullOutputDirectory, 0750);
                    }

                    stat(fullOutputDirectory, &new_dirstat); // re-read the stats to see if the new directory is there

                    if(!S_ISDIR(new_dirstat.st_mode)) {  // directory should exist now
                        LOG4CXX_ERROR(loggerPtr,
                                      "File not moved; " << fname.c_str() << ". Unable to create directory " << fullOutputDirectory);
                        continue;
                    }

                    char fullOutputFileName[strlen(fullOutputDirectory)
                                            + strlen(fname.c_str()) + 1];
                    sprintf(fullOutputFileName, "%s/%s", fullOutputDirectory,
                            fname.c_str());
                    LOG4CXX_TRACE(loggerPtr,
                                  "MOVE FILES: dir_full_output_filename = :  " << fullOutputFileName);
                    char fullTempFileName[strlen(tempDirectoryPath)
                                          + strlen(fname.c_str()) + 1];
                    sprintf(fullTempFileName, "%s%s", tempDirectoryPath,
                            fname.c_str());
                    LOG4CXX_TRACE(loggerPtr,
                                  "MOVE FILES: dir_full_temp_filename = :  " << fullOutputFileName);
                    // file number is in the outmap.
                    size_t pos2 = fname.find(".log");

                    if(pos2 != std::string::npos) {
                        pos2 = pos2 - 3; // for filenumber "000"
                        string base_filename(fname.substr(0, pos2));
                        LOG4CXX_TRACE(loggerPtr,
                                      "MOVE FILES: Search for " << fullTempFileName << " in OUTMAP");

                        if((fileMap.size() > 0) && (numFilesInOutput > 0)) {
                            OutputFileMap_t::iterator findIter = fileMap.find(
                                    fullTempFileName);

                            if(findIter != fileMap.end()) {
                                filenumber = findIter->second->file_number;
                                LOG4CXX_TRACE(loggerPtr,
                                              "MOVE FIES: Found file " << fullTempFileName << " in Outmap : file number = " << filenumber);
                            } else {
                                filenumber = 99;
                                LOG4CXX_ERROR(loggerPtr,
                                              "MOVE FILES: Unable to determine file number from " << fname.c_str() << " : Setting to 099");
                            }
                        } else { //no map or no files in output directory => new files => fle Number =0;
                            filenumber = 0;
                        }

                        if(filenumber) {  // only change the filename if file Number is non zero
                            sprintf(fullOutputFileName, "%s/%s%03d.%s",
                                    fullOutputDirectory, base_filename.c_str(),
                                    filenumber, kOutputFileVersion);
                            LOG4CXX_TRACE(loggerPtr,
                                          "MOVE FILES: (New) dir_full_output_filename = " << fullOutputFileName);
                        } else {
                            LOG4CXX_TRACE(loggerPtr,
                                          "MOVE FILES: (UnChanged) dir_full_output_filename = " << fullOutputFileName);
                        }
                    } else {
                        LOG4CXX_ERROR(loggerPtr,
                                      "File not moved; " << fname.c_str() << ". Problem generating duplicate file name " << fullOutputDirectory);
                        continue;
                    }

                    int success = rename(fullTempFileName, fullOutputFileName);

                    if(success != 0) {
                        LOG4CXX_ERROR(loggerPtr,
                                      "MOVE FILES: Error moving files from " << fullTempFileName << " to " << fullOutputFileName);
                    } else {
                        numFilesMoved++;
                    }
                }
            }
        }

        closedir(dir);
    } else {
        // Could not open directory.
        LOG4CXX_ERROR(loggerPtr,
                      "The temp directory does not exist, or you don't have access to it.");
    }

    if(fileWriterTimers) {
        time(&endMovingFiles);
        fileCounters.timeTakenToMoveFiles = difftime(endMovingFiles,
                                            startMovingFiles);
    }

    LOG4CXX_INFO(loggerPtr,
                 "Finished moving the temp files to the LAC filtered output directories.");

    if(numFilesMoved != fileCounters.filesInRop) {
        LOG4CXX_ERROR(loggerPtr,
                      "ERROR moving files; NOT ALL FILES MOVED; files_in_rop = " << fileCounters.filesInRop << " : numFilesMoved = " << numFilesMoved);
        return -1;
    } else {
        return numFilesMoved;
    }
}

/*
 * This function checks of the outMap is empty.
 *
 * @param char * when
 *
 * The "when" parameter is for outputting the correct position e.g. before
 * or after the attempt to write.
 * Return -1 if error  or number of entries in Outmap
 */
int checkIfOutMapIsEmpty(const char *when, OutputFileMap_t &fileMap) {
    int numEntriesinMap = 0;

    if(fileMap.size() == 0) {
        LOG4CXX_TRACE(loggerFileWriter, "GZ Map Empty: " << when);
        return 0;
    } else {
        LOG4CXX_WARN(loggerFileWriter, "GZ Map not empty: " << when);

        // Print the remaining content of the hashmap.
        for(OutputFileMap_t::const_iterator outMap_it2 = fileMap.begin();
                outMap_it2 != fileMap.end(); ++outMap_it2) {
            LOG4CXX_WARN(loggerFileWriter,
                         "Map still contains: " << outMap_it2->first);
            numEntriesinMap++;
        }
    }

    return numEntriesinMap;
}

/*
 * This function does a deep erase of the outMap variable.
 *
 * It deletes outKey and outputfilestream, as well as the position in the outMap.
 */
void eraseOutMapAfterROP(OutputFileMap_t &fileMap) {
    file_struct *fs = NULL;
    size_t length = fileMap.size();

    // Erase the contents of the hashmap via a deep deallocation of memory.
    for(size_t i = 0; i < length; ++i) {
        OutputFileMap_t::iterator outMap_it2 = fileMap.begin();

        if(outMap_it2 != fileMap.end()) {
            fs = outMap_it2->second;
            (*fs->zip_stream).flush();
            (*fs->zip_stream).close();
            char *outKey = outMap_it2->first;
            LOG4CXX_TRACE(loggerFileWriter,
                          "CLOSING " << outKey << ": fs->zip_stream = " << * (fs->zip_stream));
            delete[] outKey;
            delete fs->zip_stream;
            delete fs;
            fileMap.erase(outMap_it2);
        }
    }
}

/*
 * This function creates the filename for each merged record in the ROP.
 * The file name is created from data stored in the record and then placed back into the record for later use.
 */
void generateFileNamesForRecords(
    std::vector<struct MergedRecord *> &recordsToPrint,
    const char *fileTypeName, string tempDirectory,
    OutputFileMap_t &fileMap, struct FileCounters &fileCounters) {
    time_t now_merge_time = time(0);
    double now_time = (double) now_merge_time;
    char outputFileName[MAX_DIRECTORY_LENGTH + MAX_FILENAME_LENGTH];

    for(std::vector<struct MergedRecord *>::iterator recordIter =
                recordsToPrint.begin(); recordIter != recordsToPrint.end();
            recordIter++) {
        if(!generateFileName(**recordIter, outputFileName, now_time,
                             tempDirectory, fileTypeName, fileCounters)) {
            writeRecordToFile(outputFileName, &((*recordIter)->theData),
                              fileMap, fileCounters);
        }
    }
}

int printHeaderOnce = 0;
void printGtpu(FlowDataString fds) {
    if(!printHeaderOnce) {
        stringstream gtpuHeader;
        gtpuHeader << *fds.getFlowHeaderString();
        LOG4CXX_DEBUG(loggerFileWriter, gtpuHeader.str());
        printHeaderOnce = 1;
    }

    stringstream gtpu;
    gtpu << *fds.getFlowDataString() << endl;
    LOG4CXX_DEBUG(loggerFileWriter, gtpu.str());
}

void mergeRecord(string &gtpcString, PDPSession *session, FlowDataString &gtpu,
                 vector<struct MergedRecord *> &destination) {
    struct MergedRecord *thisRecord = new MergedRecord();

    if(evaluatedArguments.excludeRATs.find(session->rat)
            == evaluatedArguments.excludeRATs.end()) {
        LOG4CXX_TRACE(loggerFileWriter, "MERGING " << session->rat);
        snprintf(thisRecord->mcc, MCC_MAX_CHARS, "%s", session->locationInfo.mcc);
        snprintf(thisRecord->mnc, MNC_MAX_CHARS, "%s", session->locationInfo.mnc);
        thisRecord->lac = session->locationInfo.lac;
        //Fix for Invalid Start time EQEV-1014
        unsigned int theROPCounter = gtpu.getRopCtr();
        double tmpTime = gtpu.getFirstPacketInRopTime() + (theROPCounter * (60 * kRopDurationInMinutes));

        if(theROPCounter >= 1) {
            roundDownEpoch(&tmpTime, &(thisRecord->recordStartTime));
            //printf("tmpTime = %.6f, v13A.ropStartTime = %.6f\n",tmpTime,v13A->ropStartTime);
        } else {
            thisRecord->recordStartTime = tmpTime;
        }

        thisRecord->theData = gtpcString + *gtpu.getFlowDataString();
        destination.push_back(thisRecord);
        //Temp just for debug of Invalid start time. Can remove later.
        thisRecord->theRopCounter = gtpu.getRopCtr();
        thisRecord->theFirstPacketinROPTime = gtpu.getFirstPacketInRopTime();
    } else {
        LOG4CXX_TRACE(loggerFileWriter, "NOT MERGING " << session->rat);
    }
}

/**
 * cleanup all record in recordlistmap
 *
 */
void cleanUpRecordList(vector<struct MergedRecord *> &list) {
    for(vector<struct MergedRecord *>::iterator it = list.begin();
            it != list.end(); it++) {
        delete(*it);
    }

    list.clear();
}

/*
 * Write To File function
 *
 * A function that writes the current record to the open Compression file buffer.
 *
 * @return 0 if error.
 * @return 1 if OK.
 */
int writeToFile(string *theData, file_struct *fs, char *outputFileName,
                struct FileCounters &fileCounters) {
    if(fileWriterTimers) {
        time(&fileCounters.startOfFileWriter);
    }

    //TODO if filestream is zero, then error
    if(!(*(fs->zip_stream)).good()) {
        LOG4CXX_WARN(loggerFileWriter,
                     "DATA LOSS when writing to file due to error RETREVING file Stream " << * (fs->zip_stream) << " for file : " << outputFileName);
        return 0;
    } else {
        *(fs->zip_stream) << *theData << endl;
    }

    // Logging the number of records in the ROP. LUKE - also increment the file_struct->records_in_file here.
    fileCounters.recordsInRop++;

    if(fileWriterTimers) {
        time(&fileCounters.endOfFileWriter);
        fileCounters.timeToWriteToFile = fileCounters.timeToWriteToFile
                                         + (difftime(fileCounters.endOfFileWriter,
                                                 fileCounters.startOfFileWriter));
    }

    return 1;
}

/**
 * Algorithm:
 *   Loop through the ogzstream map
 *     See if we have a mapping for outputFileName
 *     If we do
 *       Get the ogzstream + set to a variable
 *     If we don't find it...
 *       Allocate some new memory on the heap for the filename, ie: char key = new char[SIZE];
 *     Create a new ogzstream object on the heap also
 *     Add the items to the map
 *   End loop
 *   write the record to the ostream.
 */
int writeRecordToFile(char *fileName, string *theData, OutputFileMap_t &fileMap,
                      struct FileCounters &fileCounters) {
    int state = 0;
    file_struct *fs;

    if(fileWriterTimers) {
        time(&fileCounters.startCreatingStreams);
    }

    int found = 0; // Variable to denote weather we've found a matching filename in in the hashmap of file pointers
    OutputFileMap_t::iterator findIter = fileMap.find(fileName);

    if(findIter != fileMap.end()) {
        fs = findIter->second;
        fs->records_in_file += 1;
        found = 1;
        fileCounters.filesReusedOgz++;
        state = 1;

        if(!(*(fs->zip_stream)).good()) {
            LOG4CXX_ERROR(loggerFileWriter,
                          "DATA LOSS due to error RETREVING file Stream " << * (fs->zip_stream) << " for file : " << *fileName);
            fs = NULL;
            state = 0;
        }
    } else { // Create a new output file pointer and add it to the hashmap of file pointers
        char *key = new char[MAX_FILENAME_LENGTH + MAX_DIRECTORY_LENGTH];
        snprintf(key, MAX_FILENAME_LENGTH + MAX_DIRECTORY_LENGTH, "%s",
                 fileName);
        fs = new file_struct();
        fs->zip_stream = new ogzstream(key);
        fs->file_number = 0;
        LOG4CXX_TRACE(loggerFileWriter,
                      "OPENING " << *fileName << ": fs->zip_stream = " << * (fs->zip_stream));

        if(!(*(fs->zip_stream)).good()) {
            LOG4CXX_ERROR(loggerFileWriter,
                          "DATA LOSS due to UNABLE to opening file " << *fileName);
            fs = NULL;
        }

        fs->records_in_file = 1;
        fileMap[key] = fs;
        fileCounters.filesCreatedOgz++;
        state = 1;
    }

    if(fileWriterTimers) {
        time(&fileCounters.finishedCreatingStreams);
        fileCounters.timeForGettingGzipStreamReference =
            fileCounters.timeForGettingGzipStreamReference
            + (difftime(fileCounters.finishedCreatingStreams,
                        fileCounters.startCreatingStreams));
    }

    if(fs != NULL) {
        state = writeToFile(theData, fs, fileName, fileCounters);
    }

    return state;
}

/*
 * This function logs the statistics from FileWriter.
 *
 * It outputs various function related timers to the DEBUG log. It also outputs
 * numbers related to files in the ROP to the INFO log. Then the stats on the
 * merge to the INFO log. Lastly it resets the counters in the counter struct.
 */
void logFileWriterStats(struct FileCounters &fileCounters,
                        LoggerPtr loggerPtr) {
    if(loggerPtr->isDebugEnabled()) {
        LOG4CXX_DEBUG(loggerPtr,
                      "Printing all queues: generateFileName took " << fileCounters.timeForGenerateFileName << " seconds");
        LOG4CXX_DEBUG(loggerPtr,
                      "Printing all queues: getting compressed stream reference from hash map took " << fileCounters.timeForGettingGzipStreamReference << " seconds");
        LOG4CXX_DEBUG(loggerPtr,
                      "Printing all queues: writeToFile took " << fileCounters.timeToWriteToFile << " seconds");
        LOG4CXX_DEBUG(loggerPtr,
                      "Merging Records took " << fileCounters.timeToMerge << " seconds");
        LOG4CXX_DEBUG(loggerPtr,
                      "Reading output directory took " << fileCounters.timeTakenToReadOutput << " seconds");
        LOG4CXX_DEBUG(loggerPtr,
                      "Moving files from temp to output directory took " << fileCounters.timeTakenToMoveFiles << " seconds");
    }

    // Output Logging.
    // files_in_rop calculated in MoveFilesFromTempDirToOutputDir() or MoveFilesFromTempDirToOutputDir2()
    if(fileCounters.filesInRop < 0) {
        fileCounters.filesInRop = 0; // Make the files_in_rop, be greater than or equal to zero.
    }

    time_t endOfPrintAllRecordsToFile = time(0);
    float merged_percentage = 0.0;

    if(fileCounters.total > 0) {
        merged_percentage = (float) fileCounters.merged
                            / (float)(fileCounters.total - fileCounters.ratExcluded);
    }

    // Determine weather to output "seconds" or "second" in the Merge message.
    string secondsTerminationMessage = " seconds.";
    int mergeDuration = (int)(endOfPrintAllRecordsToFile
                              - fileCounters.startOfPrintAllRecordsToFile);

    if(mergeDuration == 1) {
        secondsTerminationMessage = " second.";
    }

    // Log a warning if the time take to merge is more than the ROP length in minutes.
    if(mergeDuration > (kRopDurationInMinutes * 60)) {
        LOG4CXX_WARN(loggerPtr,
                     "MERGE STATS:" << " Merged: " << fileCounters.merged << " Excluded by RAT: " << fileCounters.ratExcluded << " Total: " << fileCounters.total << " Merged percentage: " << (merged_percentage * 100) << "%" << " Duration: " << mergeDuration << secondsTerminationMessage);
    } else {
        LOG4CXX_INFO(loggerPtr,
                     "MERGE STATS:" << " Merged: " << fileCounters.merged << " Excluded by RAT: " << fileCounters.ratExcluded << " Total: " << fileCounters.total << " Merged percentage: " << (merged_percentage * 100) << "%" << " Duration: " << mergeDuration << secondsTerminationMessage);
    }

    // Output the minimum information for "FILE STATS" unless DEBUG is enabled.
    if(loggerPtr->isDebugEnabled()) {
        LOG4CXX_DEBUG(loggerPtr,
                      "FILE STATS:" << " Output files created in ROP: " << fileCounters.filesInRop << " Files in OUT MAP: " << fileCounters.filesInOutMap << " Files Re-Accessed: " << fileCounters.filesReusedOgz << " Records in ROP: " << fileCounters.recordsInRop);
    } else {
        LOG4CXX_INFO(loggerPtr,
                     "FILE STATS:" << " Output files created in ROP: " << fileCounters.filesInRop << " Records in ROP: " << fileCounters.recordsInRop);
    }

    LOG4CXX_INFO(loggerPtr, "Finished printing UE Map.");
    fileCounters.resetToZero();
}

void fileWriterThreadCloseCleanup(void *init) {
    LOG4CXX_INFO(loggerFileWriter, "Stopping FileWriter.");

    if(init != NULL) {
        // Put any cleanup here:
        FileWriterMapManager *manager = (FileWriterMapManager *) init;
        delete(manager);
    }
}

/*
 * makes a call to an external cleanup script.
 *
 */
int removeOldFiles() {
    FILE *fileCleanUpMessage =
        popen(
            ("find /" + evaluatedArguments.outputlocation
             + " -mmin +120 -type f -exec  rm -f \\{\\} \\; 2>&1 ").c_str(),
            "r");

    if(NULL == fileCleanUpMessage) {
        LOG4CXX_ERROR(loggerFileWriter, "Failed to perform the file Cleanup");
        return -1;
    }

    char message[1000];

    if(fgets(message, 1000, fileCleanUpMessage) == NULL) {
        strcpy(message, "Cleanup success.");
    }

    int returnedValue = pclose(fileCleanUpMessage);
    LOG4CXX_INFO(loggerFileWriter, message << "Cleanup Returned value:" << WEXITSTATUS(returnedValue));
    LOG4CXX_INFO(loggerFileWriter, message);
    return returnedValue;
}

int removeEmptyDirectoriesUnderPath(string &path) {
    LOG4CXX_INFO(loggerFileWriter, "Removing empty directories under " << path);
    FILE *fileCleanUpMessage = popen(("find /" + path
                                      +  " ! -samefile " + path + " -type d -empty | xargs --no-run-if-empty rm -r ; 2>&1 "
                                     ).c_str(), "r");

    if(NULL == fileCleanUpMessage) {
        LOG4CXX_ERROR(loggerFileWriter, "Failed to perform the directory Cleanup");
        return -1;
    }

    char message[1000];

    if(fgets(message, 1000, fileCleanUpMessage) == NULL) {
        strcpy(message, "Directory cleanup completed.");
    }

    int returnedValue = pclose(fileCleanUpMessage);
    LOG4CXX_INFO(loggerFileWriter, message << "Cleanup Returned value:" << WEXITSTATUS(returnedValue));
    LOG4CXX_INFO(loggerFileWriter, message);
    return returnedValue;
}

/*
 * Cloned child function which has its pre-allocated memory 
 * Calls pcp-cleanup.bsh to do the cleanup with parameters of  evaluatedArguments.outputlocation and 0 to indicate script to print ERROR info only
 * Will not return if the execl call is successful;
 * Will return -1 if there is a problem running the script;
 */ 
int do_cleanup_child(void *) {
	int ret = execl("/opt/ericsson/pcp/pect/pect/pcp-cleanup.bsh", "/opt/ericsson/pcp/pect/pect/pcp-cleanup.bsh", outputDirectoryPath, "0", NULL);

	//This print out is after execl() and should not be executed if execl were successful; excel does not return if successful 
	LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_child: Failed to perform the Cleanup: excel return value is " << ret)
	_Exit(1);

}

/*
 * Cloned child function which has its pre-allocated memory 
 * Calls pcp-cleanup.bsh to do the cleanup with parameters of  evaluatedArguments.outputlocation and 1 to indicate script to print debug  type info
 * Will not return if the execl call is successful;
 * Will return -1 if there is a problem running the script;
 */ 
int do_cleanup_child_debug(void *) {
	//  THESE DEBUG STATEMENTS are causing mutex issues with parent as both try to access log file at the same time with same file reference
	//  terminate called after throwing an instance of 'log4cxx::helpers::MutexException'
    //  what():  Mutex exception: stat = 1
	
	//LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_child: STARTING CLEANUP IN CLONED CHILD");
	//LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_child: Child:  PID= " << (long) getpid() << ": PPID= " << (long) getppid()); 
	//LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_child: Directory : " <<  outputDirectoryPath);
	int ret = execl("/opt/ericsson/pcp/pect/pect/pcp-cleanup.bsh", "/opt/ericsson/pcp/pect/pect/pcp-cleanup.bsh", outputDirectoryPath, "1", NULL);
	
	//This print out is after execl() and should not be executed if execl were successful; excel does not return if successful 
	LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_child: Failed to perform the Cleanup: excel return value is " << ret)
	_Exit(1);

}
/*
 * Function that clones a child proces so that exec can be called to run linux commands.
 * 
 * fork() which is used by POPEN() (in the Functions removeOldFiles() and removeEmpthyDirectoriesUnderPath)
 * is slow and memory inefficent. But a seperate process is required to allow linux commands to be run using exec() as 
 * the exec() family of commands will  destroy all threads other than the calling thread.
 * 
 * By using clone(), a child process can be created which runs in the same memory space as the parent. This means that no memory structures are 
 * copied when the child process is created (memory efficient) and as it is a seperate process, exec() can be called with out destroying any other threads
 * or the parent process.
 * 
 */ 
int do_cleanup_parent(const int STACK_SIZE, char *child_stack) {
	char *stackTop;     // End of stack buffer area
	pid_t child_pid, wait_pid;
	int status;
	if(loggerFileWriter->isDebugEnabled()) {
		LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Filewriter Parent: PID= "<< (long) getpid() << " PPID= " << (long) getppid() << ": STACK_SIZE = " << STACK_SIZE);
	}
	
	if (child_stack == NULL) {
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Failed to perform the Cleanup : ERROR NO STACK ALLOCATED FOR CHILD CLONE\n") ;
		return -1; 
	}
	else {
		stackTop = child_stack + STACK_SIZE;  /* Assume stack grows downward */
		if(loggerFileWriter->isDebugEnabled()) {
			child_pid=clone(do_cleanup_child_debug, stackTop, CLONE_VM, NULL);
		}
		else {
			child_pid=clone(do_cleanup_child, stackTop, CLONE_VM, NULL);
		}
		if( child_pid == -1) {
			LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: ERROR CLONING CHILD\n") ;
			return -1; 
		}
		else {
			if(loggerFileWriter->isDebugEnabled()) {
				LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: CHILD PID = " <<  (long) child_pid ) ;
			}
			wait_pid = waitpid(child_pid, &status, __WALL | __WNOTHREAD);
			if (wait_pid == -1){
				LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: ERROR WAITING FOR CHILD PROCESS; You need to check for Zombie Process\n") ;
				return -1; 
			} 
			else {
				if (WIFEXITED(status)) {
					if(loggerFileWriter->isDebugEnabled()) {
						LOG4CXX_DEBUG(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Child with PID = " << (long) wait_pid << " has exited, status = " << WEXITSTATUS(status));
					}
					return WEXITSTATUS(status);
				} else if (WIFSIGNALED(status)) {
					LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Child with PID = " << (long) wait_pid << " has been killed by signal; status = " << WTERMSIG(status));
					return WTERMSIG(status);
				} else if (WIFSTOPPED(status)) {
					LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Child with PID = " << (long) wait_pid << " has stopped by signal; status = " << WSTOPSIG(status));
					return WIFSTOPPED(status);
				} else if (WIFCONTINUED(status)) {
					LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: Child with PID = " << (long) wait_pid << " has continued ;  You need to check for Zombie Process"  );
					return WIFCONTINUED(status);
				}
			}
		} 
	}     
	LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: do_cleanup_parent: UNKNOWN  ERROR \n") ;
	return -1;
}

void  do_cleanup_checkReturnValue(int theStatus, long timeTakenToCleanup_uS) {
   if(theStatus == 0) {
		LOG4CXX_INFO(loggerFileWriter, "PCP Cleanup: All cleanup finished : SUCCESS (status = " << theStatus << ") in " << timeTakenToCleanup_uS << " micro Seconds" );
	}
	else if(theStatus == 1){
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: All cleanup finished but ERROR cleaning old files (status = " << theStatus << ") in " << timeTakenToCleanup_uS << " micro Seconds" );
	}
	else if(theStatus == 2){
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: All cleanup finished but ERROR cleaning old empty directories (status = " << theStatus <<") in " << timeTakenToCleanup_uS << " micro Seconds");
	}
	else if(theStatus == 3){
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: USAGE ERROR (status = " << theStatus << ") in " << timeTakenToCleanup_uS << " micro Seconds" );
	}
	else if(theStatus == -1){
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: All cleanup finished but ERROR cleaning due to System Resource Reasons (status = " << theStatus << ") in " << timeTakenToCleanup_uS << " micro Seconds");
	}
	else{
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: All cleanup finished but ERROR cleaning due to UNKNOWN Reasons (status = " << theStatus << ") in " << timeTakenToCleanup_uS << " micro Seconds" );
	}
			
}
/*
 * The function to run the printUeMap() function.
 *
 * This function determines the time until the next ROP is due,
 * then sleeps that length and prints the UE map.
 */
void *threadForPrintUeMap(void *init) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    pthread_attr_t captoolAttr;
    pthread_attr_init(&captoolAttr);
    pthread_t captoolThread;
    pthread_attr_t stapleAttr;
    pthread_attr_init(&stapleAttr);
    pthread_t stapleThread;
    prctl(PR_SET_NAME, "fileWriter_main", 0, 0, 0);
    waitForFileWriter = 0;
    defineKconstants();   // File writer core constants
    initPectFileWriter(); // PECT file writer constants
    initCaptoolFileWriter();
    initStapleFileWriter();
    unsigned int sinkCount;
    struct timeval startCleanup, endCleanup;
    unsigned long long timeTakenToCleanup_uS;
    
	// for Cleanup Clone
	const int STACK_SIZE = 65536;       // Stack size for cloned child 
	char *child_stack;                  // Start of stack buffer area 

	child_stack = (char *) malloc(STACK_SIZE);
	if (child_stack == NULL) {
		LOG4CXX_ERROR(loggerFileWriter, "PCP Cleanup: Failed to perform the directory Cleanup : MAOLOC ERROR\n") ; 
	}
		
	
    if(evaluatedArguments.packetBufferSinkCount >= 1) {
        sinkCount = evaluatedArguments.packetBufferSinkCount;
    } else {
        sinkCount = MAX_NUM_FLOWS_SUPPORTED;
    }

    if(loggerFileWriter->isDebugEnabled()) {
        fileWriterTimers = 1;
    } else {
        fileWriterTimers = 0;
    }

    LOG4CXX_INFO(loggerFileWriter, "Starting File Writer");
    //Print the header for DEBUG Print of ThroughPut Metrics just one
    fileWriterPrintTP_Header();
    printPktLossRateInfo_Header();
    int doFileCleanupCounter = 0;
    FileWriterMapManager *manager = FileWriterMapManager::getInstance();
    FileWriterMap *mapToConsume;
    std::list<FileWriterMap *> rop;
    pthread_cleanup_push(fileWriterThreadCloseCleanup, manager);

    while(1) {
        while(rop.size() < sinkCount) {  // Keep pulling maps until we're at the expected number (== number of sink threads)
            mapToConsume = manager->consumeMap(); // Blocks until there is a map available
            mapToConsume->lockMap();
            rop.push_back(mapToConsume);
        }

        LOG4CXX_INFO(loggerFileWriter,
                     "--------------------------------------------------------------------------");
        LOG4CXX_INFO(loggerFileWriter, "Consuming event data");

        //if(evaluatedArguments.fileOutputFormat.compare("legacy") == 0) {
        if(!pectFileOutputFormat_isPect) {   // 0=Legacy 1=Pect
            // Print the captool/staple formatted files
            // No cancel during file writing to avoid seg faults
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
            pthread_create(&captoolThread, &captoolAttr, printUPDataCaptool, &rop);
            pthread_create(&stapleThread, &stapleAttr, printUPDataStaple, &rop);
            pthread_join(captoolThread, NULL);
            pthread_join(stapleThread, NULL);
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        } else {
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
            printUeMap(&rop);
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        }

        for(list<FileWriterMap *>::iterator it = rop.begin();
                it != rop.end(); ++it) {
            (*it)->unlockMap();
            manager->freeMap((*it));
        }

        if(doFileCleanupCounter >= FILE_CLEANUP_INTERVAL - 1) {
			
            LOG4CXX_INFO(loggerFileWriter, "PCP Cleanup: Starting periodic cleanup.");
            // CLONE AND EXECL METHOD
            gettimeofday(&startCleanup, NULL);
            int cleanupReturn = do_cleanup_parent(STACK_SIZE, child_stack);
            gettimeofday(&endCleanup,NULL); 
            timeTakenToCleanup_uS = ((endCleanup.tv_sec - startCleanup.tv_sec) * 1000000) + (endCleanup.tv_usec - startCleanup.tv_usec);
			do_cleanup_checkReturnValue(cleanupReturn, timeTakenToCleanup_uS);
			
			
			/* 
			// POPEN METHOD
			gettimeofday(&startCleanup, NULL);
            removeOldFiles();

			if(!pectFileOutputFormat_isPect) {   // 0=Legacy 1=Pect
                removeEmptyDirectoriesUnderPath(stapleOutputDirectory);
                removeEmptyDirectoriesUnderPath(captoolOutputDirectory);
            } else {
                removeEmptyDirectoriesUnderPath(kOutputDirectory);
            }
            gettimeofday(&endCleanup,NULL); 
            timeTakenToCleanup_uS = ((endCleanup.tv_sec - startCleanup.tv_sec) * 1000000) + (endCleanup.tv_usec - startCleanup.tv_usec);
			
            LOG4CXX_INFO(loggerFileWriter, "PCP Cleanup: All cleanup finished in " << timeTakenToCleanup_uS << " micro Seconds") 
            */

            doFileCleanupCounter = 0;
            
        } else {
            doFileCleanupCounter++;
        }

        LOG4CXX_INFO(loggerFileWriter, "--------------------------------------------------------------------------");
        rop.clear();
    }

    pthread_cleanup_pop(1);
    //when cancel , executing will jump here, after cleanup
    LOG4CXX_INFO(loggerFileWriter, "fileWriter module closed.");
    return NULL;
    //return 1;  // The apocalypse happened
}

/**
 * input printedRop Epoch minutes
 * output printedRop
 */
void sleepTillNextRop(time_t &printedRop) {
    time_t now;

    while(true) {
        sleep(1);
        time(&now);
        time_t r = now % 60;
        time_t currentRop = (time_t) floor(static_cast<double>(now) / 60.0);

        if((r >= 5) && (r < 57)) {  // offset 5 seconds
            time_t distance = currentRop - printedRop; //find distance of print Rop and current Rop in minutes

            if((distance < kRopDurationInMinutes) && (distance >= 0)) {  //still in the same ROP
                //do nothing
            } else {
                if((distance > kRopDurationInMinutes)  //in the next rop, do the printing
                        && (0 != printedRop)) {
                    LOG4CXX_ERROR(loggerFileWriter,
                                  "Rop missed:" << (distance / kRopDurationInMinutes) << "Current: " << currentRop << " last output:" << printedRop);
                } else {
                    if(distance < 0 && 0 != printedRop) {
                        LOG4CXX_ERROR(loggerFileWriter,
                                      "Rop Error. System clock seems to have been changed. Distance:" << distance << "Current: " << currentRop << " last output:" << printedRop);
                    }
                }

                printedRop = currentRop;
                break;
            }
        }
    }
}

