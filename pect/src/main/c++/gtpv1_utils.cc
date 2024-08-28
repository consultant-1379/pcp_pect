/*
 * gtpv1_utils.cc


 *
 *  Created on: 12 Jul 2012
 *      Author: emilawl
 */
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstring>
#include <list>
#include "ArgProcessor.h"
#include "gtpv1_utils.h"
#include "logger.hpp"
#include "ipq_api.h"
#include "flow.h"
#include <sstream>

using std::stringstream;
using std::ofstream;
using std::string;
using std::list;
using namespace log4cxx;

int interval;
const char *instance_tag = NULL;
struct EArgs evaluatedArguments;

int processAndApplyArgs(vector<RequiredArgument> &theRequired, SuppliedArguments &theSupplied);

// efitleo
// keep descriptions less than RAT_MAX_CHARS long
const char *RAT_DESCRIPTIONS[] = {
    "RESERVED",
    "WCDMA", //UTRAN
    "GSM",   //GERAN
    "WLAN",
    "GAN",
    "HSPA+", //HSPA-evolution (HSPA+)
    "LTE",   //E-UTRAN
    "UNKNOWN"
};

/**
 *
 * Utility function to create directory
 *
 */
void makeDir(string theDirectory) {
    string cmd;
    cmd = "mkdir -p " + theDirectory;

    if(system(cmd.c_str())) {
        LOG4CXX_ERROR(loggerGtpcMap, "Unable to create the directory path :" + theDirectory + ": mkdir failed ");
        LOG4CXX_ERROR(loggerConfiguration, "Unable to create the directory path :" + theDirectory + ": mkdir failed ");
    } else {
        LOG4CXX_DEBUG(loggerConsole, "Created directory : " + theDirectory);
        LOG4CXX_INFO(loggerConfiguration, "Created directory : " + theDirectory);
    }
}

/**
 *
 * Utility function to set permissions on a directory
 *
 */
void chmodDir(string thePermission, string theDirectory) {
    string cmd;
    cmd = "chmod -R " + thePermission + " " + theDirectory;

    if(system(cmd.c_str())) {
        LOG4CXX_ERROR(loggerGtpcMap, "Unable to set permissions on directory " + theDirectory + ": chmod failed ");
        LOG4CXX_ERROR(loggerConfiguration, "Unable to set permissions on directory " + theDirectory + ": chmod failed ");
    } else {
        LOG4CXX_DEBUG(loggerConsole, "Set permissions " + thePermission + " on directory : " + theDirectory);
        LOG4CXX_INFO(loggerConfiguration, "Set permissions " + thePermission + " on directory : " + theDirectory);
    }
}

/**
 *
 * create directory
 *
 * createHierarchy =0 means create captool/staple and pect directorys only
 * createHierarchy =1 means create captool/staple and pect directorys with full 3g  paths
 * createHierarchy =2 or any thing else  means no captool/staple or pect directorys created
 *
 *
 */
void createDir(string thePath, string thePermissions, int createHierarchy) {
    struct stat new_dirstat;
    // don's handle root directories [path = /]
    //printf("%d\n",(int) strlen(thePath.c_str()));
    int pathLength = (int) strlen(thePath.c_str());

    if(pathLength < 2) {
        return;
    }

    LOG4CXX_DEBUG(loggerConsole, "Checking if directory : " + thePath + " exists, with file permissions : " + thePermissions);
    LOG4CXX_INFO(loggerConfiguration, "Checking if directory : " + thePath + " exists, with file permissions : " + thePermissions);

    if(stat(thePath.c_str(), &new_dirstat) == -1) {     // DIR does not exist .. create it
        if(createHierarchy == 0) {
            makeDir(thePath + "/captool");
            makeDir(thePath + "/staple");
            makeDir(thePath + "/pect");
        } else if(createHierarchy == 1) {
            makeDir(thePath + "/captool/3g");
            makeDir(thePath + "/staple/3g/tcpta-partial");
            makeDir(thePath + "/pect/3g");
        } else if(createHierarchy == 2) {
            makeDir(thePath);
        } else {
            makeDir(thePath);
        }

        //chmod the top dir with -R
        chmodDir(thePermissions, thePath);
    } else {
        LOG4CXX_DEBUG(loggerConsole, "Directory : " + thePath + " already exists");
        LOG4CXX_INFO(loggerConfiguration, "Directory : " + thePath + " already exists");
    }
}



void setCdpDecodeHostsLevel(const string &theCdpDecodeHostsLevel) {
    if(theCdpDecodeHostsLevel.length() > 0) {
        evaluatedArguments.cdpDecodeHostsLevel.clear();
        char *cstr = new char[theCdpDecodeHostsLevel.length() + 1];
        snprintf(cstr, theCdpDecodeHostsLevel.length() + 1, "%s", theCdpDecodeHostsLevel.c_str());
        char *p = std::strtok(cstr, ",");
        int n, cdp_value;

        while(p != 0) {
            if(p != NULL) {
                n = sscanf(p, "%d", &cdp_value);

                if((n != 1) || (p == NULL)) {
                    throw string("CDP INFO: Format for the poroperty  \'customProtocols_decodeLevelForHosts\' is incorrent, expect format is \'<number1>,<number2>,<number3,<number4>,<number5>,<number6>,<number7>\'  : input was ") + theCdpDecodeHostsLevel;
                } else {
                    LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Processing Custom Protocol Host Level from \'customProtocols_decodeLevelForHosts\' : cdp_value = " << cdp_value);
                    evaluatedArguments.cdpDecodeHostsLevel.push_back(cdp_value);
                }
            }

            p = strtok(NULL, ",");
        }

        delete[] cstr;
    }
}
void setCdpDecodeUsingExtraHosts(const string &theCdpDecodeUsingExtraHosts) {
    if(strcmp(theCdpDecodeUsingExtraHosts.c_str(), "true") == 0) {
        evaluatedArguments.cdpDecodeExtraHosts = true;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using EXTRA HOST information is Enabled");
    } else {
        evaluatedArguments.cdpDecodeExtraHosts = false;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using EXTRA HOST information is Disabled");
    }
}

void setCdpDecodeUsingUserAgent(const string &theCdpDecodeUsingUserAgent) {
    if(strcmp(theCdpDecodeUsingUserAgent.c_str(), "true") == 0) {
        evaluatedArguments.cdpDecodeUserAgent = true;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using USER AGENT information is Enabled");
    } else {
        evaluatedArguments.cdpDecodeUserAgent = false;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using USER AGENT information is Disabled");
    }
}

void setCdpDecodeUsingURL(const string &theCdpDecodeUsingURL) {
    if(strcmp(theCdpDecodeUsingURL.c_str(), "true") == 0) {
        evaluatedArguments.cdpcdpDecodeURL = true;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using URL information is Enabled");
    } else {
        evaluatedArguments.cdpcdpDecodeURL = false;
        LOG4CXX_INFO(loggerConfiguration, "CDP INFO: Decode Custom Protocols using URL information is Disabled");
    }
}

/*
 *
void setIpoquePaceLicenseFile(const string &theIpoquePaceLicenseFile) {
    evaluatedArguments.ipoquePaceLicenseFile = theIpoquePaceLicenseFile;
}
*/
void setGTPCSessionTimeoutAge(const string &theTimeout) {
    int n = sscanf(theTimeout.c_str(), "%i", &evaluatedArguments.gtpcSessionTimeoutAge);

    if(n != 1) {
        throw string("Hash size must be numeric: input was ") + theTimeout;
    }

    LOG4CXX_INFO(loggerConfiguration, "gtpcSessionTimeoutAge = " << evaluatedArguments.gtpcSessionTimeoutAge);
}

void setGTPCSessionTimeoutFrequency(const string &theFrequency) {
    int n = sscanf(theFrequency.c_str(), "%i", &evaluatedArguments.gtpcSessionTimeoutFrequency);

    if(n != 1) {
        throw string("Hash size must be numeric: input was ") + theFrequency;
    }

    LOG4CXX_INFO(loggerConfiguration, "gtpcSessionTimeoutFrequency = " << evaluatedArguments.gtpcSessionTimeoutFrequency);
}


void setIpoqueTimeout(const string &theTimeout) {
    int n = sscanf(theTimeout.c_str(), "%i", &evaluatedArguments.ipqConnectionNormalTimeout);

    if(n != 1) {
        throw string("Ipoque Normal timeout must be numeric: input was ") + theTimeout;
    }

    LOG4CXX_INFO(loggerConfiguration, "Ipoque Normal Timeout of : " << evaluatedArguments.ipqConnectionNormalTimeout << "s will be used");
}


void setIpoqueShortTimeout(const string &theShortTimeout) {
    int n = sscanf(theShortTimeout.c_str(), "%i", &evaluatedArguments.ipqConnectionShortTimeout);

    if(n != 1) {
        throw string("Ipoque Short timeout must be numeric: input was ") + theShortTimeout;
    }

    LOG4CXX_INFO(loggerConfiguration, "Ipoque Short Timeout of : " << evaluatedArguments.ipqConnectionShortTimeout << "s will be used");
}


void setIpoqueLongTimeout(const string &theLongTimeout) {
    int n = sscanf(theLongTimeout.c_str(), "%i", &evaluatedArguments.ipqConnectionLongTimeout);

    if(n != 1) {
        throw string("Ipoque Long timeout must be numeric: input was ") + theLongTimeout;
    }

    LOG4CXX_INFO(loggerConfiguration, "Ipoque Long Timeout of : " << evaluatedArguments.ipqConnectionLongTimeout << "s will be used");
}

void setFileOutputFormat(const string &fileOutputFormat) {
    evaluatedArguments.fileOutputFormat = fileOutputFormat;
}

void setMinFlowSize(const string &minFlowSize) {
    int n = sscanf(minFlowSize.c_str(), "%i", &evaluatedArguments.minFlowSize);

    if(n != 1) {
        throw string("Hash size must be numeric: input was ") + minFlowSize;
    }

    LOG4CXX_INFO(loggerConfiguration, "minFlowSize = " << evaluatedArguments.minFlowSize);
    LOG4CXX_DEBUG(loggerConsole, "minFlowSize = " << evaluatedArguments.minFlowSize);
}

void setPacketBufferSize(const string &thePBSize) {
    int n = sscanf(thePBSize.c_str(), "%i", &evaluatedArguments.packetBufferSize);

    if(n != 1) {
        throw string("Hash size must be numeric: input was ") + thePBSize;
    }

    LOG4CXX_INFO(loggerConfiguration, "Packet Buffer Size = " << evaluatedArguments.packetBufferSize << "[each]");
}

void setUse_multiple_packetBuffers(const string &setUseMultiplePacketBuffers) {
    if(strcmp(setUseMultiplePacketBuffers.c_str(), "true") == 0) {
        evaluatedArguments.useMultiplePacketBuffers = true;
        LOG4CXX_INFO(loggerConfiguration, "Multiple Packet buffers = TRUE");
    } else {
        evaluatedArguments.useMultiplePacketBuffers = false;
        LOG4CXX_INFO(loggerConfiguration, "Multiple Packet buffers = FALSE");
    }
}
//efitleo: added packet buffer config items

void setPacketBufferCaptureFrom(const string &theCapture_from) {
    unsigned int foundLive = -1;
    unsigned int foundFile = -1;
    foundLive = (unsigned int) theCapture_from.find("LIVE");

    if(foundLive == 0) {
        evaluatedArguments.packetBufferCaptureType = 1;
        LOG4CXX_INFO(loggerConfiguration, "UTILS: found LIVE Option ");
        return;
    }

    foundFile = (unsigned int) theCapture_from.find("FILE");

    if(foundFile == 0) {
        evaluatedArguments.packetBufferCaptureType = 0;
        LOG4CXX_INFO(loggerConfiguration, "UTILS: found FILE Option ");
        return;
    }

    if((foundFile == std::string::npos) & (foundLive == std::string::npos)) throw string(
            "Packet Buffer Capture From must be either  LIVE or FILE: input was ") + theCapture_from;
}

void setPacketBufferGtpuSourceName(const string &theGtpuSourceName) {
    if(theGtpuSourceName.length() > 0) {
        char *cstr = new char[theGtpuSourceName.length() + 1];
        snprintf(cstr, theGtpuSourceName.length() + 1, "%s", theGtpuSourceName.c_str());
        char *p = std::strtok(cstr, ",");

        while(p != 0) {
            evaluatedArguments.packetBufferGtpuSourceName.push_back(p);
            p = strtok(NULL, ",");
        }

        delete[] cstr;
        list<string>::iterator i;
        evaluatedArguments.packetBufferSourceCount = 0;

        for(i = evaluatedArguments.packetBufferGtpuSourceName.begin();
                i != evaluatedArguments.packetBufferGtpuSourceName.end(); ++i) {
            evaluatedArguments.packetBufferSourceCount++;
        }
    }
}

void setPacketBufferSinkCount(const string &theSink_count) {
    int n = sscanf(theSink_count.c_str(), "%i", &evaluatedArguments.packetBufferSinkCount);

    if(n != 1) {
        throw string("File interval must be numeric: input was ") + theSink_count;
    }
}

void setPacketBufferMacOfKnownElement(const string &theMacOfKnownElement) {
    if(theMacOfKnownElement.length() > 0) {
        char buffer[theMacOfKnownElement.length() + 1];
        char cstr[theMacOfKnownElement.length() + 1];
        snprintf(cstr, theMacOfKnownElement.length() + 1, "%s", theMacOfKnownElement.c_str());
        unsigned int j = 0;
        unsigned int i;

        for(i = 0; i < strlen(cstr); i++) {
            if(cstr[i] != ':') {
                buffer[j++] = cstr[i];
            }
        }

        buffer[j] = '\0';
        char *p = std::strtok(buffer, ",");
        unsigned long macAddr = 0;
        char *pEnd;

        while(p != 0) {
            //LOG4CXX_INFO(loggerConfiguration, p);
            macAddr = strtoul(p, &pEnd, 16);
            evaluatedArguments.packetBufferMacOfKnownElement.push_back(macAddr);
            p = strtok(NULL, ",");
        }

        list<unsigned long>::iterator itr;
        evaluatedArguments.packetBufferMacOfKnownElementCount = 0;

        for(itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
                itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++itr) {
            evaluatedArguments.packetBufferMacOfKnownElementCount++;
        }
    }
}

void setExcludeRATNumber(const string &value) {
    evaluatedArguments.excludeRATs.clear();
    std::stringstream ss(value);
    string item;
    int  ratNum = 0;

    while(std::getline(ss, item, ',')) {
        ratNum = atoi(item.c_str());

        if(ratNum >= 0 && ratNum < NUM_OF_RAT_DESCRIPTION) {
            evaluatedArguments.excludeRATs[RAT_DESCRIPTIONS[ratNum]] = ratNum;
        }
    }
}

void outputErrorMessage(const string &first, const string &second) {
    string message(first);
    message += second;
    LOG4CXX_ERROR(loggerConfiguration, message);
}

void setGTPCVersion(const string &theVersion) {
    evaluatedArguments.GTPCVersion = theVersion;
}

void setGTPCInput(const string &theInput) {
    evaluatedArguments.GTPCInput = theInput;
}

void setGTPCInstanceTag(const string &theInstanceTag) {
    evaluatedArguments.GTPCInstance_tag = theInstanceTag;
}

void setGTPFileInterval(const string &theInterval) {
    int n = sscanf(theInterval.c_str(), "%i", &evaluatedArguments.GTP_file_interval);

    if(n != 1) {
        throw string("File interval must be numeric: input was ") + theInterval;
    }
}

void setHashSize(const string &theSize) {
    int n = sscanf(theSize.c_str(), "%i", &evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);

    if(n != 1) {
        throw string("Hash size must be numeric: input was ") + theSize;
    }
}

void setPropertyFileName(const string &value) {
    evaluatedArguments.propertyFileName = value;
    evaluatedArguments.usePropertyFile = true;
}

void setRMILicenseFullPath(const string &value) {
    evaluatedArguments.rmiLicenseFullPath = value;
}

void setRMILicenseHost(const string &value) {
    evaluatedArguments.rmiLicenseHost = value;
}

void setRMILicensePort(const string &value) {
    evaluatedArguments.rmiLicensePort = value;
}

void setRMILicenseName(const string &value) {
    evaluatedArguments.rmiLicenseName = value;
}

void setType(const string &type) {
    evaluatedArguments.type = type;
}

void setOutputLocation(const string &theOutput) {
    evaluatedArguments.outputlocation = theOutput;
    createDir(evaluatedArguments.outputlocation, "750", 1);
}

void setTemptOutputLocation(const string &theOutput) {
    evaluatedArguments.tempOutputLocation = theOutput;
    createDir(evaluatedArguments.tempOutputLocation, "700", 0);
}

void setOutputReportingPeriod(const string &theReportInterval) {
    int n = sscanf(theReportInterval.c_str(), "%i", &evaluatedArguments.outputReportingPeriod);

    if(n != 1) {
        throw string("File interval must be numeric: input was ") + theReportInterval;
    }
}

void setPrintPacketBufferStatsInterval(const string &timeInterval) {
    int n = sscanf(timeInterval.c_str(), "%i", &evaluatedArguments.printPacketBufferStatsInterval);

    if(n != 1) {
        throw string("Time interval must be numeric: input was ") + timeInterval;
    }

    if(evaluatedArguments.printPacketBufferStatsInterval < 5) {
        throw string("Time interval should be greater than 5 seconds.");
    }

    if(evaluatedArguments.printPacketBufferStatsInterval > 3600) {
        throw string("Time interval should be less than 3600 seconds.");
    }
}

void setPacketLossUserThreshold(const string &thePacketLossUserThreshold) {
    if(thePacketLossUserThreshold.length() > 0) {
        char *cstr = new char[thePacketLossUserThreshold.length() + 1];
        snprintf(cstr, thePacketLossUserThreshold.length() + 1, "%s", thePacketLossUserThreshold.c_str());
        char *p1 = std::strtok(cstr, ",");
        char *p2 = strtok(NULL, ",");
        int n1 = 0, n2 = 0;

        if(p1 != NULL) {
            n1 = sscanf(p1, "%u", &evaluatedArguments.packetLossUserThreshold_UE_to_INET);
        }

        if(p2 != NULL) {
            n2 = sscanf(p2, "%u", &evaluatedArguments.packetLossUserThreshold_INET_to_UE);
        }

        delete[] cstr;

        if((n1 != 1) || (p1 == NULL)) {
            throw string("Packet Loss User Threshold UE_to_INET  Format incorrect expected  <UE_to_INET threshold number>,<INET_to_UE Threshold number>: input was ") + thePacketLossUserThreshold;
        }

        if((n2 != 1) || (p2 == NULL)) {
            throw string("Packet Loss User Threshold INET_to_UE Format incorrect expected  <UE_to_INET threshold number>,<INET_to_UE Threshold number>: input was ") + thePacketLossUserThreshold;
        }

        if(evaluatedArguments.packetLossUserThreshold_INET_to_UE < (unsigned int) PACKET_LOSS_PACKET_THRESHOLD_INET_TO_UE) {
            char buf[200];
            snprintf(buf, sizeof(buf), "Packet Loss User Threshold INET_to_UE = %u. It should be greater than %u packets", evaluatedArguments.packetLossUserThreshold_INET_to_UE, (unsigned int) PACKET_LOSS_PACKET_THRESHOLD_INET_TO_UE);
            throw string(buf);
        }

        if(evaluatedArguments.packetLossUserThreshold_UE_to_INET < (unsigned int) PACKET_LOSS_PACKET_THRESHOLD_UE_TO_INET) {
            char buf[200];
            snprintf(buf, sizeof(buf), "Packet Loss User Threshold UE_to_INET = %u. It should be greater than %u packets", evaluatedArguments.packetLossUserThreshold_UE_to_INET, (unsigned int) PACKET_LOSS_PACKET_THRESHOLD_UE_TO_INET);
            throw string(buf);
        }

        LOG4CXX_INFO(loggerConfiguration, "Packet Loss User Threshold UE_to_INET = " << evaluatedArguments.packetLossUserThreshold_UE_to_INET);
        LOG4CXX_INFO(loggerConfiguration, "Packet Loss User Threshold INET_to_UE = " << evaluatedArguments.packetLossUserThreshold_INET_to_UE);
    } else {
        LOG4CXX_INFO(loggerConfiguration, "Problem Reading Packet Loss User Threshold; Input read from properties file is " << thePacketLossUserThreshold);
        throw string("Problem Reading Packet Loss User Threshold; Input read from properties file is ") + thePacketLossUserThreshold;
    }
}

void setGtpcCacheWriteInterval(const string &gtpcCacheWriteInterval) {
    evaluatedArguments.gtpcCacheWriteInterval = atoi(gtpcCacheWriteInterval.c_str());
}

bool isDir(const char *path) {
    // Get the directory attributes
    struct stat stats;

    if(stat(path, &stats) != 0) {
        return false; // Not a directory
    }

    return (S_ISDIR(stats.st_mode) != 0);
}

bool isDir(const string &path) {
    // Get the directory attributes
    struct stat stats;

    if(stat(path.c_str(), &stats) != 0) {
        return false; // Not a directory
    }

    return (S_ISDIR(stats.st_mode) != 0);
}

int isFile(const string &path) {
    struct stat stats;

    if(stat(path.c_str(), &stats) != 0) {
        return 0; // Not a directory
    }

    return S_ISREG(stats.st_mode);
}

bool isBool(const string &value) {
    if((strcmp(value.c_str(), "true") == 0) || (strcmp(value.c_str(), "false") == 0)) {
        return true;
    } else {
        return false;
    }
}

bool isNumber(const string &value) {
    int i;
    return sscanf(value.c_str(), "%d", &i) == 1;
}

bool isNumberGreaterThenOne(const string &value) {
    int i;
    return (sscanf(value.c_str(), "%d", &i) == 1 && i >= 1);
}

bool isDurationLongerThanOneMinute(const string &value) {
    int i;
    return (sscanf(value.c_str(), "%d", &i) == 1 && i >= 60);
}


bool isShortTimeoutCorrect(const string &value) {
    unsigned int i;
    return (sscanf(value.c_str(), "%d", &i) == 1 && i < evaluatedArguments.ipqConnectionNormalTimeout);
}

bool isLongTimeoutCorrect(const string &value) {
    unsigned int i;
    return (sscanf(value.c_str(), "%d", &i) == 1 && i > evaluatedArguments.ipqConnectionNormalTimeout);
}

bool isPortNumber(const string &value) {
    int portNum;

    if(sscanf(value.c_str(), "%d", &portNum) == 1) {
        if(portNum > 0 && portNum < 65536) {
            return true;
        }
    }

    return false;
}

int isPipe(const char *path) {
    struct stat stats;

    if(stat(path, &stats) != 0) {
        return 0; // Not a directory
    }

    return S_ISFIFO(stats.st_mode);
}

bool isExistingFileOrPipe(const string &value) {
    FILE *file;
    file = fopen(value.c_str(), "r");

    if(file) {
        fclose(file);
        return true;
    }

    if(isPipe(value.c_str())) {
        return true;
    }

    return false;
}

bool isValidFileOutputFormat(const string &value) {
    return value.compare("legacy") == 0 || value.compare("pect") == 0;
}

int parseArgs(int argc, char **argv, pcap_t **descrPtr) {
    vector<RequiredArgument> requiredArgs;
    requiredArgs.push_back(RequiredArgument("-outputLocation", setOutputLocation, isDir, "Must be a Directory."));
    requiredArgs.back().addValue("-", true);
    requiredArgs.push_back(RequiredArgument("-tempOutputLocation", setTemptOutputLocation, isDir, "Must be a Directory."));
    requiredArgs.back().addValue("-", true);
    requiredArgs.push_back(RequiredArgument("-reportOutputPeriod", setOutputReportingPeriod, isNumberGreaterThenOne, "Must be a number."));
    requiredArgs.back().addValue("1", true);
    requiredArgs.push_back(RequiredArgument("-gtpc_cache_write_interval", setGtpcCacheWriteInterval, isDurationLongerThanOneMinute, "Must be a number in integer format, greater than, or equal to, sixty seconds."));
    requiredArgs.back().addValue("86400", true); // Default value, for 86400 seconds (24 hours).
    requiredArgs.push_back(RequiredArgument("-version", setGTPCVersion));
    requiredArgs.back().addValue(VERSION_ONE, true);
    requiredArgs.back().addValue(VERSION_TWO);
    requiredArgs.back().addValue(VERSION_BOTH);
    requiredArgs.push_back(RequiredArgument("-input", setGTPCInput));
    requiredArgs.back().addValue("live", true);
    requiredArgs.push_back(RequiredArgument("-interval", setGTPFileInterval, isNumberGreaterThenOne, "Must be a number."));
    requiredArgs.back().addValue("1", true);
    requiredArgs.push_back(RequiredArgument("-instance_tag", setGTPCInstanceTag, isNumber, "Must be a number."));
    requiredArgs.back().addValue("0", true);
    requiredArgs.push_back(RequiredArgument("-live", setType));
    requiredArgs.back().addValue("true", true);
    requiredArgs.back().addValue("false");
    requiredArgs.push_back(RequiredArgument("-hash_size", setHashSize));
    requiredArgs.back().addValue("1000000", true);
    requiredArgs.push_back(RequiredArgument("-packetBuffer_capture_type", setPacketBufferCaptureFrom));
    requiredArgs.back().addValue("LIVE", true);
    requiredArgs.push_back(RequiredArgument("-use_multiple_packetBuffers", setUse_multiple_packetBuffers, isBool, "Must be 'true' or 'false'"));
    requiredArgs.back().addValue("false", true);
    requiredArgs.push_back(RequiredArgument("-packetBuffer_size", setPacketBufferSize, isNumberGreaterThenOne, "Must be a number greater than one."));
    requiredArgs.back().addValue("1000000", true);
    requiredArgs.push_back(RequiredArgument("-packetBuffer_gtpu_source_name", setPacketBufferGtpuSourceName));
    requiredArgs.back().addValue("", true);
    requiredArgs.push_back(RequiredArgument("-packetBuffer_sink_count", setPacketBufferSinkCount, isNumber, "Must be a number."));
    requiredArgs.back().addValue("0", true);
    requiredArgs.push_back(RequiredArgument("-packetBuffer_macOfKnownElement", setPacketBufferMacOfKnownElement));
    requiredArgs.back().addValue("", true);
    requiredArgs.push_back(RequiredArgument("-excludeRATNumber", setExcludeRATNumber));
    requiredArgs.back().addValue("2", true);
    requiredArgs.push_back((RequiredArgument("-properties", setPropertyFileName, isExistingFileOrPipe, "Must be an existing file")));
    requiredArgs.push_back(RequiredArgument("-fileOutputFormat", setFileOutputFormat, isValidFileOutputFormat, "Valid file output formats are 'legacy' and 'pect'"));
    requiredArgs.back().addValue("legacy", true);  // Default Value.
    requiredArgs.back().addValue("pect");
    requiredArgs.push_back(RequiredArgument("-minFlowSize", setMinFlowSize, isNumber, "Must be a number"));
    requiredArgs.back().addValue("0", true);  //
    requiredArgs.push_back(RequiredArgument("-rmiLicenseFullPath", setRMILicenseFullPath));
    requiredArgs.back().addValue("/opt/ericsson/pcp/pect/license", true);
    requiredArgs.push_back(RequiredArgument("-rmiLicenseServerHost", setRMILicenseHost));
    requiredArgs.back().addValue("licenceserver", true);
    requiredArgs.push_back(RequiredArgument("-rmiLicenseServerPort", setRMILicensePort, isPortNumber, "Must be a valid number."));
    requiredArgs.back().addValue("1200", true);
    requiredArgs.push_back(RequiredArgument("-licensingServiceName", setRMILicenseName));
    requiredArgs.back().addValue("LicensingCache", true);
    requiredArgs.push_back(RequiredArgument("-printPacketBufferStatsInterval", setPrintPacketBufferStatsInterval));
    requiredArgs.back().addValue("60", true);
    requiredArgs.push_back(RequiredArgument("-packetLossUserThreshold", setPacketLossUserThreshold));
    requiredArgs.back().addValue("50,100", true);
    // requiredArgs.push_back(RequiredArgument("-classificationEngineLicenseFile", setIpoquePaceLicenseFile));
    requiredArgs.push_back(RequiredArgument("-ipoqueTimeout", setIpoqueTimeout, isDurationLongerThanOneMinute, "Must be a number greater than sixty seconds"));
    requiredArgs.back().addValue("600", true);
    // efitleo: Multiple Timeout Queues
    requiredArgs.push_back(RequiredArgument("-ipoqueShortTimeout", setIpoqueShortTimeout, isShortTimeoutCorrect, "Must be a number, less than value entered for -ipoqueTimeout"));
    requiredArgs.back().addValue("40", true);
    requiredArgs.push_back(RequiredArgument("-ipoqueLongTimeout", setIpoqueLongTimeout, isLongTimeoutCorrect, "Must be a number, greater than value entered for -ipoqueTimeout "));
    requiredArgs.back().addValue("10800", true);
    requiredArgs.push_back(RequiredArgument("-gtpcSessionTimeoutAge", setGTPCSessionTimeoutAge, isNumber, "Must be a number"));
    requiredArgs.back().addValue("86400", true);
    requiredArgs.push_back(RequiredArgument("-gtpcSessionTimeoutFrequency", setGTPCSessionTimeoutFrequency, isNumber, "Must be a number"));
    requiredArgs.back().addValue("3600", true);
    requiredArgs.push_back(RequiredArgument("-customProtocols_decodeLevelForHosts", setCdpDecodeHostsLevel));
    requiredArgs.back().addValue("1,2,4,1,6,4,2", true);
    requiredArgs.push_back(RequiredArgument("-customProtocols_decodeUsingExtraHosts", setCdpDecodeUsingExtraHosts, isBool, "Must be 'true' or 'false'"));
    requiredArgs.back().addValue("false", true);
    requiredArgs.push_back(RequiredArgument("-customProtocols_decodeUsingUserAgent", setCdpDecodeUsingUserAgent, isBool, "Must be 'true' or 'false'"));
    requiredArgs.back().addValue("false", true);
    requiredArgs.push_back(RequiredArgument("-customProtocols_decodeUsingURL", setCdpDecodeUsingURL, isBool, "Must be 'true' or 'false'"));
    requiredArgs.back().addValue("false", true);
    SuppliedArguments suppliedArguments;

    try {
        // First check if we have -properties <filename>, if so, then read properties from file
        suppliedArguments = SuppliedArguments(argc, argv);
        int valid = processAndApplyArgs(requiredArgs, suppliedArguments);

        if(valid == 1) {
            return 1;
        }

        if(evaluatedArguments.usePropertyFile) {
            suppliedArguments = SuppliedArguments(evaluatedArguments.propertyFileName);
        }
    } catch(const string &argumentError) {
        LOG4CXX_FATAL(loggerConfiguration, argumentError);
        return 1;
    }

    //check all args are in place
    int valid = processAndApplyArgs(requiredArgs, suppliedArguments);

    if(valid == 1) {
        return 1;
    }

    LOG4CXX_INFO(loggerConfiguration, "Values: ");
    LOG4CXX_INFO(loggerConfiguration, "Version: " << evaluatedArguments.GTPCVersion);
    LOG4CXX_INFO(loggerConfiguration, "GTP-C Cache Write Interval: " << evaluatedArguments.gtpcCacheWriteInterval << " seconds.");
    LOG4CXX_INFO(loggerConfiguration, "Input: " << evaluatedArguments.GTPCInput);
    LOG4CXX_INFO(loggerConfiguration, "Output Directory: " << evaluatedArguments.outputlocation);
    LOG4CXX_INFO(loggerConfiguration, "Temporary output Directory: " << evaluatedArguments.tempOutputLocation);
    LOG4CXX_INFO(loggerConfiguration, "Instance tag: " << evaluatedArguments.GTPCInstance_tag);
    LOG4CXX_INFO(loggerConfiguration, "Type: " << evaluatedArguments.type);
    LOG4CXX_INFO(loggerConfiguration,
                 "Limiting HashMaps to a maximum size of: " << evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);
    LOG4CXX_INFO(loggerConfiguration, "Program Timeout (0 run forever) = " << evaluatedArguments.programTimeout);
    LOG4CXX_INFO(loggerConfiguration, "The GTPU will be collected from the following source(s)");

    for(list<string>::iterator i = evaluatedArguments.packetBufferGtpuSourceName.begin();
            i != evaluatedArguments.packetBufferGtpuSourceName.end(); ++i) {
        LOG4CXX_INFO(loggerConfiguration, "GTPU INPUT " << evaluatedArguments.packetBufferSourceCount << " : " << *i);
    }

    LOG4CXX_INFO(loggerConfiguration, "The following MAC address will used");

    for(list<unsigned long>::iterator itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
            itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++itr) {
        LOG4CXX_INFO(loggerConfiguration, "MAC ADDR" << " : " << std::hex << *itr);
    }

    LOG4CXX_TRACE(loggerConfiguration, "Excluding the following RAT types: ");

    for(std::tr1::unordered_map<string, int>::iterator iter = evaluatedArguments.excludeRATs.begin();
            iter != evaluatedArguments.excludeRATs.end(); ++iter) {
        LOG4CXX_TRACE(loggerConfiguration, "   " << iter->first << "(" << iter->second << ")");
    }

    if(evaluatedArguments.usePropertyFile) LOG4CXX_INFO(loggerConfiguration,
                "Properties file: " << evaluatedArguments.propertyFileName);

    LOG4CXX_DEBUG(loggerConsole, "Values: ");
    LOG4CXX_DEBUG(loggerConsole, "Version: " << evaluatedArguments.GTPCVersion);
    LOG4CXX_DEBUG(loggerConsole, "GTP-C Cache Write Interval: " << evaluatedArguments.gtpcCacheWriteInterval << " seconds.");
    LOG4CXX_DEBUG(loggerConsole, "Input: " << evaluatedArguments.GTPCInput);
    LOG4CXX_DEBUG(loggerConsole, "Output Directory: " << evaluatedArguments.outputlocation);
    LOG4CXX_DEBUG(loggerConsole, "Temporary output Directory: " << evaluatedArguments.tempOutputLocation);
    LOG4CXX_DEBUG(loggerConsole, "Instance tag: " << evaluatedArguments.GTPCInstance_tag);
    LOG4CXX_DEBUG(loggerConsole, "Type: " << evaluatedArguments.type);
    LOG4CXX_DEBUG(loggerConsole, "Limiting HashMaps to a maximum size of: " << evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);
    LOG4CXX_DEBUG(loggerConsole, "Program Timeout (0 run forever) = " << evaluatedArguments.programTimeout);
    LOG4CXX_DEBUG(loggerConsole, "Use Multiple Packet Buffers = " << evaluatedArguments.useMultiplePacketBuffers);
    LOG4CXX_DEBUG(loggerConsole, "Packet Buffer Size = " << evaluatedArguments.packetBufferSize << "[each]");
    LOG4CXX_DEBUG(loggerConsole, "The GTPU will be collected from the following source(s)");
    LOG4CXX_INFO(loggerConfiguration, "Values: ");
    LOG4CXX_INFO(loggerConfiguration, "Version: " << evaluatedArguments.GTPCVersion);
    LOG4CXX_INFO(loggerConfiguration, "GTP-C Cache Write Interval: " << evaluatedArguments.gtpcCacheWriteInterval << " seconds.");
    LOG4CXX_INFO(loggerConfiguration, "Input: " << evaluatedArguments.GTPCInput);
    LOG4CXX_INFO(loggerConfiguration, "Output Directory: " << evaluatedArguments.outputlocation);
    LOG4CXX_INFO(loggerConfiguration, "Temporary output Directory: " << evaluatedArguments.tempOutputLocation);
    LOG4CXX_INFO(loggerConfiguration, "Instance tag: " << evaluatedArguments.GTPCInstance_tag);
    LOG4CXX_INFO(loggerConfiguration, "Type: " << evaluatedArguments.type);
    LOG4CXX_INFO(loggerConfiguration, "Limiting HashMaps to a maximum size of: " << evaluatedArguments.GTPC_HASHMAP_MAX_SIZE);
    LOG4CXX_INFO(loggerConfiguration, "Program Timeout (0 run forever) = " << evaluatedArguments.programTimeout);
    LOG4CXX_INFO(loggerConfiguration, "Use Multiple Packet Buffers = " << evaluatedArguments.useMultiplePacketBuffers);
    LOG4CXX_INFO(loggerConfiguration, "Packet Buffer Size = " << evaluatedArguments.packetBufferSize << "[each]");
    LOG4CXX_INFO(loggerConfiguration, "The GTPU will be collected from the following source(s)");

    for(list<string>::iterator i = evaluatedArguments.packetBufferGtpuSourceName.begin();
            i != evaluatedArguments.packetBufferGtpuSourceName.end(); ++i) {
        LOG4CXX_DEBUG(loggerConsole, "GTPU INPUT " << evaluatedArguments.packetBufferSourceCount << " : " << *i);
        LOG4CXX_INFO(loggerConfiguration, "GTPU INPUT " << evaluatedArguments.packetBufferSourceCount << " : " << *i);
    }

    LOG4CXX_INFO(loggerConfiguration, "The following MAC address will used;");
    LOG4CXX_DEBUG(loggerConsole, "The following MAC address will used;");

    for(list<unsigned long>::iterator itr = evaluatedArguments.packetBufferMacOfKnownElement.begin();
            itr != evaluatedArguments.packetBufferMacOfKnownElement.end(); ++itr) {
        LOG4CXX_INFO(loggerConfiguration, "MAC ADDR" << " : " << std::hex << *itr);
        LOG4CXX_DEBUG(loggerConsole, "MAC ADDR" << " : " << std::hex << *itr);
    }

    LOG4CXX_TRACE(loggerConfiguration, "Excluding the following RAT types: ");

    for(std::tr1::unordered_map<string, int>::iterator iter = evaluatedArguments.excludeRATs.begin();
            iter != evaluatedArguments.excludeRATs.end(); ++iter) {
        LOG4CXX_TRACE(loggerConfiguration, "   " << iter->first << "(" << iter->second << ")");
    }

    if(evaluatedArguments.usePropertyFile) {
        LOG4CXX_INFO(loggerConfiguration, "Properties file: " << evaluatedArguments.propertyFileName);
        LOG4CXX_DEBUG(loggerConsole, "Properties file: " << evaluatedArguments.propertyFileName);
    }

    interval = evaluatedArguments.GTP_file_interval;

    if(interval < 1) {
        LOG4CXX_FATAL(loggerConfiguration,
                      "Invalid increment " << evaluatedArguments.GTP_file_interval << ", minimum increment is 1 minute.");
        LOG4CXX_FATAL(loggerConsole,
                      "Invalid increment " << evaluatedArguments.GTP_file_interval << ", minimum increment is 1 minute.");
        return 1;
    } else {
        // convert to seconds
        interval *= 60;
    }

    return 0;
}

int processAndApplyArgs(vector<RequiredArgument> &theRequired, SuppliedArguments &theSupplied) {
    ArgumentProcessor processor(theRequired, theSupplied);
    processor.applyDefaults();

    try {
        processor.processArguments();
    } catch(const string &message) {
        LOG4CXX_FATAL(loggerConfiguration, message);
        LOG4CXX_FATAL(loggerConsole, message);
        return 1;
    }

    return 0;
}

bool checkDataMatches(const string &description, long long expectedValue, long long obtainedValue) {
    bool match = true;

    if(expectedValue != obtainedValue) {
        LOG4CXX_FATAL(loggerConfiguration,
                      description << ", values do not match, expected: " << expectedValue << " got: " << obtainedValue);
        match = !match;
    }

    return match;
}

bool checkDataGE(const string &description, long long expectedValue, long long obtainedValue) {
    bool match = true;

    if(obtainedValue < expectedValue) {
        LOG4CXX_ERROR(loggerConfiguration,
                      description << ", value greater than required minimum, expected: " << expectedValue << " got: " << obtainedValue);
        match = false;
    }

    return match;
}

bool GetPacketPointerAndLength(const u_char *packet, bool cooked, const struct my_ip **ipP, int *lengthP,
                               struct pcap_pkthdr *pkthdr) {
    if(cooked) {
        *ipP = (struct my_ip *)(packet + sizeof(LinuxCookedHeader));
        *lengthP = (int)(pkthdr->len - sizeof(LinuxCookedHeader));
    } else {
        struct ether_header *eptr = (struct ether_header *) packet;

        if(ntohs(eptr->ether_type) == ETHERTYPE_IP) {
            *ipP = (struct my_ip *)(packet + sizeof(struct ether_header));
            *lengthP = (int)(pkthdr->len - sizeof(struct ether_header));

            if(*lengthP < (int)(sizeof(struct my_ip))) {
                checkDataMatches("Length of my_ip, ip may be truncated, exiting ", sizeof(my_ip), *lengthP);
                exit(0);
            }

            return true;
        }

        if(ntohs(eptr->ether_type) == ETHERTYPE_VLAN) {
            *ipP = (struct my_ip *)(packet + sizeof(struct ether_header) + 4);
            *lengthP = (int)(pkthdr->len - sizeof(struct ether_header) + 4);

            if(*lengthP < (int) sizeof(struct my_ip)) {
                checkDataMatches("Length of my_ip, ip may be truncated, exiting ", sizeof(my_ip), *lengthP);
                exit(0);
            }

            return true;
        } else {
            PacketCounter::getInstance()->incrementNonEthernetPackets();
            return false;
        }
    }

    //failed to match any condition leaving the length unset
    return false;
}

string PacketCounter::getDetails() const {
    char buffer[512];
    unsigned int bufferSize = sprintf(buffer, "PacketCounter: Total[%ld] V1[%ld] V2[%ld] OK[%ld] Bad[%ld] Short[%ld] Truncated[%ld] Fragmented[%ld] "
                                      "Unexpected[%ld] Non-Ethernet[%ld] Non-IPv4[%ld] Non-UDP[%ld]",
                                      this->getTotalPackets(), this->getTotalNumberOfVersionOnePackets(), this->getTotalNumberOfVersionTwoPackets(),
                                      this->getTotalOKPackets(), this->getTotalErrorPackets(), this->getInvalidHeaderLength(), this->getTruncatedPackets(),
                                      this->getFragmentedPackets(), this->getTotalUnexpectedPackets(), this->getTotalNonEthernetPackets(),
                                      this->getNonIpv4Packets(), this->getNonUdpPackets());

    if(bufferSize > sizeof(buffer) - 1) {
        LOG4CXX_WARN(loggerGtpcParser, "Packet details buffer over run by: " << bufferSize - sizeof(buffer));
    }

    return buffer;
}

ostream &operator<<(ostream &os, const printIFGE0 &value) {
    if(value.getValue() >= 0) {
        os << value.getValue();
    } else {
        os << EMPTY_INT_STRING;
    }

    os << value.getSeparator();
    return os;
}

ostream &operator<<(ostream &os, const printIFGT0 &value) {
    if(value.getValue() > 0) {
        os << value.getValue();
    } else {
        os << EMPTY_INT_STRING;
    }

    os << value.getSeparator();
    return os;
}

ostream &operator<<(ostream &os, const PacketCounter *pc) {
    os << pc->getDetails();
    return os;
}

ostream &operator<<(ostream &os, const IPAddress &ipAddress) {
    if(ipAddress.data.address > 0) {
        for(int i = 3; i >= 0; --i) {
            os << (int) ipAddress.data.bytes[i] << (i == 0 ? "" : ".");
        }
    } else {
        os << EMPTY_INT_STRING;
    }

    return os;
}
