/*
 * gtpc_map_serialisation_utils.cc
 *
 *  Created on: 9 Jul 2013
 *      Author: elukpot
 */

// Local Imports
#include "gtpc_map_serialisation_utils.h"
#include "gtpv1_utils.h"
#include "logger.hpp"
#include "gtpv1_maps.h"

// System Imports
#include <cstdio>
#include <fstream>
#include <errno.h>
// Namespace usages
using namespace log4cxx;


// Constants

// ------------------ Functions ------------------ //



/**
 *
 * return gtpcCache Directory
 *
 */

std::string getGtpcCacheDir() {
    static string gtpcCacheDirectory;
    static int dirPathAlreadySet;
    string outputPath;
    string cmd;

    if(!dirPathAlreadySet) {
        // this bit chould run once only.. at startup of application when cache is read.
        unsigned found = (unsigned) evaluatedArguments.outputlocation.find_last_of("/");

        if(found != std::string::npos) {
            // check if outout path has a / on the end like : /var/opt/ericsson/pcp/output/
            // check that user has not set output path to some thing like / [where length ==1]
            if((found == evaluatedArguments.outputlocation.length() - 1) && (evaluatedArguments.outputlocation.length() > 1)) {
                outputPath = evaluatedArguments.outputlocation.substr(0, found);
            } else {
                outputPath = evaluatedArguments.outputlocation;
            }
        }

        found = (unsigned) outputPath.find_last_of("/");

        if(found != std::string::npos) {
            gtpcCacheDirectory = outputPath.substr(0, found) + "/cache/";
            LOG4CXX_INFO(loggerGtpcMap, "Gtpc cache directory path set to (output base/cache/): " + gtpcCacheDirectory);
            LOG4CXX_DEBUG(loggerConsole, "Gtpc cache directory path set to (output base/cache/): " + gtpcCacheDirectory);
        } else {
            gtpcCacheDirectory = GTPC_CACHE_DIRECTORY_PATH;
            LOG4CXX_ERROR(loggerGtpcMap, "Unable to determine base directory path from property --outputLocation : " + evaluatedArguments.outputlocation);
            LOG4CXX_ERROR(loggerGtpcMap, "Gtpc cache directory path set to (default path) : " + gtpcCacheDirectory);
            LOG4CXX_ERROR(loggerConsole, "Unable to determine base directory path from property --outputLocation : " + evaluatedArguments.outputlocation);
            LOG4CXX_ERROR(loggerConsole, "Gtpc cache directory path set to (default path) : " + gtpcCacheDirectory);
        }

        cmd = "mkdir -p " + gtpcCacheDirectory;

        if(system(cmd.c_str())) {
            LOG4CXX_ERROR(loggerGtpcMap, "Unable to create GTP-C cache directory path " + gtpcCacheDirectory + ": mkdir failed ");
        }

        cmd = "chmod 700 " + gtpcCacheDirectory;

        if(system(cmd.c_str())) {
            LOG4CXX_ERROR(loggerGtpcMap, "Unable to set permissions on GTP-C cache " + gtpcCacheDirectory + ": chmod failed ");
        }

        dirPathAlreadySet = 1;
    }

    LOG4CXX_DEBUG(loggerGtpcMap, "Gtpc cache directory path set to : " + gtpcCacheDirectory);
    return gtpcCacheDirectory;
}

/**
 * ChangePermissionsOnCacheFile
 *
 * This function changes the permissions on the GTP-C cache file to 600
 */
void changePermissionsOnCacheFile() {
    string chmod = "chmod 600 ";
    string command = chmod + getGtpcCacheDir();
    command += GTPC_CACHE_FILE_NAME;

    if(system(command.c_str())) {
        LOG4CXX_ERROR(loggerGtpcMap, "Unable to set permissions on GTP-C cache file " + getGtpcCacheDir() + GTPC_CACHE_FILE_NAME);
    }
}

void writeGTPCCache(UserPDPSessionMap_t &userMap) {
    try {
        string gtpcCacheFullPath = getGtpcCacheDir() + GTPC_CACHE_FILE_NAME;
        string gtpcCacheTmpFullPath = gtpcCacheFullPath + GTPC_TMP_FILE_SUFIX;
        LOG4CXX_INFO(loggerGtpcMap, "Writing GTP-C cache to " << gtpcCacheTmpFullPath << ". Usermap(" << userMap.size() << ")");
        std::ofstream ofs(gtpcCacheTmpFullPath);
        boost::archive::text_oarchive oa(ofs);
        size_t count = userMap.size();
        auto it = userMap.begin();

        while(count-- > 0) {
            oa &(it->second);
            it++;
        }

        ofs.close();
        int result = std::rename(gtpcCacheTmpFullPath.c_str(), gtpcCacheFullPath.c_str());
        int errorNum = errno;

        if(result != -1) {
            LOG4CXX_INFO(loggerGtpcMap, "GTP-C cache saved to file:" << gtpcCacheFullPath);
            changePermissionsOnCacheFile();
        } else {
            LOG4CXX_ERROR(loggerGtpcMap, "Failed to move file from  " << gtpcCacheTmpFullPath << " to " << gtpcCacheFullPath << "."
                          << "Reason: " << strerror(errorNum));
        }
    } catch(boost::archive::archive_exception &ex) {
        LOG4CXX_ERROR(loggerGtpcMap, "Error when trying to save GTP-C cache. Reason: " << ex.what());
    } catch(...) {
        LOG4CXX_ERROR(loggerGtpcMap, "Failed to write GTP-C cache for unknown reason");
    }
}


void validatePDPSessionStruct(u_int32_t ue, const PDPSession *pdpS) {
    /*
    bool isError=false;
    if(pdpS->startTime<0||pdpS->touch<0||pdpS->time_pdn_response<0||pdpS->time_update_request<0||pdpS->time_update_response<0
            ||pdpS->active_update_start<0)
    {
        isError=true;
        LOG4CXX_ERROR(loggerGtpcMap,"some fields in PDPSession shond not be negative"<<
                "starTime:"<<pdpS->startTime<<","<<"touch:"<<pdpS->touch<<","<<"time_pdn_response"<<pdpS->time_pdn_response
                <<"time_update_request:"<<pdpS->time_update_request<<","
                <<"time_update_response:"<<pdpS->time_update_request<<","
                <<"active_update_start:"<<pdpS->active_update_start);
    }

    if(pdpS->pdn_cause<-1 || pdpS->nsapi<-1||pdpS->sdu<-1||
            pdpS->max_dl<-1||pdpS->max_dl<-1||pdpS->gbr_ul||
            pdpS->gbr_dl<-1 || pdpS->thp<-1||pdpS->arp<-1||
            pdpS->delay_class<-1|| pdpS->reliability_class<-1 ||
            pdpS->precedence<-1)
    {
        LOG4CXX_ERROR(loggerGtpcMap,"some fields in PDPSession shond not be less than -1");

    }

    if(strlen(pdpS->imsi)>IMSI_MAX_CHARS )
    {
        isError=true;
        LOG4CXX_ERROR(loggerGtpcMap,"IMSI String ");

    }

    if(strlen(pdpS->imei)>IMEI_MAX_CHARS)
    {
        isError=true;
        LOG4CXX_ERROR(loggerGtpcMap,"IMEI String");
    }

    if(strlen(pdpS->msisdn)>MSISDN_MAX_CHARS)
    {
        isError=true;
        LOG4CXX_ERROR(loggerGtpcMap,"MSISDN String");
    }

    if(strlen(pdpS->mnc)>MNC_MAX_CHARS)
    {
        isError=true;
        LOG4CXX_ERROR(loggerGtpcMap,"MNC String");

    }

    if(strlen(pdpS->mcc)>MCC_MAX_CHARS)
     {
        isError=true;
         LOG4CXX_ERROR(loggerGtpcMap,"MCC String");

     }
    */
    stringstream ss;
    ss << IPAddress(ue) << "|" << pdpS->startTime << "|" << pdpS->touch << "|"  << pdpS->imsi << "|" << pdpS->imei << "|" << pdpS->apn << "|" << pdpS->msisdn << "|" << pdpS->ue_addr << "|" << pdpS->nsapi << "|" <<
       pdpS->pdp_type << "|" << pdpS->rat << "|" << pdpS->dtflag << "|" << pdpS->locationInfo.mnc << "|" << pdpS->locationInfo.mcc << "|" << pdpS->locationInfo.lac << "|" << pdpS->locationInfo.rac << "|" <<
       pdpS->locationInfo.cid << "|" << pdpS->locationInfo.sac << "|" << pdpS->pdn_cause << "|" << pdpS->update_cause << "|" << pdpS->qosInfo.arp << "|" << pdpS->qosInfo.delay_class << "|" <<
       pdpS->qosInfo.reliability_class << "|" << pdpS->qosInfo.precedence << "|" << pdpS->qosInfo.traffic_class << "|" <<
       pdpS->qosInfo.thp << "|" << pdpS->qosInfo.max_dl << "|" << pdpS->qosInfo.max_dl << "|" << pdpS->qosInfo.gbr_ul << "|" << pdpS->qosInfo.gbr_dl << "|" << pdpS->qosInfo.sdu << "|" << pdpS->instanceCounter << "|" <<
       pdpS->deleteCounter << "|" << pdpS->sgsn_c << "|" << pdpS->ggsn_c << /*"|" << pdpS->ggsn_d << */ "|" << pdpS->dle << endl;
    printf("%s", ss.str().c_str());
    /*
    if(isError==true)
    {
        LOG4CXX_ERROR(loggerBroadcast,ss.str().c_str());
    }*/
}

/**
 * this function is to verify all shared PDPSession is deserialized correctly
 */
/*
void verify(UE_Session_maptype &mapGTPC, teidmaptype &teidmap, IMSI_maptype &imsiMap) {
    int equalCount = 0;
    char buf[100];

    for(UE_Session_maptype::iterator it = mapGTPC.begin(); it != mapGTPC.end(); it++) {
        snprintf(buf, 100, "%d", rand() % 10000);
        //efitleo: EQEV-5831
        //unsigned long long imsi_number = strtoull(it->second->imsi, 0, IMSI_MAX_CHARS);
        unsigned long long imsi_number = strtoull(it->second->imsi, NULL , 10);
        //LOG4CXX_INFO(loggerGtpcParser, "Serialisation: it->second->imsi = " << it->second->imsi <<": imsi_number = "<< imsi_number);
        snprintf(it->second->msisdn, MSISDN_MAX_CHARS, "%s", buf); //change to a random number

        if(imsiMap.find(imsi_number)->second == it->second) {
            equalCount ++;
        }

        LOG4CXX_DEBUG(loggerGtpcMap, "gtpc IMSI:" << it->second->imsi << " imsi:" << imsiMap.find(imsi_number)->second->imsi);
    }

    LOG4CXX_INFO(loggerGtpcMap, "Verification of gtpc-cache read from disk: count:" << equalCount << " total:" << mapGTPC.size());
}*/

/**
 * ReadGtpcMap
 *
 * This is the function to handle the reading of the GTP-C Cache file from the file system.
 */
void readGtpcCache() {
    string gtpcCacheFullPath = getGtpcCacheDir() + GTPC_CACHE_FILE_NAME;
    LOG4CXX_INFO(loggerGtpcMap, "Starting to read the GTP-C cache from:" << gtpcCacheFullPath);
    unsigned int count = 0;
    time_t now;
    time(&now);
    now = now - 21600; // 6 Hours

    try {
        std::ifstream ifs(gtpcCacheFullPath);
        boost::archive::text_iarchive ia(ifs);
        PDPSession *pdpSession;

        while(!ifs.eof()) {
            ia &pdpSession;
            pdpSession->touch = (double)now;
            pdpSession->loadedFromCache = 1;
            addPDPSession(pdpSession);
            count++;
        }

        ifs.close();
    } catch(boost::archive::archive_exception &ex) {
        LOG4CXX_INFO(loggerGtpcMap, "Failed to read GTP-C cache from:" << gtpcCacheFullPath << "." << ex.what());
    } catch(...) {
        LOG4CXX_INFO(loggerGtpcMap, "Failed to read GTP-C cache for unknown reason");
    }

    LOG4CXX_INFO(loggerGtpcMap, "Finished reading the GTP-C cache. (" << count << ")");
}




