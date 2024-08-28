/*
 * gtpc_map_serialisation_utils.h
 *
 *  Created on: 9 Jul 2013
 *      Author: elukpot
 */

#ifndef GTPC_MAP_SERIALISATION_UTILS_H_
#define GTPC_MAP_SERIALISATION_UTILS_H_

// Local Imports
#include "gtpv1_utils.h"
#include "gtpv1_maps.h"
#include "UE_map.hpp"
// System Imports
#include <boost/archive/archive_exception.hpp>
#include <boost/archive/text_oarchive.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/serialization/unordered_map.hpp>
// Namespace usages

// Constants
#define GTPC_FILE_NAME_LENGTH                   1024
const static string GTPC_CACHE_DIRECTORY_PATH = "/var/opt/ericsson/pcp/cache/";
const static string GTPC_CACHE_FILE_NAME      = "gtpc.cache-001"; // Using "-001" here as 1 is the version of GTP that we support.
const static string GTPC_TMP_FILE_SUFIX       = ".tmp";
extern EArgs evaluatedArguments;

// ------------------ Functions ------------------ //
void readGtpcCache();
void writeGTPCCache(UserPDPSessionMap_t &userMap);
void gtpcCacheIntervalWriterThreadCloseCleanup(void *init);
void *gtpcWriteTimer(void *init);
#endif /* GTPC_MAP_SERIALISATION_UTILS_H_ */
