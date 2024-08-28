/*
 * license_controler.cpp
 *
 *  Created on: 5 Jun 2013
 *      Author: ezhelao
 */

#include "license_controller.hpp"
#include "logger.hpp"
#include "MagicStringTester.h"
#include "gtpc_map_serialisation_utils.h"
#include "gtpv1_maps.h"

#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <memory>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/prctl.h>


#define LICENSE_STR_LENGTH     2000
#define SECONDS_IN_A_DAY       86400
#define MIN_OFFSET_TO_MIDNIGHT 1800  // midnight 00:30
#define MAX_OFFSET_TO_MIDNIGHT 3599  // midnight 00:59:59
#define SLEEP_LENGTH           420   // 7 minutes

extern EArgs evaluatedArguments;

LicenseController *LicenseController::licenseController = NULL;

/**
 * LicenseController
 */
LicenseController::LicenseController() {
    // archive and stream closed when destructors are called
    pthread_attr_init(&pthread_attr);
    closed = false;
}

/**
 * GetLicenseController
 */
LicenseController *LicenseController::getLicenseController() {
    if(licenseController == NULL) {
        licenseController = new LicenseController();
    }

    return licenseController;
}

/**
 * Start
 *
 * This function kicks off the license checking thread.
 */
void LicenseController::start() {
    LOG4CXX_INFO(loggerLicense, "License module has started.");
    run(NULL);
}

/**
 * Run
 *
 * This is the thread function. It checks the license.
 * This thread also checks if the time has moved forward or backwards and
 * prints these messages to the log.
 */
void *LicenseController::run(void *init) {
    prctl(PR_SET_NAME, "pect_license", 0, 0, 0);
    time_t timeNow;
    struct tm scheduleTime;
    string separator = "----------------------------------------------------------------------";
    time(&timeNow);
    localtime_r(&timeNow, &scheduleTime);
    scheduleTime.tm_mday += 1;
    scheduleTime.tm_hour = 0;
    scheduleTime.tm_min = 30;
    scheduleTime.tm_sec = 0;
    time_t nextTime = mktime(&scheduleTime);
    char tmbuf[64];

    while(true) {
        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", &scheduleTime);
        LOG4CXX_INFO(loggerLicense, "License scheduled to be checked at " << tmbuf);
        time(&timeNow);

        while(timeNow < nextTime) {
            unsigned int sleepTime = static_cast<unsigned int>((double)(nextTime - timeNow) * 0.9 + 60);
            LOG4CXX_DEBUG(loggerLicense, "LicenseSchedule: Sleeping for " << sleepTime << " seconds");
            sleep(sleepTime);
            time(&timeNow);
        }

        LOG4CXX_INFO(loggerLicense, separator);
        int licenseResult = checkLicense();

        if(licenseResult != 0) {
            LOG4CXX_ERROR(loggerLicense, "Packet Capture Pre-Processor application will be terminated.");
            terminateApplication();
            LOG4CXX_ERROR(loggerBroadcast, "Stopping Packet Capture Pre-processor application due to invalid license.");
            break;
        }

        LOG4CXX_INFO(loggerLicense, "License is valid.");
        LOG4CXX_INFO(loggerLicense, separator);
        scheduleTime.tm_mday += 1;
        nextTime = mktime(&scheduleTime);
    }

    exit(0);
    return NULL;
}

/**
 * TerminateApplication
 */
void LicenseController::terminateApplication() {
    if(licenseController == NULL) {
        return ;
    }

    if(licenseController != NULL) {
        licenseController->closed = true;
    }

    vector<pthread_t> &threads = licenseController->threads;

    for(vector<pthread_t>::iterator it = threads.begin(); it != threads.end(); it++) {
        int result = pthread_cancel(*it);

        if(result != 0) {
            LOG4CXX_ERROR(loggerLicense, "can not cancel thread, result is " << result);
        }

        sleep(3);
    }

    LOG4CXX_INFO(loggerLicense, "Waiting all thread to finish.");

    for(vector<pthread_t>::iterator it = threads.begin(); it != threads.end(); it++) {
        pthread_join(*it, NULL);
    }

    writeGtpcCache();
    LOG4CXX_INFO(loggerLicense, "All cleanup finished.");
}

/**
 * AddThreadToController
 */
void LicenseController::addThreadToController(pthread_t &thread) {
    threads.push_back(thread);
}

/**
 * return 0 is we have a valid license;
 */
int LicenseController::checkLicense() {
    LOG4CXX_INFO(loggerLicense, "Checking license using the following config:");
    LOG4CXX_INFO(loggerLicense, "License File: " << evaluatedArguments.rmiLicenseFullPath);
    LOG4CXX_INFO(loggerLicense, "License Server Host: " << evaluatedArguments.rmiLicenseHost);
    LOG4CXX_INFO(loggerLicense, "License Server Port: " << evaluatedArguments.rmiLicensePort);
    LOG4CXX_INFO(loggerLicense, "Licensing Name: " << evaluatedArguments.rmiLicenseName);
    FILE *output = popen(("java -jar " + evaluatedArguments.rmiLicenseFullPath
                          + " -rmiHost " + evaluatedArguments.rmiLicenseHost
                          + " -rmiPort " + evaluatedArguments.rmiLicensePort
                          + " -licensingServiceName " + evaluatedArguments.rmiLicenseName
                          + " 2>&1 "
                         ).c_str(), "r");

    if(NULL == output) {
        LOG4CXX_FATAL(loggerLicense, "Check license fail:");
        LOG4CXX_FATAL(loggerLicense, "License file not found.");
        return -1;
    }

    char magicStr[LICENSE_STR_LENGTH];

    if(fgets(magicStr, LICENSE_STR_LENGTH, output) == NULL) {
        strcpy(magicStr, "Failed to read license key\0");
    }

    int returnedValue = pclose(output);
    MagicStringTester licenseTester;
    magicStr[LICENSE_STR_LENGTH - 1] = '\0';
    size_t length = strlen(magicStr);

    if(length > 0 && magicStr[length - 1] == '\n') {
        magicStr[length - 1] = '\0';
    }

    //licenseTester.testString return true if it fail !!!
    if(!licenseTester.testString(magicStr)) { // if successful, return value 0
        return 0;
    } else {
        LOG4CXX_FATAL(loggerLicense, "Check license fail: " << magicStr << " returned value: " << WEXITSTATUS(returnedValue));
        return 1;
    }
}
