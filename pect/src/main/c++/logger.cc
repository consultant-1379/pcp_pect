/*
 * logger.cc
 *
 *  Created on: 7 Mar 2013
 *      Author: elukpot
 */

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>
#include <iostream>
#include <iostream>
#include <fstream>
#include <string>
#include "gtpv1_utils.h"
#include <sys/stat.h>

#define LOG_CONFIG "log_config.xml"

using namespace std;
using namespace log4cxx;
using namespace log4cxx::xml;
using namespace log4cxx::helpers;

LoggerPtr loggerPect(Logger::getLogger("pect"));
LoggerPtr loggerClassify(Logger::getLogger("pect.classify"));
LoggerPtr loggerClassifyHostname(Logger::getLogger("pcpHostname"));
LoggerPtr loggerConfiguration(Logger::getLogger("pect.configuration"));
LoggerPtr loggerGtpcParser(Logger::getLogger("pect.gtpc.parser"));
LoggerPtr loggerPcpGlue(Logger::getLogger("pect.pcpglue"));
LoggerPtr loggerUeMap(Logger::getLogger("pect.uemap"));
LoggerPtr loggerGtpcMap(Logger::getLogger("pect.gtpc.map"));
LoggerPtr loggerGtpcStats(Logger::getLogger("pect.gtpc.stats"));
LoggerPtr loggerFileWriter(Logger::getLogger("pect.file_writer"));
LoggerPtr loggerCaptoolFileWriter(Logger::getLogger("pect.file_writer.captool"));
LoggerPtr loggerStapleFileWriter(Logger::getLogger("pect.file_writer.staple"));
LoggerPtr loggerPectFileWriter(Logger::getLogger("pect.file_writer.pect"));
LoggerPtr loggerConsole(Logger::getLogger("console"));
LoggerPtr loggerLicense(Logger::getLogger("license"));
LoggerPtr loggerBroadcast(Logger::getLogger("broadcast"));
LoggerPtr loggerCaptoolExtendedOutput(Logger::getLogger("pcpCaptoolExtendedOutput"));
LoggerPtr loggerClassifyCDPTimers(Logger::getLogger("pect.classify.cdpTimers"));
LoggerPtr loggerPcpGluePacketBuffer(Logger::getLogger("pect.pcpglue.packetbuffer"));
LoggerPtr loggerPacketLoss(Logger::getLogger("pect.packetloss"));
LoggerPtr loggerThroughput(Logger::getLogger("pect.throughput"));
LoggerPtr loggerFlowIntegrity(Logger::getLogger("pect.pcpglue.testIntegrity"));


bool checkLogPathExists(string log4cxxFilename) {
    string logFileName;
    string logDirName;
    ifstream infile;
    infile.open(log4cxxFilename);
    string sLine = "";

    while(!infile.eof()) {
        getline(infile, sLine);
        std::size_t pos1 = sLine.find("<param name=\"file\" value=");

        if(pos1 != std::string::npos) {
            std::size_t pos2 = sLine.find_last_of(" \" ");
            pos1 += 26;
            logFileName =  sLine.substr(pos1, (pos2 - pos1 - 1));
            //Files will not be there at the moment.. just check the directory exists
            std::size_t pos3 = logFileName.find_last_of("/");
            logDirName = logFileName.substr(0, pos3);
            // looking for double slash at start
            string c0 = logDirName.substr(0, 1);
            string c1 = logDirName.substr(1, 1);

            if(c1.find(c0) != std::string::npos) {
                logDirName = logFileName.substr(1, pos3);
            }

            //Looking for extra slash at end:
            if(logDirName.find_last_of("/") >=  strlen(logDirName.c_str()) - 1) {
                pos3 = pos3 - 1;
                logDirName = logDirName.substr(0, pos3);
            }

            string tempDir = logDirName.substr(1); // no leading slash /
            std::size_t pos4 = tempDir.find("/");

            if((pos4 == std::string::npos)  || (pos4 < 2)) {
                pos4 = pos3;    //default to full  log path if I can't find a slash /; means directory is like /mylog as oppose to /mylog/thelog/log
            }

            if(!isDir(logDirName.c_str())) {
                std::cerr << "The log path " << logDirName << " does not exist" << std::endl;
                std::cerr << "TO FIX : Please login as user \"root\" and perform the following command: " << std::endl;
                std::cerr << "       : mkdir -p " << logDirName << std::endl;
                std::cerr << "       : chmod -R 755 " << logDirName.substr(0, pos4 + 1) << std::endl;
                std::cerr << "       : chown pcpuser:dc5000 " << logDirName << std::endl;
                std::cerr << "       : chmod 700 " << logDirName << std::endl;
                std::cerr << std::endl << "IMPORTANT: Logout as user \"root\" once the above actions are complete and login as user \"pcpuser\" " << std::endl << std::endl;
                infile.close();
                return false;
            } else  {
                std::cout << "INFO  broadcast - Logging to file: " + logDirName  << "/" << logFileName.substr(pos3 + 1) << std::endl;
            }
        }
    }

    infile.close();
    return true;
}

int initializeLogging() {
	struct stat buffer;
	if(stat(LOG_CONFIG, &buffer) != EXIT_SUCCESS) {
		std::cerr << "ERROR: Log configuration file (" << LOG_CONFIG << ") does not exist or is unable to be read." << std::endl;
		return EXIT_FAILURE;
	}

	if(!checkLogPathExists("log_config.xml"))
	    return EXIT_FAILURE;

    // Load configuration file from fixed location.
    DOMConfigurator::configureAndWatch(LOG_CONFIG);
    AppenderPtr checkPectAppender = loggerPect->getAppender("pectAppender");
    AppenderPtr checkFileWriterAppender = loggerFileWriter->getAppender("fileWriterAppender");
    AppenderPtr checkConsoleAppender = loggerConsole->getAppender("consoleAppender");
    AppenderPtr checkStatsAppender = loggerGtpcStats->getAppender("statsAppender");

    if(checkPectAppender == NULL) {
        std::cerr << "The PECT appender for logging was not found." << std::endl;
        return EXIT_FAILURE;
    }

    if(checkFileWriterAppender == NULL) {
        std::cerr << "The File Writer appender for logging was not found." << std::endl;
        return EXIT_FAILURE;
    }

    if(checkConsoleAppender == NULL) {
        std::cerr << "The Console appender for logging was not found." << std::endl;
        return EXIT_FAILURE;
    }

    if(checkStatsAppender == NULL) {
        std::cerr << "The stats appender for logging was not found." << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
