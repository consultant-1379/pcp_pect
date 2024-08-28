/*
 * logger.hpp
 *
 *  Created on: 7 Mar 2013
 *      Author: elukpot
 *
 * Apache License
 *
 * Copyright 2013 Ericsson Radio Systems AB - All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LOGGER_HPP_
#define LOGGER_HPP_

#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

using namespace log4cxx;

extern LoggerPtr loggerClassify;
extern LoggerPtr loggerPect;
extern LoggerPtr loggerFileWriter;
extern LoggerPtr loggerPectFileWriter;
extern LoggerPtr loggerCaptoolFileWriter;
extern LoggerPtr loggerStapleFileWriter;
extern LoggerPtr loggerConsole;
extern LoggerPtr loggerConfiguration;
extern LoggerPtr loggerGtpcParser;
extern LoggerPtr loggerPcpGlue;
extern LoggerPtr loggerUeMap;
extern LoggerPtr loggerLicense;
extern LoggerPtr loggerBroadcast;
extern LoggerPtr loggerGtpcMap;
extern LoggerPtr loggerGtpcStats;
extern LoggerPtr loggerClassifyHostname;
extern LoggerPtr loggerCaptoolExtendedOutput;
extern LoggerPtr loggerClassifyCDPTimers;
extern LoggerPtr loggerPcpGluePacketBuffer;
extern LoggerPtr loggerPacketLoss;
extern LoggerPtr loggerThroughput;
extern LoggerPtr loggerFlowIntegrity;

/*
 * Used to load the configuration file from a known location. once the file has been loaded the
 * logging will be ready for use.
 */
int initializeLogging();

#endif /* LOGGER_HPP_ */
