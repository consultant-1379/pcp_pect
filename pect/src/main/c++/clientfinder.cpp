/*
 * client.cpp

 *
 *  Created on: 8 May 2013
 *      Author: ezhelao/ efitleo
 */


#include "clientfinder.hpp"
#include "logger.hpp"
#include <stdio.h>
#include <string.h>


// used to print client to output;

const char* CLIENT_STR[] {
		"\\N",
		"Winamp",                 // FIRST OF CLIENT_USER_AGENT_STR_1             
		"Android-Media-Player",
		"Safari",
		"Opera",
		"Microsoft-Windows",
		"Microsoft-Windows",
		"Ubuntu-APT",
		"Telesphoreo",
		"NcAfee-antivirus",
		"Symantec",
		"Adobe-Update-Manager",
		"GoogleEarth",
		"Fring",
		"Skype",
		"LetvIphoneClient",
		"iPhone-Mail",
		"AppleDaily",
		"iTunes",
		"Android-Market",
		"BitTorrent",
		"BitComet",
		"WordsWithFriends",
		"Storm8",
		"KaW",
		"Smurfs",
		"QQGame",
		"EmpireOL",
		"AAStocks",
		"Money18",
		"ETNet",
		"LiveStockQuote",
		"Viber",
		"KakaoTalk",
		"Installous",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",
		"\\N",              // FIRST OF CLIENT_USER_AGENT_STR_2
		"Mozilla-Firefox",     
		"Chrome",
		"Internet-Explorer",
		"iPhone-Media-Player",  
		"YouTube-player",
		"Microsoft-Windows",
		"Twitter",
		"Twitter",
		"YouMail",
		"Zune",
		"TeamLava",
		"LiveCams",
		"KakaoTalk"

};

// uses memcpy to search start of User Agent
const char* CLIENT_USER_AGENT_STR_1[] {
	    "\\N", // element 0 is blank to allow indexing to work corrrectly
		"WinampMPEG",
		"PVCore",
		"Safari",
		"Opera/",
		"Windows-Update-Agent",
		"Microsoft BITS",
		"Ubuntu APT-HTTP/",
		"Telesphoreo APT-HTTP/",
		"McAfee AutoUpdate",
		"liveupdate.symantecliveupdate.com",
		"Adobe Update Manager",
		"GoogleEarth",
		"Fring",
		"Skype",
		"LetvIphoneClient",
		"iPhone Mail",
		"Appledaily",
		"iTunes",
		"/market/download/Download",
		"Bittorrent",
		"BitComet",
		"WordsWithFriends",
		"Storm8",
		"KaW",
		"Smurfs",
		"QQGame",
		"EmpireOL",
		"AAStocks",
		"Money18",
		"ETNet",
		"LiveStockQuote",
		"Viber",
		"KakaoTalk",
		"Installous",
		"Flurv",
		"SKOUT",
		"FlyCast",
		"Shareaza",
		"BearShare",
		"Azureus",
		"bitlord",
		"utorrent",
		"BTWebClient",
		"uTorrent"
		
};

// uses memmem to search any part of User Agent
const char* CLIENT_USER_AGENT_STR_2[] {
		"\\N", // element 0 is blank to allow indexing to work corrrectly
		"Mozilla/",
	    "Chrome/",
	    "MSIE",
	    "CoreMedia",
		"YouTube",
		".download.windowsupdate.com",
		"Twitter",
		"Tweet",
		"YouMail",
		"catalog.zune.net",
		"teamlava.com",
		"Live\%20Cams\%20HD",
		"com.kakao.talk"
		
};


const unsigned int MAX_SUPPORTED_CLIENTS = 59;
const unsigned int CLIENT_USER_AGENT_STR_1_SIZE = 45;
const unsigned int CLIENT_USER_AGENT_STR_2_SIZE = 14; 
std::vector<size_t> CLIENT_USER_AGENT_STR_1_LEN(45);
std::vector<size_t> CLIENT_USER_AGENT_STR_2_LEN(14);


ClientFinder::ClientFinder() {
   
   cdpGetArrayStringLen(CLIENT_USER_AGENT_STR_1, CLIENT_USER_AGENT_STR_1_SIZE, CLIENT_USER_AGENT_STR_1_LEN);
   cdpGetArrayStringLen(CLIENT_USER_AGENT_STR_2, CLIENT_USER_AGENT_STR_2_SIZE, CLIENT_USER_AGENT_STR_2_LEN);
   /*
   unsigned int idx1,idx2;
   for(idx1 = 1; idx1 < CLIENT_USER_AGENT_STR_1_SIZE; idx1++) {
		LOG4CXX_INFO(loggerClassify, "CLIENT FINDER:   CLIENT_STR[" << idx1 << "]" <<  CLIENT_STR[idx1] 
												 << ": CLIENT_USER_AGENT_STR_1["  << idx1 << "]" << CLIENT_USER_AGENT_STR_1[idx1] 
												 << ": Length["  << idx1 << "]" << CLIENT_USER_AGENT_STR_1_LEN.at(idx1) 
												 ) ; 
   }
   for(idx2 = 1; idx2 < CLIENT_USER_AGENT_STR_2_SIZE; idx2++) {
		LOG4CXX_INFO(loggerClassify, "CLIENT FINDER:   CLIENT_STR[" << idx1 + idx2 << "]" <<  CLIENT_STR[idx1 + idx2] 
												 << ": CLIENT_USER_AGENT_STR_2["  << idx2 << "]" << CLIENT_USER_AGENT_STR_2[idx2] 
												 << ": Length["  << idx2 << "]" << CLIENT_USER_AGENT_STR_2_LEN.at(idx2) 
												 ) ;				                                         
   }
   */
        
}

/**
 * input: userAgentString & length
 *        index to user agent length
 *        indexes to allow pringting from CLIENT_STR
 * output: printout of Client string that matches current inputed user agent string
 */
void ClientFinder::printClientArrayInfo_1(unsigned char *userAgent, unsigned int userAgentLen, unsigned int idx1, unsigned int idx2){
 	    if(idx1 < CLIENT_USER_AGENT_STR_1_SIZE) {
			userAgent[userAgentLen-1]= '\0';
			LOG4CXX_INFO(loggerClassify, "CLIENT FINDER:   Idx = " << (idx1 + idx2) 
												 << ": CLIENT_STR["  << (idx1 + idx2) << "] " << CLIENT_STR[(idx1 + idx2)] 
												 << ": CLIENT_USER_AGENT_STR_1["  << idx1 << "] " << CLIENT_USER_AGENT_STR_1[idx1] 
												 << ": Length["  << idx1 << "] " << CLIENT_USER_AGENT_STR_1_LEN.at(idx1) 
												 << ": userAgent " <<  userAgent
												 );
		}
} 
/**
 * input: userAgentString & length
 *        index to user agent length
 *        indexes to allow pringting from CLIENT_STR
 * output: printout of Client string that matches current inputed user agent string
 */
void ClientFinder::printClientArrayInfo_2(unsigned char *userAgent, unsigned int userAgentLen, unsigned int idx1, unsigned int idx2){
 	    if(idx2 < CLIENT_USER_AGENT_STR_2_SIZE) {
		    userAgent[userAgentLen-1]= '\0';
			LOG4CXX_INFO(loggerClassify, "CLIENT FINDER:   Idx = " << (idx1 + idx2) 
												 << ": CLIENT_STR["  << (idx1 + idx2) << "] " << CLIENT_STR[(idx1 + idx2)] 
												 << ": CLIENT_USER_AGENT_STR_2["  << idx2 << "] " << CLIENT_USER_AGENT_STR_2[idx2] 
												 << ": Length["  << idx2 << "] " << CLIENT_USER_AGENT_STR_2_LEN.at(idx2) 
												 << ": userAgent " <<  userAgent
												 );
	    }
} 

/**
 * Purpuse: return location (index) of a specific char in a string (char *)
 * Input : User agent string (char *) & length and the char to find
 * Returns: Indexed location for a match of the char to find in the useragent string (char*) or -1 if no match
 */ 
unsigned int ClientFinder::getCharacterLocation(unsigned char *userAgent, unsigned int userAgentLen, unsigned char *theCharToFind){
	for(unsigned int i=0; i< userAgentLen; i++){
		if(userAgent[i] == *theCharToFind) {
			return i;
		}
	}
	return userAgentLen;
}

/**
 * Purpuse: Find user Agent that matches input from  CLIENT_USER_AGENT_STR_1 & CLIENT_USER_AGENT_STR_2 arrays
 * Input : User agent string & length and host string (for debug print)
 * Returns: Indexed location for a match in CLIENT_STR or -1 if no match
 */ 											  
int ClientFinder::findClientFromUserAgentMemSearch(unsigned char *userAgent, unsigned int userAgentLen, char * theHost) {

   unsigned int idx1,idx2;
   idx1=0;
   idx2=0;
   for(idx1 = 1; idx1 < CLIENT_USER_AGENT_STR_1_SIZE; idx1++) {
	    if(userAgentLen >= CLIENT_USER_AGENT_STR_1_LEN.at(idx1)){
			if(memcmp(userAgent, CLIENT_USER_AGENT_STR_1[idx1], CLIENT_USER_AGENT_STR_1_LEN.at(idx1)) == 0) {
				/* found */		
				//printClientArrayInfo_1(userAgent,userAgentLen,idx1,idx2);
				return idx1;
			}
		}
   }
   // EXAMPLE need to find "Mozilla" not Chrome :- fr;Mozilla/5.0 (Linux; Android 4.4.2; GT-I9505 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.3
   unsigned char endChar = '(' ; // terminate useragent search at first bracket as this is where the compatibility list starts
   unsigned int endLocation = getCharacterLocation(userAgent,userAgentLen, &endChar);
   //userAgent[userAgentLen-1]= '\0';  // for print 
   //LOG4CXX_INFO(loggerClassify, "CLIENT FINDER: RAW : userAgent = " << userAgent << ": Host = " << theHost << ": endChar = " << endChar << ": endLocation/userAgentLen = " << endLocation << "/" << userAgentLen ); 
   for(idx2 = 1; idx2 < CLIENT_USER_AGENT_STR_2_SIZE; idx2++) {
	    if(endLocation >= CLIENT_USER_AGENT_STR_2_LEN.at(idx2)){
			if(memmem(userAgent, endLocation, CLIENT_USER_AGENT_STR_2[idx2], CLIENT_USER_AGENT_STR_2_LEN.at(idx2)) != NULL) {
				//printClientArrayInfo_2(userAgent,userAgentLen,idx1, idx2);
				/* found */		
				return (idx1+idx2);
			}
		}
   }
   return -1;

}
