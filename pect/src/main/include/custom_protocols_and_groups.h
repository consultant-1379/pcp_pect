/*
 * custom_protocols_and_groups.h
 *
 *  Created on: 5 Mar 2014
 *      Author: efitleo
 */

#ifndef CUSTOM_PROTOCOLS_AND_GROUPS_H_
#define CUSTOM_PROTOCOLS_AND_GROUPS_H_

#define IPOQUE_MAX_CUSTOM_PROTOCOLS 16
// See definition of IPOQUE_MAX_HTTP_CUSTOM_PROTOCOLS in pcp_limits.h

#include "pcp_limits.h"

unsigned int MAX_SUPPORTED_PROTOCOLS = IPOQUE_LAST_IMPLEMENTED_PROTOCOL + IPOQUE_MAX_CUSTOM_PROTOCOLS;
unsigned int MAX_SUPPORTED_GROUPS = IPOQUE_NUMBER_OF_GROUPS + 8;

int INITIAL_LEN = 100;

int CDP_MATCH = 0;
int CDP_EXCLUDE = 1;
int CDP_NOT_MATCH = -1;


int CDP_PROTOCOL_SPEEDTEST = 0;
int CDP_PROTOCOL_WEATHER = 1;
int CDP_PROTOCOL_MAPS = 2;
int CDP_PROTOCOL_NEWS = 3;
int CDP_PROTOCOL_ADVERTISEMENTS = 4;
int CDP_PROTOCOL_SW_UPDATES = 5;
int CDP_PROTOCOL_PHOTO_SHARING = 6;
//LLMNR = 7

int MAX_SIMPLE_HOSTS = 8;
int CDP_SIMPLE_HOST_PROTOCOL[] = {
    8,  // Flurry
	9,  // ANDOMEDIA
	10, // ADMOB
	11, // SYMANTEC
	12, // MCAFEE
	13, // Team Lava
	14, // SpeedyShare
	15  // Slacker
};

const char *CDP_PROTOCOL_HTTP[] = {"Speedtest", "Weather", "Maps", "News", "Advertisements", "SW_Updates", "Photo Sharing", "flurry", "Andomenia", "Admob", "Symantec Live Update", "McAfee AutoUpdate", "TeamLava", "SpeedyShare", "Slacker"} ;

//HTTP HOST is the first CUSTOM DEFINED PROTOCOL

const char *CDP_SPEEDTEST_DEFAULT[] = {
    "speedtest\0"
};
int CDP_SPEEDTEST_DEFAULT_SIZE;
std::vector<size_t> CDP_SPEEDTEST_DEFAULT_LEN(INITIAL_LEN);

const char *CDP_WEATHER_DEFAULT[] = {
    "weather\0",
    "metoffice\0",
    "noaa.gov\0",
    "www.intellicast.com\0",
    "www.windfinder.com\0",
    "www.metoffice.gov.uk\0",
    "www.yr.no\0",
    "www.met.ie\0",
    "www.accuweather.com\0"
};

const char *CDP_WEATHER[] = {
    "www.weather.com\0" ,
    "www.weather.gov.hk\0"
};

int CDP_WEATHER_DEFAULT_SIZE;
int CDP_WEATHER_SIZE;
std::vector<size_t> CDP_WEATHER_DEFAULT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_WEATHER_LEN(INITIAL_LEN);



const char *CDP_MAPS_DEFAULT[] = {
    "maps.\0",
    "virtualearth\0",
    "earth.google.\0",
    "trapster\0",
    "agps.location.live.net\0",
    "www.google.com/loc/m/api\0",
    "www.google.com/glm/mmap\0"
};

const char *CDP_MAPS[] = {
    "www.trapster.com\0",
    "www.google.com/loc/m/api\0",
    "www.google.com/glm/mmap\0"
};

const char *CDP_MAPS_USER_AGENT[] = {
    "GoogleMobile\0",
    "GMM\0",
    "GoogleEarth\0",
    "Trapster\0",
    "trapster\0",
    "maps\0"
};

const char *CDP_MAPS_URL[] = {
    "/glm/mmap\0",
    "/loc/m/api\0"
};

int CDP_MAPS_URL_SIZE;
int CDP_MAPS_USER_AGENT_SIZE;
int CDP_MAPS_DEFAULT_SIZE;
int CDP_MAPS_SIZE;
std::vector<size_t> CDP_MAPS_DEFAULT_LEN(INITIAL_LEN) ;
std::vector<size_t> CDP_MAPS_LEN(INITIAL_LEN);
std::vector<size_t> CDP_MAPS_USER_AGENT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_MAPS_URL_LEN(INITIAL_LEN);

const char *CDP_NEWS_DEFAULT[] = {
    "news\0",
    "www.cnn.com\0",
    "www.itn.co.uk\0"
};

const char *CDP_NEWS[] = {
    "www.cnn.com\0",
    "www.itn.co.uk\0"
};

int CDP_NEWS_DEFAULT_SIZE;
int CDP_NEWS_SIZE;
std::vector<size_t> CDP_NEWS_DEFAULT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_NEWS_LEN(INITIAL_LEN);



unsigned int CUSTOM_GROUP_SYSTEM_NUMBER = ((unsigned int)IPOQUE_NUMBER_OF_GROUPS) + 5;

std::tr1::unordered_map<unsigned int, unsigned int> custom_group_system = {
    {((unsigned int)IPOQUE_PROTOCOL_SSDP), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_DHCP), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_DHCPV6), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_NTP), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_STUN), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_ICMP), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_IGMP), CUSTOM_GROUP_SYSTEM_NUMBER},
    {((unsigned int)IPOQUE_PROTOCOL_DNS), CUSTOM_GROUP_SYSTEM_NUMBER}
};


const char *CDP_ADVERTISEMENTS_DEFAULT[] = {
    "doubleclick.net\0", 
    "advert",
    //"flurry.com\0",   // Simple Host CDP of its own now.. see below
    //"andomedia.com\0", // Simple Host CDP of its own now.. see below
    //"admob.com\0",    // Simple Host CDP of its own now.. see below
    "adwhirl.com\0"
};

const char *CDP_ADVERTISEMENTS[] = {
    "ad.doubleclick.net\0",
    //"data.flurry.com\0", // Simple Host CDP of its own now.. see below
    //"media.admob.com\0", // Simple Host CDP of its own now.. see below
    "met.adwhirl.com\0"
};

const char *CDP_ADVERTISEMENTS_USER_AGENT[] = {
    "GoogleAnalytics\0",
    "googleanalytics\0"
};

const char *CDP_ADVERTISEMENTS_URL[] = {
    "__utm.gif\0",
    "pagead/ads\0"
};

int CDP_ADVERTISEMENTS_URL_SIZE;
int CDP_ADVERTISEMENTS_USER_AGENT_SIZE;
int CDP_ADVERTISEMENTS_DEFAULT_SIZE;
int CDP_ADVERTISEMENTS_SIZE;
std::vector<size_t> CDP_ADVERTISEMENTS_DEFAULT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_ADVERTISEMENTS_LEN(INITIAL_LEN);
std::vector<size_t> CDP_ADVERTISEMENTS_USER_AGENT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_ADVERTISEMENTS_URL_LEN(INITIAL_LEN);


const char *CDP_SW_UPDATES_DEFAULT[] = {
    "telesphoreo\0",
    "download\0",
    //"symantecliveupdate.com\0", // Simple Host CDP of its own now.. see below
    "adobe.com/support/downloads\0"
};

const char *CDP_SW_UPDATES[] = {
    "liveupdate.symantecliveupdate.com\0",
    "Telesphoreo\0",
    ".download.windowsupdate.com\0"
};


const char *CDP_SW_UPDATES_USER_AGENT[] = {
    "Installous\0",
    "Adobe Update Manager\0",
    "Software%20Update\0",
    "Installer\0",
    //"McAfee AutoUpdate\0", // Simple Host CDP of its own now.. see below
    "Telesphoreo APT-HTTP\0",
    "Ubuntu APT-HTTP\0",
    "Microsoft BITS\0",
    "Windows-Update-Agent\0"
};


int CDP_SW_UPDATES_USER_AGENT_SIZE;
int CDP_SW_UPDATES_DEFAULT_SIZE;
int CDP_SW_UPDATES_SIZE;
std::vector<size_t> CDP_SW_UPDATES_DEFAULT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_SW_UPDATES_LEN(INITIAL_LEN);
std::vector<size_t> CDP_SW_UPDATES_USER_AGENT_LEN(INITIAL_LEN);

const char *CDP_PHOTO_SHARING_DEFAULT[] = {
    "picasaweb.google.com\0",
    "flickr.com\0"
};

const char *CDP_PHOTO_SHARING[] = {
    "picasaweb.google.com\0",
    "flickr.com\0"
};

int CDP_PHOTO_SHARING_DEFAULT_SIZE;
int CDP_PHOTO_SHARING_SIZE;
std::vector<size_t> CDP_PHOTO_SHARING_DEFAULT_LEN(INITIAL_LEN);
std::vector<size_t> CDP_PHOTO_SHARING_LEN(INITIAL_LEN);

// LLMR is CDP #8
// LLMNR is DNS on port port 5355 (server port)
/* LLMNR queries are sent to and received on port 5355 (i.e server port is 5355). The IPv4 link-
    scope multicast address a given responder listens to, and to which a
    sender sends queries, is 224.0.0.252. The IPv6 link-scope multicast
    address a given responder listens to, and to which a sender sends all
    queries, is FF02:0:0:0:0:0:1:3.
*/
//efitleo: 23June14; EQEV-14220 ; updated to indicate the ue port need not be 5355 for LLMNR (just server port)
uint32_t llmnr_serverIP = 3758096636; //224.0.0.252 for IPV4 only
uint32_t llmnr_serverPort = 5355;
//uint32_t llmnr_uePort = 5355;


/* TESTING LLMNR
    Test using 17221118:43933, 3251538722:80  and Throughput test 1

    uint32_t llmnr_serverIP=3251538722;
    uint32_t llmnr_serverPort=80;
    uint32_t llmnr_uePort=43933;


    TEST 1: Gn Simulator [native] eclipsedownload-10.156.64.127-port-43933.pcap [Big Download, with and without pauses]
	rm -f /var/opt/ericsson/pcp/cache/gtpc.cache-001 & Ensure Gn loads Relevant GTPC info into PCP. [tail -f pect.log|grep pect.gtpcparser]
	./pcp-pect-packet-loss -properties properties_gn_8Streams_0k_Threshold.xml
	/root/gn-sim/simulator_13Sept13  -i eth6 -u eth5  -t 10000000 -m 500000 gtp-hack/cells.cfg gtp-hack/gn.cfg gtp-hack/eclipsedownload-traffic.cfg gtp-hack/theOne
*/


// Update CDP_SIMPLE_HOST in classify.cc
extern const char *CDP_SIMPLE_HOST[];

int CDP_SIMPLE_HOST_SIZE;
std::vector<size_t> CDP_SIMPLE_HOST_LEN[] ={
	std::vector<size_t>(INITIAL_LEN), // Flurry
	std::vector<size_t>(INITIAL_LEN), // ANDOMEDIA
	std::vector<size_t>(INITIAL_LEN), // ADMOB
	std::vector<size_t>(INITIAL_LEN), // SYMANTEC
	std::vector<size_t>(INITIAL_LEN), // MCAFEE
	std::vector<size_t>(INITIAL_LEN), // Team Lava
	std::vector<size_t>(INITIAL_LEN), // SpeedyShare
	std::vector<size_t>(INITIAL_LEN)  // Slacker
};
  
#endif /* CUSTOM_PROTOCOLS_AND_GROUPS_H_ */
