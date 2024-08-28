#include <boost/tr1/unordered_map.hpp>
#include "service_provider.hpp"
#include "ipq_api.h"


extern unsigned int MAX_SUPPORTED_PROTOCOLS;
extern unsigned int MAX_SUPPORTED_GROUPS;




ServiceProvider::ServiceProvider(){
			LOG4CXX_INFO(loggerClassify, "SERVICE_PROVIDER: INIT: Initialising Service provider ");
            initServiceProvider_protocolMap();
            initServiceProvider_subProtocolMap();
            initServiceProvider_applicationMap();
            initServiceProvider_protocolGroupMap();
			initServiceProvider_clientfinderMap();
}


ServiceProvider::ServiceProvider(int classfiyInstanceNum){
			LOG4CXX_INFO(loggerClassify, "SERVICE_PROVIDER: INIT: Initialising Service provider [" << classfiyInstanceNum << "]" );
            initServiceProvider_protocolMap();
            initServiceProvider_subProtocolMap();
            initServiceProvider_applicationMap();
            initServiceProvider_protocolGroupMap();
			initServiceProvider_clientfinderMap();
}


void ServiceProvider::initServiceProvider_protocolMap(){
    using namespace service_provider_info;
    service_provider_protocol[IPOQUE_PROTOCOL_PANDORA] = Pandora;
    service_provider_protocol[IPOQUE_PROTOCOL_NETFLIX] = Netflix;
    service_provider_protocol[IPOQUE_PROTOCOL_QQLIVE ] = Tencent_QQ;
    service_provider_protocol[IPOQUE_PROTOCOL_YAHOO] = Yahoo;
    service_provider_protocol[IPOQUE_PROTOCOL_MSN] = MSN;
    service_provider_protocol[IPOQUE_PROTOCOL_VIBER] = Viber;    
    service_provider_protocol[IPOQUE_PROTOCOL_JABBER_APPLICATION_NIMBUZZ] = Nimbuzz;
    service_provider_protocol[IPOQUE_PROTOCOL_PPSTREAM] = PPStream;
    service_provider_protocol[IPOQUE_PROTOCOL_PPLIVE] = PPLive;
    service_provider_protocol[IPOQUE_PROTOCOL_FUNSHION] = Funshion;
    service_provider_protocol[IPOQUE_PROTOCOL_SPOTIFY] = Spotify;
    service_provider_protocol[IPOQUE_PROTOCOL_HTTP_APPLICATION_GOOGLE_TALK] = Google;
    service_provider_protocol[IPOQUE_PROTOCOL_GOOGLE] = Google;
    service_provider_protocol[IPOQUE_PROTOCOL_APPLEJUICE] = Apple;
    service_provider_protocol[IPOQUE_PROTOCOL_ADOBE_CONNECT] = Adobe;
    service_provider_protocol[IPOQUE_PROTOCOL_OSCAR] = AOL;
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 9] = Flurry; //CDP
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 10] = Andomedia; //CDP
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 11] = AdMob; //CDP
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 12] = Symantec; //CDP
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 13] = McAfee; //CDP    
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 14] = TeamLava; //CDP    
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 15] = SpeedyShare; //CDP  
    service_provider_protocol[IPOQUE_LAST_IMPLEMENTED_PROTOCOL + 16] = Slacker; //CDP          
	service_provider_protocol[IPOQUE_PROTOCOL_XBOX] = Microsoft;
}

void ServiceProvider::initServiceProvider_subProtocolMap(){
    using namespace service_provider_info;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_RAPIDSHARE_COM] = RapidShare;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_MEGAUPLOAD_COM] = megaupload;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_2SHARED_COM] = _2shared;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_FILESONIC_COM] = FileSonic;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_HOTFILE_COM] = Hotfile;
    service_provider_subProtocol[IPOQUE_PROTOCOL_DDL_SUBTYPE_YOUTUBE_COM] = YouTube;
}

void ServiceProvider::initServiceProvider_protocolGroupMap(){
    using namespace service_provider_info;
    service_provider_protocolGroup[IPOQUE_GROUP_P2P] = P2P;
    
}
void ServiceProvider::initServiceProvider_applicationMap(){
    using namespace service_provider_info;
    service_provider_application[IPOQUE_APPLICATION_FACEBOOK] = Facebook;
    service_provider_application[IPOQUE_APPLICATION_FRIENDSTER] = Friendster;
    service_provider_application[IPOQUE_APPLICATION_TWITTER] = Twitter;
    service_provider_application[IPOQUE_APPLICATION_MYSPACE] = Myspace;
    service_provider_application[IPOQUE_APPLICATION_FLICKR] = Flickr;
    service_provider_application[IPOQUE_APPLICATION_ITUNES] = iTunes;

    service_provider_application[IPOQUE_APPLICATION_YOUTUBE] = YouTube;
    service_provider_application[IPOQUE_APPLICATION_GOOGLEDOCS] = Google;
    service_provider_application[IPOQUE_APPLICATION_ICLOUD] = Apple;
    service_provider_application[IPOQUE_APPLICATION_IMESSAGE] = Apple;
    service_provider_application[IPOQUE_APPLICATION_ADOBE_CREATIVE_CLOUD] = Adobe;
    
}

/*
 *  Index   Client
 *      0    \N
		1    		Winamp
		2    		Android-Media-Player
		3    		Safari
		4    		Opera
		5    		Microsoft-Windows
		6    		Microsoft-Windows
		7    		Ubuntu-APT
		8    		Telesphoreo
		9    		NcAfee-antivirus
		10    		Symantec
		11    		Adobe-Update-Manager
		12    		GoogleEarth
		13    		Fring
		14    		Skype
		15    		LetvIphoneClient
		16    		iPhone-Mail
		17    		AppleDaily
		18    		iTunes
		19    		Android-Market
		20    		BitTorrent
		21    		BitComet
		22    		WordsWithFriends
		23    		Storm8
		24    		KaW
		25    		Smurfs
		26    		QQGame
		27    		EmpireOL
		28    		AAStocks
		29    		Money18
		30    		ETNet
		31    		LiveStockQuote
		32    		Viber
		33    		KakaoTalk
		34    		Installous
		35    		\\N
		36    		\\N
		37    		\\N
		38    		\\N 
		39    		\\N 
		40    		\\N 
		41    		\\N 
		42    		\\N 
		43    		\\N 
		44    		\\N 
		45    		\\N 
		46           Mozilla-Firefox
		47    		Chrome
		48    		Internet-Explorert
		49    		iPhone-Media-Player
		50    		YouTube-player
		51    		Microsoft-Windows
		52    		Twitter
		53    		Twitter
		54    		YouMail
		55    		Zune
		56    		TeamLava
		57    		LiveCams
		58    		KakaoTalk


*/
void ServiceProvider::initServiceProvider_clientfinderMap(){
    using namespace service_provider_info;
    service_provider_clinetfinder[5] = Microsoft;
    service_provider_clinetfinder[6] = Microsoft;
    service_provider_clinetfinder[7] = Ubuntu;
    service_provider_clinetfinder[19] = Android_Market;
    service_provider_clinetfinder[51] = Microsoft;
    service_provider_clinetfinder[54] = YouMail;
    service_provider_clinetfinder[55] = Microsoft;  // Zune
    
    service_provider_clinetfinder[35] = Flurv;
    service_provider_clinetfinder[36] = SKOUT;
    service_provider_clinetfinder[37] = FlyCast;
    service_provider_clinetfinder[38] = P2P; // Shareaza
    service_provider_clinetfinder[39] = P2P; // BearShare
    service_provider_clinetfinder[40] = P2P; // Azureus
    service_provider_clinetfinder[41] = P2P; // bitlord
    service_provider_clinetfinder[42] = P2P; // utorrent
    service_provider_clinetfinder[43] = P2P; // BWebClient
    service_provider_clinetfinder[44] = P2P; // uTorrent
   
}


void ServiceProvider::printServiceProviderInfo(flow_data* fd, const char* myTitle, int *check_service_provider){
    if((loggerClassify->isTraceEnabled())) {
    //if((loggerClassify->isInfoEnabled())) {
			
			char applicationBuf[MAX_APPLICATION_STRING_LENGTH];
			getApplicationValueAsString(fd->application, applicationBuf);
			char sub_protocol_strBuf[MAX_SUB_PROTOCOL_STRING_LENGTH];
			getSubProtocolValueAsString(fd->sub_protocol, fd->sub_protocol_str, sub_protocol_strBuf);
			char protocolBuf[MAX_IPOQUE_PROTOCOL_STRING_LENGTH];
			getProtocolValueAsString(fd->protocol, protocolBuf);
			char protocolGroupBuf[MAX_IPOQUE_GROUP_STRING_LENGTH];
			getProtocolGroupValueAsString(fd->group, protocolGroupBuf);
			
			LOG4CXX_INFO(loggerClassify, "SERVICE_PROVIDER " << myTitle << ": service_provider (Str) = " << service_provider_info::SERVICE_PROVIDER_STR[fd->service_provider]
                                                  << ": service_provider (enum) =  " << fd->service_provider 
                                                  << ": application =  " << applicationBuf << "(" << fd->application << ")"
                                                  << ": group =  " << protocolGroupBuf << "(" << fd->group << ")"
                                                  << ": sub_protocol =  " << sub_protocol_strBuf << "(" << fd->sub_protocol << ")"
                                                  << ": protocol =  " << protocolBuf <<"(" << fd->protocol << ")"
                                                  << ": Client =  " << CLIENT_STR[fd->client] <<"(" << fd->client << ")"
                                                  << ": check_service_provider =  " << *check_service_provider
                                                  );
    }
}
void ServiceProvider::getServiceProvider(flow_data* fd, int *check_service_provider){
         
        if(*check_service_provider) {
			if((fd->application <= 1) && (fd->protocol == 0 ) ){
				fd->service_provider =  0; //Unknown
				//printServiceProviderInfo(fd, (const char*) "DURING", check_service_provider);
				
			}
			if((fd->application != UINT_MAX) && (fd->application < ((int)IPOQUE_NUMBER_OF_APPLICATIONS)) && (fd->application > 1) ) { // IPOQUE_APPLICATION_NOT_DETECTED == 1
				std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum>::iterator it_app = service_provider_application.find(fd->application);

				if(it_app != service_provider_application.end()) {
					fd->service_provider = it_app->second;
					return;
				}
			} 
			
			if((fd->sub_protocol != UINT_MAX) && (fd->sub_protocol <= IPOQUE_MAX_SUPPORTED_SUB_PROTOCOLS) && (fd->protocol > 0 )) { // IPOQUE_PROTOCOL_UNKNOWN == 0
			   std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum>::iterator it_sub = service_provider_subProtocol.find(fd->sub_protocol);

				if(it_sub != service_provider_subProtocol.end()) {
					fd->service_provider = it_sub->second;
					return;
				}
			}
			
			if((fd->protocol != UINT_MAX) && (fd->protocol <= MAX_SUPPORTED_PROTOCOLS) && (fd->protocol >  0 )) { // IPOQUE_PROTOCOL_UNKNOWN == 0
				std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum>::iterator it_protocol = service_provider_protocol.find(fd->protocol);

				if(it_protocol != service_provider_protocol.end()) {
					fd->service_provider = it_protocol->second;
					return;
				}
			
			}
			if((fd->client != 0) && (fd->client <= MAX_SUPPORTED_CLIENTS) ) { // fd->client == \N
				std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum>::iterator it_client = service_provider_clinetfinder.find(fd->client);

				if(it_client != service_provider_clinetfinder.end()) {
					fd->service_provider = it_client->second;
					return;
				}
			
			}
		}
    
}

void ServiceProvider::getGroupServiceProvider(flow_data* fd, unsigned int protocol, unsigned int application){
         
        
			if((fd->group != UINT_MAX) && (fd->group <= MAX_SUPPORTED_GROUPS) && (fd->group > 0)) {
				std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum>::iterator it_group = service_provider_protocolGroup.find(fd->group);

				if(it_group != service_provider_protocolGroup.end()) {
					fd->service_provider = it_group->second;
				}
			
			}
			if((fd->group == 0) && (protocol == 0) && (application <= 1)) {
				fd->service_provider = 0; //Unknown
			}			    
}
ServiceProvider::~ServiceProvider() {
}	
