/*
 * clientregex.hpp
 *
 *  Created on: 8 May 2013
 *      Author: ezhelao
 */

#ifndef CLIENT_HPP_
#define CLIENT_HPP_
#include <string>
#include <vector>
/*
 *
 */

//TODO memcmp first char and then memcmp the string in question. also maintain alpha order
static  std::string CLIENT_USER_AGENT_MAP[][2] = {
    {"Winamp", "^WinampMPEG"},
    {"Android-Media-Player", "^PVCore"},
    {"iPhone-Media-Player", "CoreMedia"},
    {"YouTube-player", "YouTube"},
    {"Mozilla-Firefox", "Firefox/\\d\\.\\d"},
    {"Internet-Explorer", "MSIE \\d\\.\\d"},
    {"Safari", "^Safari"},
    {"Opera", "^Opera/\\d\\.\\d"},
    {"Microsoft-Windows", "\\.download\\.windowsupdate\\.com$"}, //http host
    {"Microsoft-Windows", "^Windows-Update-Agent"},
    {"Microsoft-Windows", "^Microsoft BITS"},
    {"Ubuntu-APT", "^Ubuntu APT-HTTP/"},
    {"Telesphoreo", "^Telesphoreo APT-HTTP/"},
    {"NcAfee-antivirus", "^McAfee AutoUpdate"},
    {"Symantec", "^liveupdate\\.symantecliveupdate\\.com$"},//http host
    {"Adobe-Update-Manager", "^Adobe Update Manager"},
    {"GoogleEarth", "^GoogleEarth"},
    {"Fring", "^Fring"},
    {"Skype", "^Skype"},
    {"LetvIphoneClient", "^LetvIphoneClient"},
    {"YouTube-player", "YouTube"},
    {"Twitter", "Twitter|Tweet"},
    {"YouMail", "YouMail"},
    {"iPhone-Mail", "^iPhone Mail"},
    {"Chrome", "Chrome/\\d"},
    {"AppleDaily", "^Appledaily"},
    {"iTunes", "^iTunes"}, 
    {"Android-Market", "^/market/download/Download"}, //http host
    {"Zune", "catalog\\.zune\\.net$" } , //http host
    {"BitTorrent", "^Bittorrent"},
    {"BitComet", "^BitComet"},
    {"WordsWithFriends", "^WordsWithFriends"},
    {"Storm8", "^Storm8"},
    {"TeamLava", "teamlava.com$"}, //host
    {"KaW", "^KaW"},
    {"Smurfs", "^Smurfs"},
    {"QQGame", "^QQGame"},
    {"EmpireOL", "^EmpireOL"},
    {"LiveCams", "Live\%20Cams\%20HD"},
    {"AAStocks", "^AAStocks"},
    {"Money18", "^Money18"},
    {"ETNet", "^ETNet"},
    {"LiveStockQuote", "^LiveStockQuote"},
    {"Viber", "^Viber"},
    {"KakaoTalk", "^KakaoTalk"},
    {"KakaoTalk", "com.kakao.talk"},
    {"Installous", "^Installous"},
    {"\\N", "^Flurv"},  // not an output for CLIENT Field, but used in Service provider
    {"\\N", "^SKOUT"}, // not an output for CLIENT Field, but used in Service provider
    {"\\N", "^FlyCast"}, // not an output for CLIENT Field, but used in Service provider
    {"\\N", "^\\(Shareaza\\|BearShare\\|Azureus\\|[B\\|b]it[L\\|l]ord\\|u[T\\|t]orrent\\|BTWebClient\\)" } // not an output for CLIENT Field, but used in Service provider
    
};

extern const char* CLIENT_STR[];
extern const unsigned int MAX_SUPPORTED_CLIENTS;
extern const char* CLIENT_USER_AGENT_STR[];


class ClientFinder {
private:

public:
    ClientFinder();
    int findClientFromUserAgentMemSearch(unsigned char *userAgent, unsigned int userAgentLen, char * theHost);
    void printClientArrayInfo_1(unsigned char *userAgent, unsigned int userAgentLen, unsigned int idx1, unsigned int idx2);
    void printClientArrayInfo_2(unsigned char *userAgent, unsigned int userAgentLen, unsigned int idx1, unsigned int idx2);
    unsigned int getCharacterLocation(unsigned char *userAgent, unsigned int userAgentLen, unsigned char *theCharToFind);
    ~ClientFinder() {}
};

void cdpGetArrayStringLen(const char **theStringArray, int theStringArray_size, std::vector <size_t> &returnTheStringArray_len);

#endif /* CLIENT_HPP_ */
