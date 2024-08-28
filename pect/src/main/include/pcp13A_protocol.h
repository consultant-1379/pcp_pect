/*
 * pcp13Aprotocol.hpp
 *
 *  Created on: 17 May 2013
 *      Author: ezhelao
 */

#ifndef PCP13APROTOCOL_HPP_
#define PCP13APROTOCOL_HPP_
#include <boost/tr1/unordered_map.hpp>
namespace V13AProtocol {
    static const char *V13A_PROTOCOL_STR[] = {
        "RTMP",
        "RTSP",
        "RTP",
        "WAP",
        "HTTP",
        "BitTorrent",
        "Gnutella",
        "DirectConnect",
        "SIP",
        "NNTP",
        "QVOD",
        "PPStream",
        "PPLive",
        "QQLive",
        "Funshion",
        "Spotify",
        "FTP",
        "DNS",
        "Windows",
        "UPnP",
        "STUN",
        "DHCP",
        "NTP",
        "LLMNR",
        "SMTP",
        "POP3",
        "IMAP",
        "XMPP",
        "SSH",
        "Opera-Mini-sockets",
        "WoW",
        "xbox",
        "Source-engine",
        "ICMP",
        "IGMP",
        "\\N",   // EQEV-16223 SSL is not approved to be on the NBI output of PCP; converts to null in DB  
        "HTTP", // -SPEEDTEST",
        "HTTP", //-WEATHER",
        "HTTP", //-MAPS",
        "HTTP", //-NEWS",
        "HTTP", //-ADS",
        "HTTP", //-SW-U",
        "HTTP",// -PHOTO",
        "HTTP",// -flurry, change to http for production
        "HTTP",// -andomedia, change to http for production
        "HTTP",// -admob, change to http for production
        "HTTP",// -symantec, change to http for production
        "HTTP",// -mcafee, change to http for production
        "HTTP", // - teamlava, change to http for production
        "HTTP", // - speedyshare, change to http for production
        "HTTP", // - slacker, change to http for production
        "\\N"
    };

    enum V13AProtocolEnum {
        RTMP = 0,
        RTSP,
        RTP,
        WAP,
        HTTP,
        BitTorrent,
        Gnutella,
        DirectConnect,
        SIP,
        NNTP,
        QVOD,
        PPStream,
        PPLive,
        QQLive,
        Funshion,
        Spotify,
        FTP,
        DNS,
        Windows,
        UPnP,
        STUN,
        DHCP,
        NTP,
        LLMNR,
        SMTP,
        POP3,
        IMAP,
        XMPP,
        SSH,
        Opera_Mini_sockets,
        WoW,
        xbox,
        Source_engine,
        ICMP,
        IGMP,
        SSL,
        speedtest, // protocols is HTTP
        weather,// protocols is HTTP
        maps,// protocols is HTTP
        news,// protocols is HTTP
        ADS,// protocols is HTTP
        SW,// protocols is HTTP
        PHOTO ,// protocols is HTTP
        flurry, // protocols is HTTP
        andomedia, // protocols is HTTP
        admob, // protocols is HTTP
        symantec, // protocols is HTTP
        mcafee, // protocols is HTTP
        teamlava, // protocols is HTTP
        speedyshare, // protocols is HTTP
        slacker, // protocols is HTTP
        unknown
    };
}


#endif /* PCP13APROTOCOL_HPP_ */
