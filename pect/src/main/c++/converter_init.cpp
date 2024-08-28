/*
 * converter_init.hpp
 *
 *  Created on: 20 May 2013
 *      Author: ezhelao
 */


#include "converter.h"
#include "ipq_api.h"


void Converter::initProtocolMap() {
    using namespace V13AProtocol;
    protocol13Bto13A[IPOQUE_PROTOCOL_FLASH] = RTMP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_RTSP] = RTSP;
    protocol13Bto13A[IPOQUE_PROTOCOL_RTP] = RTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_WAP_WTLS] = WAP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_WAP_WTP_WSP] = WAP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_HTTP] = HTTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_BITTORRENT] = BitTorrent;
    protocol13Bto13A[ IPOQUE_PROTOCOL_GNUTELLA] = Gnutella;
    protocol13Bto13A[ IPOQUE_PROTOCOL_DIRECTCONNECT] = DirectConnect;
    protocol13Bto13A[ IPOQUE_PROTOCOL_SIP] = SIP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_USENET] = NNTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_PPSTREAM] = PPStream;
    protocol13Bto13A[ IPOQUE_PROTOCOL_PPLIVE] = PPLive;
    protocol13Bto13A[ IPOQUE_PROTOCOL_QQLIVE] = QQLive;
    protocol13Bto13A[ IPOQUE_PROTOCOL_FUNSHION] = Funshion;
    protocol13Bto13A[ IPOQUE_PROTOCOL_SPOTIFY] = Spotify;
    protocol13Bto13A[ IPOQUE_PROTOCOL_FTP] = FTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_DNS] = DNS;
    protocol13Bto13A[ IPOQUE_PROTOCOL_SSDP] = UPnP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_STUN] = STUN;
    protocol13Bto13A[ IPOQUE_PROTOCOL_DHCP] = DHCP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_DHCPV6] = DHCP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_NTP] = NTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_MAIL_SMTP] = SMTP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_MAIL_POP] = POP3;
    protocol13Bto13A[ IPOQUE_PROTOCOL_MAIL_IMAP] = IMAP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_UNENCRYPED_JABBER] = XMPP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_SSH] = SSH;
    protocol13Bto13A[ IPOQUE_PROTOCOL_OPERAMINI] = Opera_Mini_sockets;
    protocol13Bto13A[ IPOQUE_PROTOCOL_WORLDOFWARCRAFT] = WoW;
    protocol13Bto13A[ IPOQUE_PROTOCOL_XBOX] = xbox;
    protocol13Bto13A[ IPOQUE_PROTOCOL_HALFLIFE2] = Source_engine;
    protocol13Bto13A[ IPOQUE_PROTOCOL_ICMP] = ICMP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_IGMP] = IGMP;
    protocol13Bto13A[ IPOQUE_PROTOCOL_SSL] = SSL;
}
void Converter::initFunctionMap() {
    using namespace V13AFunction;
    function13Bto13A[IPOQUE_GROUP_STREAMING] = media_playback;
    function13Bto13A[IPOQUE_GROUP_WEB] = web_browsing;
    function13Bto13A[IPOQUE_GROUP_VIDEO] = video_playback;
    function13Bto13A[IPOQUE_GROUP_IM] = instant_messaging;
    function13Bto13A[IPOQUE_GROUP_MAIL] = email;
    function13Bto13A[IPOQUE_GROUP_MOBILE] = MMS;
    function13Bto13A[IPOQUE_GROUP_FILETRANSFER] = file_download;
    function13Bto13A[IPOQUE_GROUP_P2P] = file_sharing;
    function13Bto13A[IPOQUE_GROUP_REMOTE_CONTROL] = remote_access;
    function13Bto13A[IPOQUE_GROUP_GAMING] = gaming;
    function13Bto13A[IPOQUE_GROUP_BUSINESS] = stocks;
    function13Bto13A[IPOQUE_GROUP_AUDIO] = audio_playback;
    function13Bto13A[IPOQUE_GROUP_VOIP] = VoIP;
    function13Bto13A[IPOQUE_GROUP_SOCIAL_NETWORKING] = social_networking;
}

