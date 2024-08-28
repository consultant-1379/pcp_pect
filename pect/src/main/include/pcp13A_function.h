/*
 * pcp13Afunction.hpp
 *
 *  Created on: 17 May 2013
 *      Author: ezhelao
 */


namespace V13AFunction{

static const char* V13A_FUNCTION_STR[]={
"media-playback" ,
"VoIP",
"web-browsing",
"video-playback",
"audio-playback",
"advertisement",
"instant-messaging",
"social-networking",
"photo-sharing",
"email",
"MMS",
"file-download",
"file-sharing",
"news",
"software-update",
"system",
"maps",
"weather",
"remote-access",
"gaming",
"speedtest",
"stocks",
"\\N"
};

enum V13AFunctionEnum {
    media_playback=0 ,
    VoIP,
    web_browsing,
    video_playback,
    audio_playback,
    advertisement,
    instant_messaging,
    social_networking,
    photo_sharing,
    email,
    MMS,
    file_download,
    file_sharing,
    news,
    software_update,
    system,
    maps,
    weather,
    remote_access,
    gaming,
    speedtest,
    stocks,
    unknown
};
}
