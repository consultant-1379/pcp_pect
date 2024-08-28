#ifndef __IPQ_METADATA_PUBLIC_H__
#define __IPQ_METADATA_PUBLIC_H__

#ifndef __IPOQUE_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE IPQ_API.H
#endif

#if IPOQUE_PACE_API_VARIANT == 2

enum metadata_type {
    DISSECTOR_IP = 0,
    DISSECTOR_TCP,
    DISSECTOR_H264,
    DISSECTOR_AMR,
    DISSECTOR_RTP,
    DISSECTOR_ID3,
    DISSECTOR_MP3,
    DISSECTOR_HTTP,
    DISSECTOR_MP4,

    METADATA_DISSECTOR_COUNT
};

enum metadata_status {
    METADATA_DISSECTOR_SUCCESS = 0,
    METADATA_DISSECTOR_MEMORY_ALLOCATION_FAILED,
    METADATA_DISSECTOR_INVALID_ARGUMENTS,
    METADATA_DISSECTOR_NO_DATA,
    METADATA_DISSECTOR_NOT_ENABLED,
    METADATA_DISSECTOR_MISSING_DEPENDENCY,
    METADATA_DISSECTOR_FAILURE
};

#define CODEC_LIST(M) M(UNKNOWN, UNKNOWN) \
                      M(H263,    VIDEO)   \
                      M(H264,    VIDEO)   \
                      M(AMR,     AUDIO)   \
                      M(PCMU,    AUDIO)   \
                      M(GSM,     AUDIO)   \
                      M(G723,    AUDIO)   \
                      M(DVI4,    AUDIO)   \
                      M(LPC,     AUDIO)   \
                      M(PCMA,    AUDIO)   \
                      M(G722,    AUDIO)   \
                      M(L16,     AUDIO)   \
                      M(QCELP,   AUDIO)   \
                      M(CN,      AUDIO)   \
                      M(MPA,     AUDIO)   \
                      M(G728,    AUDIO)   \
                      M(G729,    AUDIO)   \
                      M(CELB,    VIDEO)   \
                      M(H261,    VIDEO)   \
                      M(MPV,     VIDEO)   \
                      M(JPEG,    VIDEO)   \
                      M(NV,      VIDEO)   \
                      M(AMR_WB,  AUDIO)   \
                      M(AAC,     AUDIO)   \
                      M(MP3,     AUDIO)   \
                      M(MP4,     AUDIO)

#define STREAM_TYPE_LIST(M) M(UNKNOWN)              \
                            M(AUDIO)                \
                            M(VIDEO)                \
                            M(AUDIO_VIDEO)

#define LIST_TO_STREAM_TYPE_ENUM(NAME) STREAM_TYPE_ ## NAME,
#define LIST_TO_CODEC_ENUM(NAME, ...) CODEC_ ## NAME,
#define LIST_TO_STR(NAME, ...) #NAME,

enum stream_media_type {
    STREAM_TYPE_LIST(LIST_TO_STREAM_TYPE_ENUM)

    NUMBER_OF_STREAM_TYPES
};

enum codec_type {
    CODEC_LIST(LIST_TO_CODEC_ENUM)

    NUMBER_OF_CODECS
};

struct metadata_string {
    u8 const * ptr;
    u16 len;
} __attribute__ ((packed));

union metadata_result {
    struct {
        struct {
            u16 min;                /* Minimum packet size per flow */
            u16 max;                /* Maximum packet size per flow */
            u16 avg;                /* Average packet size per flow */
        } packet_size[2];

        u32 invalid_checksums[2];   /* Total count of invalid IP checksum per flow and direction */

        struct {
            u64 min;                /* Minimum throughput in Bytes/s per flow */
            u64 max;                /* Maximum throughput in Bytes/s per flow */
            u64 avg;                /* Average throughput in Bytes/s per flow */
        } throughput[2];

        u64 throughput_interval[2]; /* Throughput in Bytes/s
                                       The interval is the time between one get_metadata_ip()
                                       function call and the next one.
                                     */
        u32 interval_duration[2];   /* Interval duration of throughput_interval in s*/
    } ip;

    struct {

        u32 ooo_packets;            /* Total count of out-of-order packets per flow */
        u32 retransmissions;        /* Total count of retransmitted packets per flow */
        u32 invalid_checksums[2];   /* Total count of packets with an invalid TCP checksum per flow and direction */

        struct {
            u16 min;                /* Minimum TCP window size per flow and direction */
            u16 max;                /* Maximum TCP window size per flow and direction */
            u16 avg;                /* Average TCP window size per flow and direction */
            u16 cur;                /* Current TCP window size of the packet */
        } window_size[2];

        struct {
            u8 value:4;             /* Current window scale value per flow and direction */
        } window_scale[2];
    } tcp;


    struct {
        struct {
            u8 numerator;
            u8 divisor;
        } aspect_ratio[2];                      /* aspect ratio, i.e 4:3 */

        u32 bitrate[2];                         /* bitrate in bits per second */
        u32 frame_count[2];                     /* total number of frames */
        u32 iframe_count[2];                    /* number of i-frames */
        u16 picture_width[2];                   /* picture width in pixels */
        u16 picture_height[2];                  /* picture height in pixels */
        u8 frame_rate[2];                       /* frame rate in frames per second */
        u8 avg_frame_rate[2];                   /* average frame rate in frames per second */
    } h264;

    struct {
        const char *codec_str[2];               /* detected codec as string */
        const char *stream_type_str[2];         /* detected stream type as string */
        enum codec_type codec[2];               /* detected codec as enum value */
        enum stream_media_type stream_type[2];  /* detected stream type as enum value */
    } rtp;

    struct {
        u32 bitrate[2];                         /* bitrate in bits per second */
        u8 dtx_silence_active[2];               /* whether dtx silence is currently active or not */
    } amr;

    struct {
        struct {
            struct metadata_string talb;       /* Album/Movie/Show title */
            struct metadata_string tpe1;       /* Lead performer(s)/Soloist(s) */
            struct metadata_string tpe2;       /* Band/orchestra/accompaniment */
            struct metadata_string tpe3;       /* Conductor/performer refinement */
            struct metadata_string tpe4;       /* Interpreted, remixed, or otherwise modified by */
            struct metadata_string trck;       /* Track number/Position in set */
            struct metadata_string tit1;       /* Content group description */
            struct metadata_string tit2;       /* Title/songname/content description */
            struct metadata_string tit3;       /* Subtitle/Description refinement */
            struct metadata_string tcon;       /* Content type */
        } frames[2];
        u8 version[2];                         /* ID3v2 version */
    } id3;

    struct {
        const char * codec_str[2];             /* detected codec as string */
        enum codec_type codec[2];              /* detected codec as enum value */
        struct {
            u32 bitrate;                       /* bitrate in bits per second */
            u16 sampling_rate;                 /* Sampling rate frequency index */
            u8 channel_mode:2;                 /* Channel mode */
            u8 version:2;                      /* MPEG Audio version ID */
            u8 copyright:1;                    /* Copyright*/
            u8 original:1;                     /* Original media */
        } audio[2];

    } mp3;

    struct {
        struct {
            enum pace_http_content_type type;   /* the container format which could be identified */
            char const * type_str;              /* detected type as string */
            u8 done;                            /* tracks the status of the http dissector - 0: still ongoing; 1: done */
        } content;
    } http;

    struct {

        struct {
            const char *codec_str;              /* detected codec as string */
            enum codec_type codec;              /* detected codec as enum value */
            u32 bitrate;                        /* bitrate of the video stream */
            u16 width;                          /* width of the video in pixels */
            u16 height;                         /* width of the video in pixels */
            u16 color_depth;                    /* color depth of the video in bit */
            struct {
                u8 numerator;
                u8 divisor;
            } aspect;                           /* aspect ratio, i.e 4:3 */
            u8 fps;                             /* calculated frames per second */
        } video[2];

        struct {
            const char *codec_str;              /* detected codec as string */
            enum codec_type codec;              /* detected codec as enum value */
            u32 sampling_rate;                  /* sampling rate of the audio stream */
            u32 bitrate;                        /* bitrate of the audio stream in bits per second */
            u16 channels;                       /* number of audio channels */
        } audio[2];

        u64 duration[2];                        /* the current duration of the stream in seconds */
        const char *stream_type_str[2];         /* detected stream type as string */
        enum stream_media_type type[2];         /* detected stream type as enum value */
    } mp4;
};

struct metadata_config {
    struct {
        u8 enabled;
    } ip;

    struct {
        u8 enabled;
    } tcp;

    struct {
        u8 enabled;
    } h264;

    struct {
        u8 enabled;
    } amr;

    struct {
        u8 enabled;
    } rtp;

    struct {
        u8 enabled;
    } id3;

    struct {
        u8 enabled;
    } mp3;

    struct {
        u8 enabled;
    } http;

    struct {
        u8 enabled;
    } mp4;
};

/**
 * This function initializes the metadata dissectors as configured.
 * It must be called directly after initializing the detection module and before
 * getting the flow memory size.
 *
 * Additional flow memory is used when enabled, the amount depending on the configured dissectors.
 *
 *
 * @param ipoque_struct the detection module
 * @param config pointer to configuration structure
 * @param pace_malloc function pointer to memory allocator
 * @param pace_free function pointer to memory free function
 * @return: METADATA_DISSECTOR_SUCCESS on success or an enum value indicating the error type
 *
 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
 */

#if IPOQUE_PACE_API_VARIANT == 2
enum metadata_status ipoque_init_metadata_dissectors(struct ipoque_detection_module_struct * const ipoque_struct,
                                                     const struct metadata_config * const config,
                                                     void *(*pace_malloc) (unsigned long size, void *userptr),
                                                     void (*pace_free) (void *ptr, void *userptr));
#else
enum metadata_status ipoque_init_metadata_dissectors(struct ipoque_detection_module_struct * const ipoque_struct,
                                                     const struct metadata_config * const config,
                                                     pace2_malloc pace_malloc,
                                                     pace2_free pace_free,
                                                     int thread_ID,
                                                     void *userptr);
#endif

/**
 * This function reset the given metadata dissector state.
 * It can be called anytime however not all dissectors allow a reset.
 *
 * @param ipoque_struct the detection module
 * @param flow pointer to the flow to reset metadata for
 * @param type metadata dissector id to reset
 * @return: METADATA_DISSECTOR_SUCCESS on success or an enum value indicating the error type
 *
 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
 */

enum metadata_status ipoque_reset_metadata_dissector(struct ipoque_detection_module_struct * const ipoque_struct,
                                                     void * const flow,
                                                     const enum metadata_type type);

/**
 * This function returns the current metadata dissector result.
 *
 * @param ipoque_struct the detection module
 * @param flow pointer to the flow to retrieve metadata for
 * @param type metadata dissector id to get
 * @return: pointer to result union on success or NULL incase of an error
 *
 * works with IPOQUE_PACE_DYNAMIC_UPGRADE
 */

const union metadata_result *ipoque_get_metadata(struct ipoque_detection_module_struct * const ipoque_struct,
                                                 void * const flow,
                                                 const enum metadata_type type);

#endif /* IPOQUE_PACE_API_VARIANT */

#endif
