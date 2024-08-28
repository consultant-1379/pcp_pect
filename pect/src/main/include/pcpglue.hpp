/*
 * pcpglue.hpp
 *
 *  Created on: 21 Jan 2013
 *      Author: emilawl
 */

#ifndef PCPGLUE_HPP_
#define PCPGLUE_HPP_

#include <pthread.h>
#include "classify.h"

enum capture_from {
    CAPTURE_FILE,
    CAPTURE_LIVE
};
/*
 * THEORY OF OPERATION:
 * If  There are to be multiple Packet buffers [packet_buffer_num > 0] then we have only 1 queue for source and sink [queue = 1]
 * Alt: If there are multiple source and sinks [ queue > 1] then only one  packet buffer is to be used [packet_buffer_num = 0]
 * If we have multiple packet buffers defined, we use a 'one in one out' configuration per packet buffer and the packetBufferSinkCount value is ignored.
 */
struct packet_source_struct {
    pthread_mutex_t mutex;
    pthread_t thread;
    enum capture_from capture_type;
    const char *source_name;
    pcap_t *input;
    int queue; // queue for output: 0 = hash on UE-IP
    unsigned int packetBufferNum; // for multiple instances each using their own Packet Buffer;
    unsigned long bytes, packets, truncated;
    bool pbFull;
};

struct packet_sink_struct {
    pthread_mutex_t mutex;
    pthread_t thread;
    int queue; // queue for input
    classify_data cd;
    unsigned int packetBufferNum; // for multiple instances each using their own Packet Buffer;
    unsigned long bytes, packets, truncated;
};

typedef struct packet_source_struct *packet_source;
typedef struct packet_sink_struct *packet_sink;

void *start_source_sink(void *init);

void printInputQueueLogToBuffer(string *inputLogBuffer, int timeDurationInSeconds);
void printOutputQueueLogToBuffer(string *outputLogBuffer, int timeDurationInSeconds);
void printPacketBufferLogToBuffer(string *freePackets);
void printPacketLossStats();
void printQueueAndPacketBufferStatsToLog(string *inputBuffer, string *outputBuffer, string *freePacketsBuffer);
void printFragmentedStats();
void cleanupPacketLossStandAlone();

#endif /* PCPGLUE_HPP_ */
