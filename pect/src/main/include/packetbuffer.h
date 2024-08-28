/************************************************************************
* COPYRIGHT (C) Ericsson 2012                                           *
* The copyright to the computer program(s) herein is the property       *
* of Telefonaktiebolaget LM Ericsson.                                   *
* The program(s) may be used and/or copied only with the written        *
* permission from Telefonaktiebolaget LM Ericsson or in accordance with *
* the terms and conditions stipulated in the agreement/contract         *
* under which the program(s) have been supplied.                        *
*************************************************************************
*************************************************************************
* File: packetbuffer.h
* Date: Oct 8, 2012
* Author: LMI/LXR/PE Simon Richardson
************************************************************************/

/**********************************************************************
 * This is headers for a packet buffer pool.  It creates the pool,
 * assigns the buffers to one of a number of output queues, and the
 * frees them in turn.
 * It is controlled by mutexes to make it thread-safe.
 **********************************************************************/

#ifndef PACKETBUFFER_H_
#define PACKETBUFFER_H_

#include <iostream>
#include <sys/types.h>
#include <pcap.h>
#include "packet_utils.h"
#include "GTPv1_packetFields.h"

/* enough for an Ethernet frame and a bit more */
#define PACKET_MAX_BYTES	1600
#define MAX_NUM_OF_PACKET_BUFFERS     20

typedef struct packetbuffer_struct *packetbuffer;


/*
 * 4 tuple of ip
 * all in host byte order
 */
struct PectIP4Tuple {
    u_int32_t ueIP;
    u_int32_t serverIP;
    u_int16_t uePort;
    u_int16_t serverPort;

};

/**
 * Customised packet header to hold more information.
 */
struct PectPacketHeader {
    struct pcap_pkthdr pcapHeader;
    PectIP4Tuple fourTuple;
    PacketDirection_t packetDirection;
    bool isTcpPacket;
    iphdr *userPacketIPHeader;
    unsigned int userPacketSize;
    unsigned int userPacketOffset;
    unsigned int userHeaderSize;
    unsigned int userTotalLength;
    struct FTEID teid_d;
    unsigned short windowsSize;
    bool cooked;
    int dlink;
    unsigned long long packetTime_uS;
    uint16_t ip1_fragmented;
    uint16_t ip2_fragmented;
    uint16_t ip2_fragmented_dropped;
    uint16_t udp1_srcPort;
    uint16_t udp1_dstPort;

};



struct packetqueue_struct {
    int first, last;
    pthread_cond_t queue_semaphore;
};

struct packetpool_struct {
    unsigned char data[PACKET_MAX_BYTES];
    struct PectPacketHeader header;
    int number_of_queues;
    int *next;
};


struct packetbuffer_struct {
    int queue_count;
    int packet_count;
    struct packetqueue_struct *packetqueues;
    struct packetpool_struct *packetpool;
    int free;
    pthread_cond_t free_semaphore;
    pthread_mutex_t packet_mutex;
    int freePacketCount;
    int blockedROPCount;
    unsigned int droppedPacketCount;
    unsigned int cumulativeDroppedPacketCount;
    unsigned int cumulativeBlockedROPCount;
    int printOnce;
};


/*
 * Initializes a packet buffer with the supplied number of queues and packets
 *
 */
packetbuffer packetbuffer_start(int queues, int packets);

/*
 * Deletes a pre-existing packetbuffer and frees all the associated storage
 */
void packetbuffer_end(packetbuffer pb);

/*
 * Grabs the index of the next free packet
 *
 * @param pb The packetbuffer to get a free packet from
 *
 * @return The index of the next free packet
 */
int packetbuffer_grab_free(packetbuffer pb);
int packetbuffer_grab_free(packetbuffer pb, int pktBufNum, int queueNum, unsigned int pktBufferSize, int Max_Allowed);

/*
 * Adds the given packet to an output queue
 *
 * @param pb The packetbuffer to use
 * @param queue The index of the queue to add the packet to
 * @param packet The index of the packet to add
 */
void packetbuffer_queue(packetbuffer pb, int queue, int packet);

/*
 * Gets the index of the next packet in the given queue
 *
 * @param pb The packetbuffer to use
 * @param queue The index of the queue to access
 * @param wait Non-zero indicates that the method should wait for a free packet if there is none
 *
 * @return The index of the next packet.  A value of 0 indicates that no packet could be obtained
 */
int packetbuffer_grab_next(packetbuffer pb, int queue, int wait);

/*
 * Releases the given packet, once the packet has been released from all queues
 * the packet is reinserted into the free queue for reuse
 *
 * @param pb The packet buffer in which the packet belongs
 * @param packet The index of the packet in question
 */
void packetbuffer_release(packetbuffer pb, int packet);

/*
 * Returns a pointer to the header information for the packet at the given index
 *
 * @param pb The packet buffer which contains the desired packet
 * @param packet The index of the packet to get the header information
 *
 * @return The pcap packet header structure of the given packet
 */
struct PectPacketHeader *packetbuffer_header(packetbuffer pb, int packet);

/*
 * Returns a pointer to the data for the packet at the given index
 *
 * @param pb The packet buffer which contains the desired packet
 * @param packet The index of the packet to get the data from
 *
 * @return A char array containing the packet's data
 */
unsigned char *packetbuffer_data(packetbuffer pb, int packet);

std::ostream &operator<<(std::ostream &os, const packetbuffer_struct *pb_t);


/*
 * increments the number of times the packet buffer was blocked when checked
 * PUTS packet buffer into ROP BLOCKED started.
 *
 * @param pktBufferNum The index of the thread that is running
 * @param pb The packet buffer which contains the desired packet
 *
 * @return void
 */
void checkIfBlockedROPCount(packetbuffer_struct *pb_t, int pktBufNum);

/*
 * reset the packet buffet to it initial state. If there are unread packets, the are lost
 *
 * @param pb The packet buffer which contains the desired packet
 * @param pktBufferNum The index of the thread that is running
 * @queue is the queue to access. If useMultiplePacketBuffers==ture, queue=1.
 * @maxPackets is the PB size
 *
 * @return void
 */

void packetbuffer_reset(packetbuffer pb, int pktBufferNum, int queue, int maxPackets);
/*
 * Check if the packet buffer is full and returns 1 if the packet was dropped and 0 if it was not
 *
 * @param pb pointer to the packet buffer which contains the desired packet
 * @param pktBufferNum The index of the thread that is running
 * @pool_packet is result of the packetbuffer_grab_free call
 *
 * @return 1 if the packet was dropped and 0 if it was not
 */
int checkIfPacketBufferBlocked(packetbuffer pb, int pktBufferNum, int pool_packet);

/*
 * Checkis if the PB can be put into the ROP FREED  state from the ROP BLOCKED state
 *
 * @param pb pointer to the packet buffer which contains the desired packet
 * @param pktBufferNum The index of the thread that is running
 *
 * @return void
 */
void resetBlockedROPCount(packetbuffer_struct *pb, int pktBufferNum);

#endif /* PACKETBUFFER_H_ */
