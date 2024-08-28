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

#include <pcap.h>

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include "config.h"

// Hacking in the ip stuff
#include <net/ethernet.h>
#include "classify.h"
// End of hack
#include "logger.hpp"
#define MAX_TIMES_PB_ALLOWED_BLOCKED 1

#ifndef TEST
# define OPTIMISE
#endif

#ifndef OPTIMISE
#define ASSERT(x)														\
{ 																		\
	if(!(x)) { 															\
		fprintf(stderr, "%s:%d ASSERT failed :-(\n", 					\
						__FILE__, __LINE__); 							\
		exit(255); 														\
	}																	\
}																		\
 
#else
#define ASSERT(x)	/* do nothing */
#endif


extern EArgs evaluatedArguments;
using namespace log4cxx;
unsigned int packetbuffer_free_threshold;
//with mutliplePacketbuffers == false packet buffer free does not reach it max size... FREE[99995/100000] . so use 0.9 
int packetbuffer_free_threshold2;
int loggerPrintPacketBuffer = 0;

/*
 * This creates a packetbuffer which supports a fixed number
 * of queues and packets
 *
 * NOTE queues is not the number of threads. It is the number of threads that use each packet buffer
 * If useMultiplePacketBuffers==true, then each packet buffer will have one queue.
 */
packetbuffer packetbuffer_start(int queues, int packets) {
    int thisFreePacketCount = packets;
    packetbuffer ret;
    int i;
    ASSERT(queues > 0 && packets > 0);
    ret = (packetbuffer) calloc(1, sizeof(struct packetbuffer_struct));
    packetbuffer_free_threshold2 = (int)((float) evaluatedArguments.packetBufferSize * 0.9);
    packetbuffer_free_threshold = (unsigned int)(float)(evaluatedArguments.packetBufferSize * 0.5);
    LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_free_threshold = " << packetbuffer_free_threshold << ": packetbuffer_free_threshold2 = " << packetbuffer_free_threshold2);
    
    if(ret) {
        ret->freePacketCount = thisFreePacketCount;
        ret->queue_count = queues; // see note above
        ret->packet_count = packets;
        ret->packetqueues = (packetqueue_struct *) calloc(ret->queue_count,
                            sizeof(struct packetqueue_struct));

        if(!ret->packetqueues) {
            free(ret);
            return (0);
        }

        ret->packetpool = (packetpool_struct *) calloc(ret->packet_count,
                          sizeof(struct packetpool_struct));

        if(!ret->packetpool) {
            free(ret->packetqueues);
            free(ret);
            return (0);
        }

        /* add all the new packets to the free packet queue */
        ret->free = 1;

        for(i = 0; i < ret->packet_count; i++) {
            ret->packetpool[i].next = (int *) calloc(ret->queue_count + 1,
                                      sizeof(int));

            if(!ret->packetpool[i].next) {
                while(i > 0) {
                    free(ret->packetpool[--i].next);
                }

                free(ret->packetpool);
                free(ret->packetqueues);
                free(ret);
                return (0);
            }

            if(i < ret->packet_count - 1) {
                ret->packetpool[i].next[0] = i + 2;
            }
        }

        for(i = 0; i < ret->queue_count; i++) {
            pthread_cond_init(&(ret->packetqueues[i].queue_semaphore), 0);
        }
    }

    ret->blockedROPCount = 0;
    ret->droppedPacketCount = 0;
    ret->printOnce = 0;
    ret->cumulativeBlockedROPCount = 0;
    ret->cumulativeDroppedPacketCount = 0;

    if(loggerPcpGluePacketBuffer->isDebugEnabled()) {
        loggerPrintPacketBuffer = 1;
    } else {
        loggerPrintPacketBuffer = 0;
    }

    pthread_cond_init(&(ret->free_semaphore), 0);
    pthread_cond_signal(&(ret->free_semaphore)); // free packets available
    pthread_mutex_init(&(ret->packet_mutex), 0);
    return (ret);
}
/*
 * Reset the packet buffer when full [blocked]
 *
 * NOTE queue is not the number of the classify thread (theis is pktBufferNum). It is the number of  the thread that is curenttly using this packet buffer
 * If only using one packet buffer and many threads then this queue number will be the greater then one
 * If useMultiplePacketBuffers==true, then each packet buffer will have one queue.
 *
 * NOTE: This is not working quite right.
 * if classify is processing a packet when we decide to reset the buffer, then when classify releasea the packet it will run packetbuffer_release which will effectively
 * reduce the size of the packet bufffer to what ever packet number was being procedded at that time
 * and pb-free for the packet being processed by classify will be put pointing to packet #1
 * A flag would need to be added to indicate that a reset occured and that packetbuffer_release and packetbuffer_queue do not need to be run that one time.
 */
void packetbuffer_reset(packetbuffer pb, int pktBufferNum, int queue, unsigned int maxPackets) {
    struct packetqueue_struct *q;
    unsigned int thisFreePacketCount = maxPackets;
    int i;
    char buf[500];
    ASSERT(pb);
    ASSERT(queue > 0 && maxPackets > 0);

    if(pb) {
        q = &(pb->packetqueues[queue - 1]); //i.e  pb->packetqueues[0] as queue ==1 for useMultiplePacketBuffers==true
        pthread_mutex_lock(&(pb->packet_mutex));

        // conditions for Blockage,  free need to be zero
        if(pb->free > 0) {
            // pkt Buffer  has freed up a bit... exit
            LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_reset [" << pktBufferNum << "] EXIT at Free check; Number of FREE packets in the packet buffer is " << pb->freePacketCount);
            pthread_mutex_unlock(&(pb->packet_mutex));
        }

        LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_reset [" << pktBufferNum << "] is BLOCKED; Number of FREE packets in the packet buffer is " << pb->freePacketCount);
        snprintf(buf, sizeof(buf),  ": pb->free = %d : q->last = %d : q->first = %d: maxPackets = %d : # of the queue using this PB = %d  ", pb->free, q->last, q->first, maxPackets, queue);
        LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_reset[" << pktBufferNum << "] is BLOCKED;  pb->freePacketCount = " << (int)  pb->freePacketCount << buf);
        pb->freePacketCount = thisFreePacketCount;
        /* add all the new packets to the free packet queue */
        pb->free = 1;

        for(i = 0; i < pb->packet_count; i++) {
            pb->packetpool[i].next[queue] = 0; //matching calloc ~queue_count + 1 in packetbuffer_start function ; useMultiplePacketBuffers==true queue =1;
            pb->packetpool[i].number_of_queues = 0;

            if(i < pb->packet_count - 1) {
                pb->packetpool[i].next[0] = i + 2;
            }
        }

        q->last = 0;
        q->first = 0;
        pb->blockedROPCount = 0;
        pb->droppedPacketCount = 0;
        pb->printOnce = 0;
        pb->cumulativeBlockedROPCount = 0;
        pb->cumulativeDroppedPacketCount = 0;
        LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_reset [" << pktBufferNum << "] is FREED; Number of FREE packets in the packet buffer is " << pb->freePacketCount);
        snprintf(buf, sizeof(buf),  ": pb->free = %d : q->last = %d : q->first = %d: maxPackets = %d : # of the queue using this PB = %d  ", pb->free, q->last, q->first, maxPackets, queue);
        LOG4CXX_INFO(loggerPcpGlue, "PACKETBUFFER packetbuffer_reset [" << pktBufferNum << "] is FREED;  pb->freePacketCount = " << (int)  pb->freePacketCount << buf);
        pthread_mutex_unlock(&(pb->packet_mutex));
    }
}
/*
 * This deletes a pre-existing packetbuffer and frees
 * all the associated storage
 */
void packetbuffer_end(packetbuffer pb) {
    int i;
    ASSERT(pb);
    pthread_mutex_lock(&(pb->packet_mutex));
    free(pb->packetqueues);

    for(i = 0; i < pb->packet_count - 1; i++) {
        free(pb->packetpool[i].next);
        pb->packetpool[i].next = 0;
    }

    for(i = 0; i < pb->queue_count; i++) {
        pthread_cond_destroy(&(pb->packetqueues[i].queue_semaphore));
    }

    pthread_cond_destroy(&(pb->free_semaphore));
    pthread_mutex_destroy(&(pb->packet_mutex));
    free(pb->packetpool);
    free(pb);
}
/*
 * This grabs a free packetbuffer
 */
int packetbuffer_grab_free(packetbuffer pb) {
    int ret;
    struct packetpool_struct *pkt;
    ASSERT(pb);
    pthread_mutex_lock(&(pb->packet_mutex));

    while(!pb->free) {
        pthread_mutex_unlock(&(pb->packet_mutex));
        return -1;
    }

    ret = pb->free;
    pkt = &(pb->packetpool[ret - 1]);
    pb->free = pkt->next[0];
    pkt->next[0] = 0;
    pkt->number_of_queues = 1;
    pb->freePacketCount--;
    pthread_mutex_unlock(&(pb->packet_mutex));
    return (ret);
}
/*
 * This grabs a free packetbuffer
 */
int packetbuffer_grab_free(packetbuffer pb, int pktBufNum, int queueNum, unsigned int pktBufferSize, int Max_Allowed) {
    int ret;
    //char buf[500];
    struct packetpool_struct *pkt;
    ASSERT(pb);
    pthread_mutex_lock(&(pb->packet_mutex));

    while(!pb->free) {
        if(pb->blockedROPCount >= Max_Allowed) {
            packetbuffer_reset(pb, pktBufNum, queueNum, pktBufferSize);
            pb->blockedROPCount = 0;
        }

        pthread_mutex_unlock(&(pb->packet_mutex));
        return -1;
    }

    ret = pb->free;
    pkt = &(pb->packetpool[ret - 1]);
    pb->free = pkt->next[0];
    pkt->next[0] = 0;
    pkt->number_of_queues = 1;
    pb->freePacketCount--;
    pthread_mutex_unlock(&(pb->packet_mutex));
    return (ret);
}

/*
 * This releases the interest in a packet.  If the packet is queued
 * on other queues it stays on the queues, if not it returns to the
 * free pool.
 */

void packetbuffer_release(packetbuffer pb, int packet) {
    ASSERT(pb && packet > 0 && packet <= pb->packet_count);
    pthread_mutex_lock(&(pb->packet_mutex));

    if(--(pb->packetpool[packet - 1].number_of_queues) <= 0) {
        if(!pb->free) {
            pthread_cond_signal(&(pb->free_semaphore));
        }

        pb->packetpool[packet - 1].number_of_queues = 0;
        pb->packetpool[packet - 1].next[0] = pb->free;
        pb->free = packet;
        pb->freePacketCount++;
    }

    pthread_mutex_unlock(&(pb->packet_mutex));
}



void packetbuffer_queue(packetbuffer pb, int queue, int packet) {
    struct packetqueue_struct *q;
    struct packetpool_struct *pkt;
    int last;
    ASSERT(pb);
    ASSERT(queue > 0 && queue <= pb->queue_count);
    ASSERT(packet > 0 && packet <= pb->packet_count);
    pthread_mutex_lock(&(pb->packet_mutex));
    pkt = &(pb->packetpool[packet - 1]);
    q = &(pb->packetqueues[queue - 1]);
    last = q->last;

    if(!last) {
        q->first = packet;
        pthread_cond_signal(&(q->queue_semaphore));
    } else {
        pb->packetpool[last - 1].next[queue] = packet;
    }

    q->last = packet;
    pkt->number_of_queues++;
    pkt->next[queue] = 0;
    pthread_mutex_unlock(&(pb->packet_mutex));
}

/*
 * Get the next packet off the queue.
 * If wait is zero and there are no packets on the queue it returns
 * zero.  If the wait is nonzero then it waits until a packet is
 * available on the queue, and returns that.
 */
int packetbuffer_grab_next(packetbuffer pb, int queue, int wait) {
    struct packetqueue_struct *q;
    struct packetpool_struct *pkt;
    int ret;
    ASSERT(pb);
    ASSERT(queue > 0 && queue <= pb->queue_count);
    pthread_mutex_lock(&(pb->packet_mutex));
    q = &(pb->packetqueues[queue - 1]);

    while(!q->first) {
        if(!wait) {
            return (0);
        }

        pthread_mutex_unlock(&(pb->packet_mutex));
        return -1;
    }

    ret = q->first;
    pkt = &(pb->packetpool[ret - 1]);
    q->first = pkt->next[queue];

    if(!q->first) {
        q->last = 0;
    }

    pthread_mutex_unlock(&(pb->packet_mutex));
    return (ret);
}

/*
 * Returns a pointer to the header information for the packet
 */
struct PectPacketHeader *packetbuffer_header(packetbuffer pb, int packet) {
    ASSERT(pb);
    ASSERT(packet > 0 && packet <= pb->packet_count);
    return (&(pb->packetpool[packet - 1].header));
}

/*
 * Returns a pointer to the data buffer for the packet
 */
unsigned char *packetbuffer_data(packetbuffer pb, int packet) {
    ASSERT(pb);
    ASSERT(packet > 0 && packet <= pb->packet_count);
    return (pb->packetpool[packet - 1].data);
}

ostream &operator<<(ostream &os, const packetbuffer_struct *pb_t) {
    os << "[" << pb_t->freePacketCount << "/" << pb_t->packet_count << "]";
    return os;
}

/**
 * function checks @ rop boundary if packet buffer is blocked
 * Conditions for Blockage, both  free and freePacketCount need to be zero
 */
void checkIfBlockedROPCount(packetbuffer_struct *pb_t, int pktBufNum) {
    if(pb_t->blockedROPCount == 0) { // not currently blocked
        pthread_mutex_lock(&(pb_t->packet_mutex));

        if((!pb_t->free) && (!pb_t->freePacketCount)) {
            if(loggerPrintPacketBuffer) {
                LOG4CXX_DEBUG(loggerPcpGluePacketBuffer, "PACKETBUFFER [" << pktBufNum << "]: BLOCKAGE ROP START: Number Free Packets in Buffer = " << (int) pb_t->freePacketCount << " (pb_t->free = " << pb_t->free << ")");
            }

            pb_t->blockedROPCount++;
        }

        pthread_mutex_unlock(&(pb_t->packet_mutex));
    } else {
        pthread_mutex_lock(&(pb_t->packet_mutex));

        if(loggerPrintPacketBuffer) {
            LOG4CXX_DEBUG(loggerPcpGluePacketBuffer, "PACKETBUFFER [" << pktBufNum << "]: BLOCKAGE ROP INCREMENTED: Number Free Packets in Buffer = " << (int) pb_t->freePacketCount << " (pb_t->free = " << pb_t->free << ")");
        }

        pb_t->blockedROPCount++;
        pthread_mutex_unlock(&(pb_t->packet_mutex));
    }
}

/**
 * function checks if number of free packets in the PB is at its max again
 */
int checkIfStillBlocked(packetbuffer_struct *pb, int pktBufferNum) {
    pthread_mutex_lock(&(pb->packet_mutex));
                          
    //with mutliplePacketbuffers == false packet buffer free does not reach it max size... FREE[99995/100000] . so use 0.9 
    if((pb->freePacketCount >= packetbuffer_free_threshold2) && (pb->free > 0))  {
        pb->cumulativeDroppedPacketCount += pb->droppedPacketCount;

        if(loggerPrintPacketBuffer) {
            LOG4CXX_DEBUG(loggerPcpGluePacketBuffer, "PACKETBUFFER [" << pktBufferNum << "]: FREED"
                          << ": pb->blockedROPCount = " << pb->blockedROPCount
                          << ": # Free Packets in Buffer = " << pb->freePacketCount
                          << " (pb->free = " << pb->free << ")"
                          << ": pb->droppedPacketCount = " << pb->droppedPacketCount
                          << ": pb->cumulativeDroppedPacketCount = " << pb->cumulativeDroppedPacketCount
                          << ": packetbuffer_free_threshold2 = " << packetbuffer_free_threshold2
                          << ": evaluatedArguments.packetBufferSize = " << evaluatedArguments.packetBufferSize);
        }

        pb->printOnce = 0;
        pb->droppedPacketCount = 0;
        pthread_mutex_unlock(&(pb->packet_mutex));
        return 1;
    }

    pthread_mutex_unlock(&(pb->packet_mutex));
    return 0;
}

/**
 * This Function takes chects if the packet buffer is full. If so it drops the packet
 * IF packet buffer is full (pool_packet = -1), and has been for a while (pb->blockedROPCount >= (int) MAX_TIMES_PB_ALLOWED_BLOCKE)
 * drop this and all packets until either :
 * packet buffer is fully free again
 * or
 * we have dropped a buffer full of packets (pb->droppedPacketCount >= evaluatedArguments.packetBufferSize)
 */
int checkIfPacketBufferBlocked(packetbuffer pb, int pktBufferNum, int pool_packet) {
    if(((pb->blockedROPCount >= (int) MAX_TIMES_PB_ALLOWED_BLOCKED)  && (pool_packet < 0)) ||
            ((pb->blockedROPCount >= (int) MAX_TIMES_PB_ALLOWED_BLOCKED)  && (pb->droppedPacketCount > 0))) {
        if(!(checkIfStillBlocked(pb, pktBufferNum))) {
            pthread_mutex_lock(&(pb->packet_mutex));
            pb->droppedPacketCount++;

            if(!pb->printOnce) {
                if(loggerPrintPacketBuffer) {
                    LOG4CXX_DEBUG(loggerPcpGluePacketBuffer, "PACKETBUFFER [" << pktBufferNum << "]: BLOCKED"
                                  << ": pb->blockedROPCount = " << pb->blockedROPCount
                                  << ": # Packets in Buffer = " << pb->freePacketCount
                                  << " (pb->free = " << pb->free << ")"
                                  << ": pb->droppedPacketCount = " << pb->droppedPacketCount
                                  << ": pb->cumulativeDroppedPacketCount = " << pb->cumulativeDroppedPacketCount
                                  << ": evaluatedArguments.packetBufferSize = " << evaluatedArguments.packetBufferSize);
                }

                pb->printOnce = 1;
            }

            pthread_mutex_unlock(&(pb->packet_mutex));
            return 1; // drop packet until it packet buffer is FREE
        }
    }

    return 0;
}


/**
 * function checks @ rop boundary if packet buffer is still blocked
 * Conditions for UN BLOCK, free pointing to a packet slot and freePacketCount is greater than packetbuffer_free_threshold
 */
void resetBlockedROPCount(packetbuffer_struct *pb, int pktBufferNum) {
    if((pb->blockedROPCount > 0) && (pb->cumulativeDroppedPacketCount > 0)) {  // stop it resetting just after starting
        if(pb->droppedPacketCount == 0) { // not currently in a blocked but not freed state
            if((pb->free > 0) && (pb->freePacketCount > (int) packetbuffer_free_threshold)) {
                pthread_mutex_lock(&(pb->packet_mutex));
                pb->cumulativeBlockedROPCount += pb->blockedROPCount;

                if(loggerPrintPacketBuffer) {
                    LOG4CXX_DEBUG(loggerPcpGluePacketBuffer, "PACKETBUFFER [" << pktBufferNum << "]: BLOCKAGE ROP STOP"
                                  << ": pb->blockedROPCount = " << pb->blockedROPCount
                                  << ": pb->cumulativeBlockedROPCount = " << pb->cumulativeBlockedROPCount
                                  << ": # Packets in Buffer = " << pb->freePacketCount
                                  << " (pb->free = " << pb->free << ")"
                                  << ": pb->droppedPacketCount = " << pb->droppedPacketCount
                                  << ": pb->cumulativeDroppedPacketCount = " << pb->cumulativeDroppedPacketCount
                                  << ": evaluatedArguments.packetBufferSize = " << evaluatedArguments.packetBufferSize);
                }

                pb->blockedROPCount = 0; // resume putting packets into PB
                pb->printOnce = 0;
                pb->cumulativeDroppedPacketCount = 0;
                pthread_mutex_unlock(&(pb->packet_mutex));
            }
        }
    }
}
/*
 * Print out the running totals of the stats.  Since there is no
 * mutex, there may occasionally be strange values.
// */
//void packetBufferPrintLog() {
//    LOG4CXX_INFO(loggerPCPGlue, "The total number of active flows is: " << flow_data::getInstanceCounter());
//
//    // if not using multiple packet buffers, then packet_pool used is 1.
//    //  packet_pool[0] is for future use of hash on UEIP
//    if (evaluatedArguments.useMultiplePacketBuffers) {
//        for (int i = 1; i <= config_source_count; i++) {
//            LOG4CXX_INFO(loggerPCPGlue, "A Snapshot in time of the number of free packets in packetbuffer "<< i << " is " << packet_pool[i]->freePacketCount);
//        }
//    }
//    else {
//        LOG4CXX_INFO(loggerPCPGlue, "A Snapshot in time of the number of free packets in packetbuffer "<< 1 << " is " << packet_pool[1]->freePacketCount);
//
//    }
//}

#if defined(TEST)
#include <string.h>

/* Although this function will work outside the test environment,
 * don't call it, because it will take a long time.
 * You don't need to know the sizes of the queues or the free
 * packets in the pool, except for testing.
 *
 * And there is no mutex.  So ... just don't do it.
 */
static int packet_queue_count(packetbuffer pb, int queue) {
    ASSERT(pb);
    ASSERT(queue >= 0 && queue <= pb->queue_count);
    int ret = 0, packet;

    if(queue == 0) {
        /* count free packets */
        for(packet = pb->free;
                packet;
                packet = pb->packetpool[packet - 1].next[queue]) {
            ret++;
        }
    } else {
        /* count packets in queue */
        for(packet = pb->packetqueues[queue - 1].first;
                packet;
                packet = pb->packetpool[packet - 1].next[queue]) {
            ret++;
        }
    }

    return(ret);
}

int main(void) {
    /*
     * Random bit of Victorian poetry serves as our "packets".
     * James Kenneth Stephen was an Eton scholar and athlete, tutor to
     * the grandson of Queen Victoria and, according to some conspiracy
     * theories, a Jack the Ripper suspect.
     *
     * Rudyard Kipling wrote "The Jungle Book", and Henry Rider
     * Haggard's character, Allan Quatermain, has recently returned
     * to fame as one of the characters in Alan Moore's "League of
     * Extraordinary Gentlemen", and, according to Spielberg, served
     * as a prototype for Indiana Jones.
     */
    char *packets[] = {
        "WILL there never come a season",
        "Which shall rid us from the curse",
        "Of a prose which knows no reason",
        "And an unmelodious verse:",
        "When the world shall cease to wonder",
        "At the genius of an ass,",
        "And a boy's eccentric blunder",
        "Shall not bring success to pass:",
        " ",
        "When mankind shall be delivered",
        "From the clash of magazines,",
        "And the inkstand shall be shivered",
        "Into countless smithereens:",
        "When there stands a muzzled stripling,",
        "Mute, beside a muzzled bore:",
        "When the Rudyards cease from kipling",
        "And the Haggards ride no more.	",
        "		\"To R.K\", James Kenneth Stephen"
    };
    packetbuffer pb;
    int i;
    pb = packetbuffer_start(3, 1000000);

    if(!pb) {
        fprintf(stderr, "Cannot allocate packet buffer\n");
        return(1);
    }

    printf("%d:%d:%d:%d\n",
           packet_queue_count(pb, 1),
           packet_queue_count(pb, 2),
           packet_queue_count(pb, 3),
           packet_queue_count(pb, 0));

    for(i = 0; i < sizeof(packets) / sizeof(char *); i++) {
        int pool_packet, len;
        struct pcap_pkthdr *header;
        char *data;
        pool_packet = packetbuffer_grab_free(pb);

        if(pool_packet) {
            len = strlen(packets[i]);
            header = packetbuffer_header(pb, pool_packet);
            data = (char *) packetbuffer_data(pb, pool_packet);
            memcpy(data, packets[i], strlen(packets[i]));
            header->caplen = len;
            header->len = len;
            gettimeofday(&(header->ts), 0);
            packetbuffer_queue(pb, 1, pool_packet);

            if(i < sizeof(packets) / (2 * sizeof(char *))) {
                packetbuffer_queue(pb, 2, pool_packet);
            } else {
                packetbuffer_queue(pb, 3, pool_packet);
            }

            packetbuffer_release(pb, pool_packet);
            printf("%d:%d:%d:%d\n",
                   packet_queue_count(pb, 1),
                   packet_queue_count(pb, 2),
                   packet_queue_count(pb, 3),
                   packet_queue_count(pb, 0));
        }
    }

    printf("%d:%d:%d:%d\n",
           packet_queue_count(pb, 1),
           packet_queue_count(pb, 2),
           packet_queue_count(pb, 3),
           packet_queue_count(pb, 0));

    for(i = 1; i <= 3; i++) {
        int pool_packet;

        do {
            pool_packet = packetbuffer_grab_next(pb, i, 0);

            if(pool_packet) {
                struct pcap_pkthdr *header;
                char *data;
                header = packetbuffer_header(pb, pool_packet);
                data = (char *) packetbuffer_data(pb, pool_packet);
                printf("Queue %d: %d:%06d \t\"%s\" (length %d of %d)\n",
                       i,
                       header->ts.tv_sec, header->ts.tv_usec,
                       data,
                       header->caplen,
                       header->len);
                packetbuffer_release(pb, pool_packet);
                printf("%d:%d:%d:%d\n",
                       packet_queue_count(pb, 1),
                       packet_queue_count(pb, 2),
                       packet_queue_count(pb, 3),
                       packet_queue_count(pb, 0));
            }
        } while(pool_packet);
    }

    printf("%d:%d:%d:%d\n",
           packet_queue_count(pb, 1),
           packet_queue_count(pb, 2),
           packet_queue_count(pb, 3),
           packet_queue_count(pb, 0));
    packetbuffer_end(pb);
    return(0);
}
#endif

