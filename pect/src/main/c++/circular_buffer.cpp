/*
 * circular_buffer.cpp
 *
 *  Created on: 6 Sep 2013
 *      Author: ezhelao
 */
#include "circular_buffer.hpp"
#include <stdio.h>



packetpool_struct  *CircularBuffer::addToBufferStart() {
    pthread_mutex_lock(&bufferMutex);

    if(size > 3) {
        return (buffer + end);
    }

    pthread_mutex_unlock(&bufferMutex);
    return NULL;
}


void CircularBuffer::addToBufferEnd(packetpool_struct *element) {
    if(element != NULL) {
        end++;

        if(end >= CIRCULAR_BUFFER_SIZE) {
            end = 0;
            size--;
        }
    }

    pthread_mutex_unlock(&bufferMutex);
}

packetpool_struct  *CircularBuffer::getFromBufferStart() {
    pthread_mutex_lock(&bufferMutex);

    if(start != end) {
        return (buffer + start);
    }

    pthread_mutex_unlock(&bufferMutex);
    return NULL;
}


void  CircularBuffer::getFromBufferEnd(packetpool_struct *element) {
    if(element != NULL) {
        start++;

        if(start >= CIRCULAR_BUFFER_SIZE) {
            start = 0;
            size++;
        }
    }

    pthread_mutex_unlock(&bufferMutex);
}
