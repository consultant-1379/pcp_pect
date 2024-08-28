/*
 * circular_buffer.hpp
 *
 *  Created on: 6 Sep 2013
 *      Author: ezhelao
 */

#ifndef CIRCULAR_BUFFER_HPP_
#define CIRCULAR_BUFFER_HPP_



#include <pthread.h>
#include "packetbuffer.h"

#define CIRCULAR_BUFFER_SIZE 1000000
class CircularBuffer {
    packetpool_struct *buffer;
    int start, end;
    int size;
    pthread_mutex_t bufferMutex;
public:
    CircularBuffer() {
        pthread_mutex_init(&bufferMutex, NULL);
        buffer = new packetpool_struct[CIRCULAR_BUFFER_SIZE];
        start = 0;
        end = 0;
        size = 1000000;
    }


    packetpool_struct *addToBufferStart();

    void addToBufferEnd(packetpool_struct *element);


    packetpool_struct *getFromBufferStart();


    void getFromBufferEnd(packetpool_struct *element);


    ~CircularBuffer() {
        delete[] buffer;
    }


};


#endif /* CIRCULAR_BUFFER_HPP_ */


