/*
 * Producer/Consumer management for the data transfer between the classification engine and the file writer
 * components.
 *
 * file_writer_map_manager.cc
 *
 *  Created on: 21 Jan 2014
 *      Author: ericker
 */

#include <stddef.h>
#include "file_writer_map.hpp"
#include "file_writer_map_manager.hpp"

/**
 * Gets a FileWriterMap instance, to be used by the classify engine to transfer data to the
 * file writer module.  This method will block if it happens there are no 'free' maps available in the cache.
 */
FileWriterMap *FileWriterMapManager::getMap(int index) {
    FileWriterMap *map;
    pthread_mutex_lock(&freeMutex);

    // fileWriterMaps[index] != NULL can be null  if thisis a new thread @ startup or if the Map is blocked during printing @ file writer.
    if(fileWriterMaps[index] != NULL) {
        map = fileWriterMaps[index];  // this classsifier thread already has a map associated with it. Re-allocate it the same map
    } else { // no map allocated to this thread. Wait for a map to in the freeFWMaps &  Allocate a new map
        while(freeFileWriterMaps.size() == 0) {
            pthread_cond_wait(&freeSemaphore, &freeMutex);
        }

        map = freeFileWriterMaps.top();
        freeFileWriterMaps.pop();
        fileWriterMaps[index] = map;
    }

    pthread_mutex_unlock(&freeMutex);
    return map;
}

/**
 * Releases a FileWriterMap back into the pool.  Clears all content from the map before continuing.
 */
void FileWriterMapManager::freeMap(FileWriterMap *map) {
    map->getFileWriterFlowMap().clear();
    pthread_mutex_lock(&freeMutex);
    freeFileWriterMaps.push(map);
    pthread_cond_signal(&freeSemaphore);
    pthread_mutex_unlock(&freeMutex);
}

void FileWriterMapManager::produceMap(int index) {
    FileWriterMap *map;
    pthread_mutex_lock(&freeMutex);
    map = fileWriterMaps[index];
    fileWriterMaps[index] = NULL;
    pthread_mutex_unlock(&freeMutex);
    pthread_mutex_lock(&consumerMutex);
    consumerFileWriterMaps.push(map);
    pthread_cond_broadcast(&consumerSemaphore);
    pthread_mutex_unlock(&consumerMutex);
}

FileWriterMap *FileWriterMapManager::consumeMap() {
    FileWriterMap *map;
    pthread_mutex_lock(&consumerMutex);

    while(consumerFileWriterMaps.size() == 0) {
        pthread_cond_wait(&consumerSemaphore, &consumerMutex);
    }

    map = consumerFileWriterMaps.front();
    consumerFileWriterMaps.pop();
    pthread_mutex_unlock(&consumerMutex);
    return map;
}

FileWriterMapManager *FileWriterMapManager::INSTANCE = NULL;
