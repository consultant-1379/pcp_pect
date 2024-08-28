/*
 * file_writer_map_manager.hpp
 *
 *  Created on: 21 Jan 2014
 *      Author: ericker
 */

#ifndef FILE_WRITER_MAP_MANAGER_HPP_
#define FILE_WRITER_MAP_MANAGER_HPP_

#include "file_writer_map.hpp"
#include <queue>
#include <stack>


#define MAX_CLASSIFIER_INSTANCES 20

class FileWriterMapManager {
private:
    FileWriterMap *fileWriterMaps[MAX_CLASSIFIER_INSTANCES]; // FileWriterMaps that are allocated to a classifier instance, indexed by instance number
    std::stack<FileWriterMap *> freeFileWriterMaps; // FileWriterMaps waiting to be allocated to a classifier instance
    std::queue<FileWriterMap *> consumerFileWriterMaps; // FileWriterMaps waiting to be consumed
    pthread_cond_t freeSemaphore, consumerSemaphore;
    pthread_mutex_t freeMutex, consumerMutex;
    static FileWriterMapManager *INSTANCE;

    FileWriterMapManager() : fileWriterMaps() {
        pthread_mutex_init(&freeMutex, NULL);
        pthread_mutex_init(&consumerMutex, NULL);
        pthread_cond_init(&freeSemaphore, NULL);
        pthread_cond_init(&consumerSemaphore, NULL);
        FileWriterMap *map;

        for(int i = 0; i < 2 * MAX_CLASSIFIER_INSTANCES; i++) { // 2* chosen so as to recover from 1 ROP of too slow file writing
            map = new FileWriterMap;
            freeFileWriterMaps.push(map);
        }
    }

public:
    FileWriterMap *getMap(int index);
    void freeMap(FileWriterMap *map);

    void produceMap(int index);
    FileWriterMap *consumeMap();
    static FileWriterMapManager *getInstance() {
        if(FileWriterMapManager::INSTANCE == NULL) {
            FileWriterMapManager::INSTANCE = new FileWriterMapManager;
        }

        return FileWriterMapManager::INSTANCE;
    }

    ~FileWriterMapManager() { // destructor
        LOG4CXX_INFO(loggerFileWriter, "Cleaning Free FileWriter Maps.");
        FileWriterMap *map;

        while(!freeFileWriterMaps.empty()) {
            map = freeFileWriterMaps.top();
            freeFileWriterMaps.pop();
            delete(map);
        }

        LOG4CXX_INFO(loggerFileWriter, "Cleaning Consumer FileWriter Maps.");

        while(!consumerFileWriterMaps.empty()) {
            map = consumerFileWriterMaps.front();
            consumerFileWriterMaps.pop();
            delete(map);
        }
    }
    //static u8 ipoqueHashForeachCallback(u8 *unique_buffer, u8 *user_buffer, u32 last_timestamp, void *user_data);
};


#endif /* FILE_WRITER_MAP_MANAGER_HPP_ */
