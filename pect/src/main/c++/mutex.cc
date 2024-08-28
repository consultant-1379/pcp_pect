/*
 * mutex.cc
 *
 *  Created on: 21 Jan 2013
 *      Author: ericker
 */

#include "mutex.hpp"
#include <pthread.h>

//mutex lock for the GTPC
pthread_mutex_t map_mutex;


void MapMutex::lockMapMutex() {
    //pthread_mutex_lock(&map_mutex);
}

int MapMutex::trylockMapMutex() {
    return  0; //pthread_mutex_trylock(&map_mutex);
}

void MapMutex::unlockMapMutex() {
    //pthread_mutex_unlock(&map_mutex);
}

MapMutex::MapMutex() {
    pthread_mutex_init(&map_mutex, 0);
}

static MapMutex *instance;
static bool instanceFlag;

MapMutex *MapMutex::getInstance() {
    if(instanceFlag == false) {
        instanceFlag = true;
        instance = new MapMutex();
    }

    return instance;
}


void ClassifierMapMutex::lockMapMutex() {
    pthread_mutex_lock(&classifier_map_mutex);
}

void ClassifierMapMutex::unlockMapMutex() {
    pthread_mutex_unlock(&classifier_map_mutex);
}

ClassifierMapMutex::ClassifierMapMutex() {
    pthread_mutex_init(&classifier_map_mutex, 0);
}





