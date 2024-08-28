/*
 * mutex.h
 *
 *  Created on: 21 Jan 2013
 *      Author: ericker
 */

#ifndef MUTEX_H_
#define MUTEX_H_
#include <pthread.h>

class MapMutex {
private:
    MapMutex();

public:
    void lockMapMutex();
    int trylockMapMutex();
    void unlockMapMutex();
    static MapMutex *getInstance();
};

class ClassifierMapMutex {
private:
    pthread_mutex_t classifier_map_mutex;

public:
    ClassifierMapMutex();
    void lockMapMutex();
    void unlockMapMutex();
};

#endif /* MUTEX_H_ */
