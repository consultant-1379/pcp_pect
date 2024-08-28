/*
 * license_controler.hpp
 *
 *  Created on: 5 Jun 2013
 *      Author: ezhelao
 */

#ifndef LICENSE_CONTROLER_HPP_
#define LICENSE_CONTROLER_HPP_

#include "gtpv1_utils.h"
#include "MagicStringTester.h"

#include <fstream>
#include <pthread.h>
#include <vector>

using namespace std;

extern EArgs evaluatedArguments;

class LicenseController {

private:
    pthread_t thread;
    MagicStringTester licenseTester;
    pthread_attr_t pthread_attr;
    static void *run(void *init);
    LicenseController();
    static void printJavaCheckLicenseMsg(int returnedValue);
    bool closed;
    vector<pthread_t> threads;
    static LicenseController *licenseController;
    static bool isMagicStringValid(char input[], int inputSize);
public:
    static void terminateApplication();
    static LicenseController *getLicenseController();
    void start();
    void addThreadToController(pthread_t &thread);
    static int checkLicense();

    ~LicenseController() {}
};

#endif /* LICENSE_CONTROLER_HPP_ */
