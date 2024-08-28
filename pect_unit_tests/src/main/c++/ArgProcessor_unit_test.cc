/*
 * ArgProcessor_unit_test.cc
 *
 *  Created on: 13 Mar 2013
 *      Author: elukpot
 */

#include "ArgProcessor_unit_test.hpp"
// System Includes
#include <string.h>
#include <stdio.h>
#include <iostream>

// Test files includes
#include "ArgProcessor.h"

// Ignore the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"

void testTrue() {
    ASSERTM("Test Case should Pass", true);
}

cute::suite runArgProcessorSuite(cute::suite s) {
    // Add all tests under here.
    s.push_back(CUTE(testTrue));
    // Add all tests above here.
    return s;
}

// Re-enable the "warning: depreciated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
