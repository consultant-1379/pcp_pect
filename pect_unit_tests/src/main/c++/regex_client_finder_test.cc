/*
 * regex_client_finder_test.cc



 *
 *  Created on: 9 May 2013
 *      Author: ezhelao
 */

#include "clientfinder.hpp"
#include "cute.h"

#pragma GCC diagnostic ignored "-Wwrite-strings"


void testRegexFinder_YouTube()
{
    RegexClientFinder r ;
    char *a = "123123YouTube12313";
    int result =r.findClientFromUserAgent(a);
    ASSERTM("expecting result=3  ", result==3);


}

void testRegexFinder_NoFound()
{
    RegexClientFinder r ;
    char a[100] ="123123123\0";
    int result =r.findClientFromUserAgent(a);
    ASSERTM("expecting result=-1  ", result==-1);


}

cute::suite runCLientFinderTest(cute::suite s)
{
    s.push_back(CUTE(testRegexFinder_YouTube));
    s.push_back(CUTE(testRegexFinder_NoFound));
    return s;
}
#pragma GCC diagnostic warning "-Wwrite-strings"
