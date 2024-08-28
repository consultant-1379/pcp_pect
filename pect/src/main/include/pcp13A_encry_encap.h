/*
 * pcp13A_encry_encap.hpp
 *
 *  Created on: 20 May 2013
 *      Author: ezhelao
 */

#ifndef PCP13A_ENCRY_ENCAP_HPP_
#define PCP13A_ENCRY_ENCAP_HPP_

namespace V13AEncry
{

static const char *V13A_ENCRYPTION_STR[]=
{"SSL",
"IPSec-NAT-traversal",
"ESP",
"\\N"};

enum V13AEncrptionEnum
{
    SSL=0,
    IPSec_NAT_traversal,
    ESP,
    unknown_encry

};
}

namespace V13AEncap
{

static const char * V13A_ENCAPSULATION_STR[]=
{
        "HTTP",
        "IPSec-NAT-traversal",
        "blackberry",
        "ESP",
        "GRE",
        "IPv6_in_IPv4",
        "\\N"
};


enum V13AEncapsulationEnum
{
    HTTP=0,
    IPSec,
    blackberry,
    ESP,
    GRE,
    IPv6_in_IPv4,
    unknown_encap

};

}

#endif /* PCP13A_ENCRY_ENCAP_HPP_ */
