/*
 * pcp_check.hpp
 *
 *  Created on: 18 Sep 2013
 *      Author: ezhelao
 */

#ifndef PCP_CHECK_HPP_
#define PCP_CHECK_HPP_

#include <cstdint>

#define IPOQUE_INTERNAL_REDZONE_CHECKING

#define IPQ_FORCE_SEGFAULT() (*(std::uint8_t*)0 = 0)
#ifdef IPOQUE_INTERNAL_REDZONE_CHECKING
#  define IPQ_REDZONE_DEF(n) std::uint16_t redzone_##n;
#  define IPQ_REDZONE_REF(n) redzone_##n
#else
#endif

#endif /* PCP_CHECK_HPP_ */
