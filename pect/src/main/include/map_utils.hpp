/*
 * map_utils.hpp
 *
 *  Created on: 14 Mar 2013
 *      Author: emilawl
 *
 */

#ifndef MAP_UTILS_HPP_
#define MAP_UTILS_HPP_

#include <boost/tr1/unordered_map.hpp>
#include <algorithm>


/*
*  This header file provides a method of sharing hash_long_long to both UE_map.hpp and flow.h.
*  As flow.h includes UE_map.hpp and UE_map.hpp includes flow.h (circular reference). This leads to complications
*  in the typedef as it requires things defined in both files. Thus we define the types in both files, apparently this
*  is allowed, to allow for this double typedef this function needs to be included in both files.
*/
struct hash_long_long {
    size_t operator()(const long long in) const {
        long long ret = (in >> 32L) ^ std::hash<long long>()(in & 0xFFFFFFFF);
        return (size_t) ret;
    }
};

#endif /* MAP_UTILS_HPP_ */
