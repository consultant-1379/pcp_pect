#ifndef _CONFIG_H
#define _CONFIG_H

#include "pcpglue.hpp"

// Define externs for use outside of config.cc
extern const packet_source config_source_array;
extern const int config_source_count;
extern const packet_sink config_sink_array;
extern const int config_sink_count;

int configurePacketBuffer();

#endif
