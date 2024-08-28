// Includes
#include <iostream>
#include "cute.h"
#include "config.h"

// Ignore the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic ignored "-Wwrite-strings"
using std::cout;
using std::endl;

// Define extern for the functions which are not normally exposed through header files
int configureSource(EArgs &arguments);
int configureSink(EArgs &arguments);

void testConfigureSourcesMultiplePacketBuffers() {
    EArgs args;
    args.packetBufferSourceCount = 3;
    args.packetBufferGtpuSourceName.push_front("source1");
    args.packetBufferGtpuSourceName.push_front("source2");
    args.packetBufferGtpuSourceName.push_front("source3");
    args.useMultiplePacketBuffers = true;
    args.packetBufferCaptureType = CAPTURE_LIVE;
    int result = configureSource(args);
    stringstream string;
    string << "Expected packetBufferSourceCount to be " << args.packetBufferSourceCount << " was "
           << config_source_count;
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSourceCount, config_source_count);

    for(int i = 0; i < config_sink_count; i++) {
        // Capture type
        string.clear();
        string << "Expected captureFrom for source number " << i << " to be CAPTURE_LIVE (" << CAPTURE_LIVE << ") was ("
               << config_source_array[i].capture_type << ")";
        ASSERT_EQUALM(string.str().c_str(), args.packetBufferCaptureType, config_source_array[i].capture_type);
        // Source name
        char sourceName[10];
        snprintf(sourceName, 10, "source%i", i);
        string.clear();
        string << "Expected sourceName for source number " << i << " to be " << sourceName << " but was "
               << config_source_array[i].source_name;
        ASSERTM(string.str().c_str(), strcmp(sourceName, config_source_array[i].source_name));
        // Packet buffer number
        string.clear();
        string << "Expected packetbuffer number to be " << i + 1 << " but was "
               << config_source_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_source_array[i].packetBufferNum);
        // Queue, always equals 1 with multiple packetbuffers
        string.clear();
        string << "Expected queue number to be " << 1 << " but was " << config_source_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), 1, config_source_array[i].queue);
    }
}

void testConfigureSourcesSinglePacketBuffer() {
    EArgs args;
    args.packetBufferSourceCount = 3;
    args.packetBufferGtpuSourceName.push_front("source1");
    args.packetBufferGtpuSourceName.push_front("source2");
    args.packetBufferGtpuSourceName.push_front("source3");
    args.useMultiplePacketBuffers = false;
    args.packetBufferCaptureType = CAPTURE_LIVE;
    int result = configureSource(args);
    stringstream string;
    string << "Expected packetBufferSourceCount to be " << args.packetBufferSourceCount << " was "
           << config_source_count;
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSourceCount, config_source_count);

    for(int i = 0; i < config_sink_count; i++) {
        // Capture type
        string.clear();
        string << "Expected captureFrom for source number " << i << " to be CAPTURE_LIVE (" << CAPTURE_LIVE << ") was ("
               << config_sink_count << ")";
        ASSERT_EQUALM(string.str().c_str(), args.packetBufferCaptureType, config_source_array[i].capture_type);
        // Source name
        char sourceName[10];
        snprintf(sourceName, 10, "source%i", i);
        string.clear();
        string << "Expected sourceName for source number " << i << " to be " << sourceName << " but was "
               << config_source_array[i].source_name;
        ASSERTM(string.str().c_str(), strcmp(sourceName, config_source_array[i].source_name));
        // Packet buffer number, always equals 1
        string.clear();
        string << "Expected packetbuffer number to be " << 1 << " but was " << config_source_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), 1, config_source_array[i].packetBufferNum);
        // Queue
        string.clear();
        string << "Expected queue number to be " << i + 1 << " but was " << config_source_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_source_array[i].queue);
    }
}

void testConfigureSinksTrackSourceMultiPacketBuffer() {
    EArgs args;
    args.packetBufferSinkCount = 0;
    args.packetBufferSourceCount = 3;
    args.useMultiplePacketBuffers = true;
    configureSink(args);
    stringstream string;
    string << "Sink count (" << config_sink_count << ") doesn't match source count (" << args.packetBufferSourceCount
           << ")";
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSourceCount, config_sink_count);

    for(int i = 0; i < config_sink_count; i++) {
        string.clear();
        string << "Sink number " << i << " has incorrect packetBufferNum: " << config_sink_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_sink_array[i].packetBufferNum);
        string.clear();
        string << "Sink number " << i << " has incorrect Queue: " << config_sink_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), 1, config_sink_array[i].queue);
    }
}

// Setting useMultiplePacketBuffers to true should force the sink count to track the source count
void testConfigureSinksMultiplePacketBuffers() {
    EArgs args;
    args.packetBufferSinkCount = 1;
    args.packetBufferSourceCount = 3;
    args.useMultiplePacketBuffers = true;
    configureSink(args);
    stringstream string;
    string << "Sink count (" << config_sink_count << ") doesn't match source count (" << args.packetBufferSourceCount
           << ")";
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSourceCount, config_sink_count);

    for(int i = 0; i < config_sink_count; i++) {
        string.clear();
        string << "Sink number " << i << " has incorrect packetBufferNum: " << config_sink_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_sink_array[i].packetBufferNum);
        string.clear();
        string << "Sink number " << i << " has incorrect Queue: " << config_sink_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), 1, config_sink_array[i].queue);
    }
}

void testConfigureSinksTrackSourceSinglePacketBuffer() {
    EArgs args;
    args.packetBufferSinkCount = 0;
    args.packetBufferSourceCount = 3;
    args.useMultiplePacketBuffers = false;
    configureSink(args);
    stringstream string;
    string << "Sink count (" << config_sink_count << ") doesn't match source count (" << args.packetBufferSourceCount
           << ")";
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSourceCount, config_sink_count);

    for(int i = 0; i < config_sink_count; i++) {
        string.clear();
        string << "Sink number " << i << " has incorrect packetBufferNum: " << config_sink_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), 1, config_sink_array[i].packetBufferNum);
        string.clear();
        string << "Sink number " << i << " has incorrect Queue: " << config_sink_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_sink_array[i].queue);
    }
}

void testConfigureSinksSinglePacketBuffer() {
    EArgs args;
    args.packetBufferSinkCount = 3;
    args.packetBufferSourceCount = 2;
    args.useMultiplePacketBuffers = false;
    configureSink(args);
    stringstream string;
    string << "Sink count " << config_sink_count << " doesn't match configured value " << args.packetBufferSinkCount
           << ")";
    ASSERT_EQUALM(string.str().c_str(), args.packetBufferSinkCount, config_sink_count);

    for(int i = 0; i < config_sink_count; i++) {
        string.clear();
        string << "Sink number " << i << " has incorrect packetBufferNum: " << config_sink_array[i].packetBufferNum;
        ASSERT_EQUALM(string.str().c_str(), 1, config_sink_array[i].packetBufferNum);
        string.clear();
        string << "Sink number " << i << " has incorrect Queue: " << config_sink_array[i].queue;
        ASSERT_EQUALM(string.str().c_str(), i + 1, config_sink_array[i].queue);
    }
}

cute::suite runConfigSuite(cute::suite s) {
    s.push_back(CUTE(testConfigureSourcesMultiplePacketBuffers));
    s.push_back(CUTE(testConfigureSourcesSinglePacketBuffer));
    s.push_back(CUTE(testConfigureSinksTrackSourceMultiPacketBuffer));
    s.push_back(CUTE(testConfigureSinksMultiplePacketBuffers));
    s.push_back(CUTE(testConfigureSinksTrackSourceSinglePacketBuffer));
    s.push_back(CUTE(testConfigureSinksSinglePacketBuffer));
    return s;
}

// Re-enable the "warning: deprecated conversion from string constant to 'char*'"
#pragma GCC diagnostic warning "-Wwrite-strings"
