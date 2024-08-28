#ifndef PECT_FILE_WRITER_HPP_
#define PECT_FILE_WRITER_HPP_

#include <list>
#include "file_writer_map.hpp"

void initPectFileWriter();
void printUeMap(list<FileWriterMap *> *rop);
void timeoutFlowData(flow_data *data, struct FileCounters &fileCounters);

#endif
