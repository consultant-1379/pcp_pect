#ifndef STAPLE_FILE_WRITER_HPP_
#define STAPLE_FILE_WRITER_HPP_

void initStapleFileWriter();
void *printUeMapStaple(void *);
void stapleTimeoutFlowData(flow_data *data, struct FileCounters &fileCounters);
void *printUPDataStaple(void *data);

#endif
