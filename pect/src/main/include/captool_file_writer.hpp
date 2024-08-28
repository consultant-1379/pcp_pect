#ifndef CAPTOOL_FILE_WRITER_HPP_
#define CAPTOOL_FILE_WRITER_HPP_

void initCaptoolFileWriter();
void *printUeMapCaptool(void *init);
void captoolTimeoutFlowData(const flow_data *data, struct FileCounters &fileCounters);
void *printUPDataCaptool(void *data);

#endif
