#include "gtpc_map_serialisation_utils.h"
#include "gtpv1_message_handler_types.h"

GTPV1MessageHandlerStats_t messageHandlerStats;

extern UserPDPSessionMap_t userPDPSessionMap;

int main(int argc, char **argv) {
	cout << "Hello world!";
	initializeLogging();
	evaluatedArguments.outputlocation = ".";
	readGtpcCache();
	PDPSession *session;
	int count = 0;
	for(auto it = userPDPSessionMap.begin(); it != userPDPSessionMap.end();) {
		session = it->second;
		it++;
		cout << session << endl;
		count++;
	}

	cout << count;


	return EXIT_SUCCESS;
}
