/*
 * service_provider.h
 *
 *  Created on: 9 Jul 2014
 *      Author: efitleo
 */

#ifndef SERVICE_PROVIDER_H_
#define SERVICE_PROVIDER_H_

#include <boost/tr1/unordered_map.hpp>
#include "service_provider_init.hpp"
#include "flow.h"


class ServiceProvider{
    std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum> service_provider_protocol;
    std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum> service_provider_subProtocol;
    std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum> service_provider_application;
    std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum> service_provider_protocolGroup;
    std::tr1::unordered_map<int, service_provider_info::ServiceProviderEnum> service_provider_clinetfinder;
    void initServiceProvider_protocolMap();
    void initServiceProvider_subProtocolMap();
    void initServiceProvider_applicationMap();
    void initServiceProvider_protocolGroupMap();
    void initServiceProvider_clientfinderMap();

 
    private:

    public:
		int service_provider_cdpAdverts_arraySize;
		int service_provider_cdpSwUpdate_arraySize;

		 
        ServiceProvider();
        ServiceProvider(int classfiyInstanceNum); 
        ~ServiceProvider();
       	void getServiceProvider(flow_data* fd, int *check_service_provider);
        void getGroupServiceProvider(flow_data* fd, unsigned int protocol, unsigned int application);
		void printServiceProviderInfo(flow_data* fd, const char* myTitle, int *check_service_provider);
	    
		
		// to get rid of a compiler error "unused variable service_provider_info::SERVICE_PROVIDER_STR"
		void dummyPrintServiceProvider(int idx){
			LOG4CXX_INFO(loggerClassify, "SERVICE_PROVIDER: service_provider (Str) = " << service_provider_info::SERVICE_PROVIDER_STR[idx]);
		}

        
};

#endif /* SERVICE_PROVIDER_H_ */

