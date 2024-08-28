
CC=g++
CXX=g++

CCFLAGS = -g -D_TRACE -DCCP -DASN1RT -DGNU -D_GNU_SOURCE -I. -Wall

CPPFLAGS = -o -g -std=c++0x -I ./include

OBJ = src/main/c++/classify.o src/main/c++/packetbuffer.o src/main/c++/pcpglue.o src/main/c++/mutex.o src/main/c++/UE_map.o src/main/c++/gtpv1.o src/main/c++/gtp_ie.o src/main/c++/GTPv1_packetFields.o src/main/c++/gtpv1_utils.o src/main/c++/gtpv2_main.o src/main/c++/gtp_ie_gtpv2.o src/main/c++/ArgProcessor.o 



HEADERS=src/main/include/classify.h src/main/include/packetbuffer.h src/main/include/UE_map.hpp src/main/include/mutex.hpp src/main/include/pcpglue.hpp
LIBS=-lpcap -lpthread -L./libs -src/main/lib/libipoque_detection -I./include -lpcap -lcrypto -L./lib -libmagicstring.a


all: $(HEADERS) $(OBJ) pect
      
.PHONY : all        
        
clean:
	\rm -f src/main/c++/*.o src/main/c++/pect

pect: $(objects) $(OBJ)
	$(CXX) $(CCFLAGS) -o pect $(OBJ) $(LIBS)
