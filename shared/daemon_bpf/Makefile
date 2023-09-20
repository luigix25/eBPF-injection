BUILD_DIR=build
CXXFLAGS= -O2 -Wall -Wextra -pedantic -g
LIB_PATH=../../include
INCLUDES=-I${LIB_PATH}

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/daemon_bpf

${BUILD_DIR}/daemon_bpf: ${BUILD_DIR}/daemon_bpf.o ${BUILD_DIR}/bpf_loader.o ${BUILD_DIR}/service_list.o
	$(CXX) $(CXXFLAGS) $^ -o $@ -lbpf

#checking for changes in the library

${BUILD_DIR}/daemon_bpf.o: daemon_bpf.cpp $(LIB_PATH)/bpf_injection_msg.h 
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

${BUILD_DIR}/bpf_loader.o: BpfLoader.cpp BpfLoader.h $(LIB_PATH)/bpf_injection_header.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

${BUILD_DIR}/service_list.o: ServiceList.cpp ServiceList.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) ${BUILD_DIR}/daemon_bpf ${BUILD_DIR}/*.o