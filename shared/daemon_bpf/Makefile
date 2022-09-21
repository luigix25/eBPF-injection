BUILD_DIR=build
CXXFLAGS= -O2 -Wall -Wextra -pedantic -g
LIB_PATH=../../include
CLIBS=-I${LIB_PATH}

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/daemon_bpf

#checking for changes in the library
${BUILD_DIR}/daemon_bpf: daemon_bpf.cpp $(LIB_PATH)/bpf_injection_msg.h 
	$(CXX) $(CXXFLAGS) $(CLIBS) $< -o $@ -lbpf

clean:
	$(RM) ${BUILD_DIR}/daemon_bpf *.o