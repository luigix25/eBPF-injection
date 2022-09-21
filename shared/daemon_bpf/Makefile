BUILD_DIR=build
CXXFLAGS= -O2 -Wall -Wextra -pedantic -g

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/daemon_bpf

${BUILD_DIR}/daemon_bpf: daemon_bpf.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ -lbpf

clean:
	$(RM) ${BUILD_DIR}/daemon_bpf *.o