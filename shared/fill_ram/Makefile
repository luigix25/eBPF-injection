BUILD_DIR=build
CXXFLAGS= -g #-O2 -Wall -Wextra -pedantic -g

folder:=$(shell mkdir -vp ${BUILD_DIR})

all: ${BUILD_DIR}/ram_filler

${BUILD_DIR}/ram_filler: ram_filler.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

