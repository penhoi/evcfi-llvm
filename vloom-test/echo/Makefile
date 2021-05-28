VLOOM_LLVM_ROOT	:= $(shell pwd)/../..
CC	:= ${VLOOM_LLVM_ROOT}/build_debug/bin/clang
CXX	:= ${VLOOM_LLVM_ROOT}/build_debug/bin/clang++

DEBUG		?= 1


ifeq (${DEBUG}, 1)
	CXXFLAGS += -O0 -g
else
	CXXFLAGS += -O2 -g
endif


CXXFLAGS	+= -std=c++98
LDFLAGS		+= -fuse-ld=lld -Wl,--emit-relocs -Wl,-znotext 
LIBS		= -lm -ldl

export VLOOM_LOGFILE=stdout
export VLOOM_K=1
export VLOOM_HASH_0=add32


all: echo.exe


echo.exe: echo.cpp
	$(CXX) ${CXXFLAGS} ${LDFLAGS} $^ -o $@ ${LIBS}


run: echo.exe
	@cp ${VLOOM_LLVM_ROOT}/../src/libvloom.so .
	LD_PRELOAD=./libvloom.so ./echo.exe


clean:
	rm -f echo.exe
