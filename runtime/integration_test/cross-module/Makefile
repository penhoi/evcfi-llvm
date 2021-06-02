##usage: make [DEBUG=1] [LTO=1]

CLANG_ROOT	:=../build-release-gold
CC	:= ${CLANG_ROOT}/bin/clang
CXX	:= ${CLANG_ROOT}/bin/clang++


export VLOOM_SCRATCH=3
export VLOOM_SIZE=64
#export VLOOM_DISABLED=1
#export VLOOM_MODE=4


NOWARNS := -Wno-unused-variable -Wno-unused-variable -Wno-unused-command-line-argument
CFLAGS= ${NOWARNS} -fuse-ld=gold
CXXFLAGS=${NOWARNS} -fuse-ld=gold

ifeq (${DEBUG}, 1)
	CXXFLAGS += -O0 -ggdb3 
else
	CXXFLAGS += -O2 -ggdb3 
endif

ifeq (${LTO}, 1)
	CXXFLAGS += -flto
endif

CXXFLAGS-EXE	= ${CXXFLAGS} -L . -lvloom -Wl,--rpath='$${ORIGIN}'
CXXFLAGS-LIB	= ${CXXFLAGS}

LIBS		= -lm -ldl



all: Main.cpp Lib.cpp
	$(CXX) ${CXXFLAGS-EXE} Main.cpp -o Main  ${LIBS}
	$(CXX) ${CXXFLAGS-LIB} -fPIC -shared -o libVector.so Lib.cpp


clean:
	rm -f Main libVector.so 

