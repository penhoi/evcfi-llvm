##usage: make [DEBUG=1] [LTO=1]

CLANG_ROOT	:=../build-release-gold
CC	:= ${CLANG_ROOT}/bin/clang
CXX	:= ${CLANG_ROOT}/bin/clang++


#export VLOOM_NOP_SIZE=18
export VLOOM_SCRATCH=3
export VLOOM_SIZE=80
export VLOOM_REGSET=1
#export VLOOM_DISABLED=1
#export VLOOM_MODE=4


NOWARNS := -Wno-unused-variable -Wno-unused-variable -Wno-unused-command-line-argument
CFLAGS= ${NOWARNS} -fuse-ld=gold
CXXFLAGS=${NOWARNS} -fuse-ld=gold

ifeq (${DEBUG}, 1)
	CXXFLAGS += -O0 -g -ggdb3
else
	CXXFLAGS += -O2 -g -ggdb3
endif

ifeq (${LTO}, 1)
	CXXFLAGS += -flto
endif

CXXFLAGS	+= -L . -lvloom -Wl,--rpath='$${ORIGIN}'



all: weirdvcall.exe


%.exe: %.cpp
	$(CXX) ${CXXFLAGS} $^ -o $@ ${LIBS}


clean:
	rm -f *.exe

