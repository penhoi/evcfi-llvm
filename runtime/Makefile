CXX	        := clang++
CXXFLAGS	+= -std=c++11 -fPIC -shared
XOM		?= 0
REVERSE	?= 0
DEBUG	?= 0
PERF	?= 0

ifeq (${PERF},1)
	CXXFLAGS += -DPERF_TEST
endif

ifeq (${XOM},1)
	CXXFLAGS += -DXOM_SUPPORT
endif

ifeq (${REVERSE},1)
	CXXFLAGS += -DREVERSE
	DODEBUG	:= 1
else ifeq (${DEBUG},1)
	DODEBUG	:= 1
else
	DODEBUG	:= 0
endif

ifeq (${DODEBUG},1)
	CXXFLAGS += -O0 -ggdb3 -DDEBUG
else
	CXXFLAGS += -O2
endif
CXXFLAGS	+= -msse4.2

LIBS	+= -lelf -ldl

CPP_FILES	:= bloom.cpp  cha.cpp  config.cpp  elfmgr.cpp  hash.cpp  logging.cpp  mm.cpp  patch.cpp  utils.cpp  vloom.cpp
OBJ_FILES	:= $(patsubst %.cpp,%.o,${CPP_FILES})


all: libvloom.so libvloom.a


libvloom.so: ${CPP_FILES}
	${CXX} ${CXXFLAGS} -o $@ ${CPP_FILES} ${LIBS}


libvloom.a: ${OBJ_FILES}
	ar -rcs $@ ${OBJ_FILES}


${OBJ_FILES} : %.o : %.cpp
	${CXX} ${CXXFLAGS} -o $@ $<


clean:
	rm -rf libvloom.so
	rm -rf ${OBJ_FILES} libvloom.a
	make -C unit_test clean
