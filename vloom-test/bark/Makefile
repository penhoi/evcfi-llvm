PROJ_ROOT = $(shell pwd)/../../

CLANG	:= ${PROJ_ROOT}/build_release_gold/bin/clang++
CXX_FLAGS ?=-std=c++11 -fuse-ld=lld -Wl,--emit-relocs -Wl,--export-dynamic -Wl,-znotext -O1 -ggdb3
#CMD = ./$@ & objdump -d $@ > $@.asm
CMD = 

OBJS := bark
ASMS := $(patsubst %,%.asm,${OBJS})

all: ${OBJS}

bark: bark.cpp
	${CLANG} ${CXX_FLAGS} -DPARAM_NUM=0 $^ -o $@
	${CMD}

clean:
	@rm -f ${OBJS} ${ASMS}

