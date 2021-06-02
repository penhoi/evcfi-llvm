CXXFLAGS	:= -O0 -g -ggdb3 -msse4.2 -include /usr/include/CppUTest/MemoryLeakDetectorMallocMacros.h
LIBS		:= -lCppUTest -lCppUTestExt -ldl -lelf
RUNCMD		:= ./run.sh

TARGETS := logging.exe mm.exe config.exe hash.exe  elfmgr.exe cha.exe patch.exe vloom.exe


all: ${TARGETS}

map.exe: test_map.cpp ../utils.cpp
	clang++  ${CXXFLAGS}  -o $@ $^ ${LIBS}
	${RUNCMD} $@

logging.exe: test_logging.cpp ../logging.cpp ../utils.cpp
	clang++  ${CXXFLAGS}  -o $@ $^ ${LIBS}
	${RUNCMD} $@

mm.exe: test_mm.cpp ../mm.cpp ../utils.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@ $^ ${LIBS}
	${RUNCMD} $@

config.exe: test_config.cpp ../config.cpp ../utils.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@ $^ ${LIBS}
	${RUNCMD} $@

hash.exe: test_hash.cpp ../hash.cpp ../utils.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@  $^ ${LIBS}
	${RUNCMD} $@

elfmgr.exe: test_elfmgr.cpp ../elfmgr.h ../elfmgr.cpp ../mm.h ../mm.cpp ../utils.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@ test_elfmgr.cpp ../elfmgr.cpp ../mm.cpp ../utils.cpp ${LIBS}
	${RUNCMD} $@

cha.exe: test_cha.cpp ../cha.cpp ../mm.cpp ../utils.cpp ../config.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@ $^ ${LIBS}
	${RUNCMD} $@

patch.exe: test_patch.cpp ../patch.cpp ../mm.cpp ../hash.cpp ../config.cpp ../utils.cpp ../cha.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@  $^ ${LIBS}
	${RUNCMD} $@

vloom.exe: test_vloom.cpp ../vloom.cpp ../config.cpp ../cha.cpp ../patch.cpp ../utils.cpp ../hash.cpp  ../logging.cpp ../mm.cpp ../elfmgr.cpp ../bloom.cpp
	clang++ -DVLOOM_UTEST ${CXXFLAGS} -o $@ $^ ${LIBS}
	${RUNCMD} $@


run: ${TARGETS}
	${RUNCMD} ${TARGETS}

clean:
	rm -rf ${TARGETS}
