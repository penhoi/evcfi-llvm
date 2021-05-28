#!/bin/bash

test_VLOOM_SCRATCH()
{
    export CXX_FLAGS=-c
    for i in `seq 0 1 8`; do
        make clean
        export vloom_scratch=2 
	make bark$i && mv bark$i.asm bark${i}_2.asm 

        make clean
        export vloom_scratch=3 
	make bark$i && mv bark$i.asm bark${i}_3.asm

        diff bark${i}_2.asm bark${i}_3.asm > diff${i}_23.del
        #0 diff0_23.del
        wc -l diff${i}_23.del >> result.txt
    done
}

test_VLOOM_SCRATCH
