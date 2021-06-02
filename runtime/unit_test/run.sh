#!/bin/bash

run_app() 
{
	APP=$1
	echo "------------------------------run ${APP}------------------------------"
	./${APP}
}

for f in $@ ; do
	run_app $f
done
