#!/usr/bin/bash

set -x

#grep -E "<match.*mtype='re'.*>" -A 2 ms_rule.xml > final.xml

function buildDynamic()
{
	g++  -std=c++11 -lpthread -I./hs -I./re2 -L./ -lre2 -lhs re2_hyperscan_compare.cpp -g -o re2_hyperscan_compare
	LD_LIBRARY_PATH=./ ./re2_hyperscan_compare final.xml
}

function buildStatic()
{
	g++ -std=c++11 -I./hs -I./re2 -c re2_hyperscan_compare.cpp -g -o re2_hyperscan_compare.o
	g++  re2_hyperscan_compare.o -lpthread -L./static -lre2 -lhs -g -o re2_hyperscan_compare
	./re2_hyperscan_compare final.xml
}

if [ $# -lt 1 ];
then
	echo "Usage: $0 [static|dynamic]"
	exit 0
fi

if [ $1 = "static" ];
then
	buildStatic
else
	buildDynamic
fi

