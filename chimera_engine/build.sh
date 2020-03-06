#!/bin/bash

set -x

g++ -g -std=gnu++11 chimera_engine_test.c -L./lib -lchimera -lhs -lpcre -I./include -o chimera_engine


