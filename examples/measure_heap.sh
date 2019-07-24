#!/bin/bash

for task in acl-fw dpi lpm maglev monitoring nat-tcp-v4 
do
    ./run_local_jemalloc.sh $task
    python tlb_cal.py jemalloc-log/container_1g/$task.log > jemalloc-log/container_1g/$task.tlb
done

for task in acl-fw dpi lpm maglev monitoring nat-tcp-v4 
do
    ./run_local_valgrind.sh $task
done