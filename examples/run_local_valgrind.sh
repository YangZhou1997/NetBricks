#!/bin/bash
source ./config.sh

TASK=macswap

if [ $# == 1 ]; then
    TASK=$1
fi

echo $TASK

# valgrind --tool=massif
valgrind --tool=massif --stacks=yes $HOME/NetBricks/target/$MODE/$TASK \
-p dpdk:eth_pcap0,rx_pcap=$TRAFFIC,tx_pcap=/tmp/out.pcap -c $CORE --pool-size=$POOL_SIZE -d $TIME
