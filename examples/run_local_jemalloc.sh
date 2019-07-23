# !/bin/bash
source ./config.sh

TASK=macswap

if [ $# == 1 ]; then
    TASK=$1
fi

echo $TASK

env LD_PRELOAD=$HOME/jemalloc/lib/libjemalloc.so $HOME/NetBricks/target/debug/$TASK \
-p dpdk:eth_pcap0,rx_pcap=/home/vagran/traffic/ictf2010.pcap1,tx_pcap=/tmp/out.pcap -c 1 -d 1 \
2>&1 | grep Tracing --line-buffered > heap.log

