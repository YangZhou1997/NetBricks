# !/bin/bash
source ./config.sh

TASK=macswap

if [ $# == 1 ]; then
    TASK=$1
fi

echo $TASK

$HOME/NetBricks/target/debug/$TASK \
-p dpdk:eth_pcap0,rx_pcap=$TRAFFIC,tx_pcap=/tmp/out.pcap -c 1 -d 1
