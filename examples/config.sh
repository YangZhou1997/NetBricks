# !/bin/bash

# for both real and local run
#HOME=/home/vagrant
# HOME=/users/yangzhou
# HOME=/opt
HOME=/home/yangz
TRAFFIC=$HOME/traffic/ictf2010/merged.pcap

export LD_LIBRARY_PATH="$HOME/NetBricks/native:/opt/dpdk/dpdk-stable-17.08/build/lib:"
export RUST_BACKTRACE=1

# for real run
PORT=0000:04:00.0
CORE=0
POOL_SIZE=512
MODE=debug
TIME=100
