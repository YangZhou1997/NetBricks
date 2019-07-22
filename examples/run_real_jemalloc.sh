# !/bin/bash
source ./config.sh

TASK=macswap

if [ $# == 1 ]; then
    TASK=$1
fi

echo $TASK

# env LD_PRELOAD=$HOME/jemalloc/lib/libjemalloc.so $HOME/NetBricks/target/$MODE/$TASK \
# -p $PORT -c $CORE --pool-size=$POOL_SIZE -d $TIME \
# 2>&1 | grep Tracing --line-buffered | awk '{$3=$3/(1024.0)} {print}'

HOME=/opt
export LD_LIBRARY_PATH="$HOME/netbricks/native:/opt/dpdk/dpdk-stable-17.08/build/lib:"
env LD_PRELOAD=$HOME/jemalloc/lib/libjemalloc.so $HOME/netbricks/target/$MODE/$TASK \
-p $PORT -c $CORE --pool-size=$POOL_SIZE -d $TIME 
# \
# 2>&1 | grep Tracing --line-buffered | awk '{$3=$3/(1024.0)} {print}'


# > jemalloc.log
# awk '{$3=$3/(1024.0)} {print}' jemalloc.log > jemalloc.log

