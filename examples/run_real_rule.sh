#!/bin/bash
source ./config.sh

TASK=macswap

if [ $# -ge 1 ]; then
    TASK=$1
fi

echo $TASK

# 1, 2, 3, 4
if [ $# -eq 3 ]; then
    $HOME/NetBricks/target/$MODE/$TASK -f ./config_$2core.toml -r $3
else
    $HOME/NetBricks/target/$MODE/$TASK -p $PORT -c $CORE --pool-size=$POOL_SIZE -d $TIME -r 33471
fi

unset RUST_BACKTRACE
