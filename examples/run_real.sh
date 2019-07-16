#!/bin/bash
source ./config.sh

TASK=macswap

if [ $# -ge 1 ]; then
    TASK=$1
fi

echo $TASK

$HOME/NetBricks/target/$MODE/$TASK -f $TASK/config.toml

unset RUST_BACKTRACE
