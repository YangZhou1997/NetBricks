# #!/bin/bash
# TEST_NAME=embedded-scheduler
# PORT_OPTIONS="dpdk:eth_pcap0,rx_pcap=data/http_lemmy.pcap,tx_pcap=/tmp/out.pcap"
# ../../build.sh run $TEST_NAME -p $PORT_OPTIONS -c 1 -d 1

# C='\033[1;34m'
# NC='\033[0m'

# echo -e "${C}RUNNING: $TEST_NAME${NC}"

# tcpdump -tner /tmp/out.pcap | tee /dev/tty | diff - data/expect.out

# result=$?
# echo ----
# if [[ $result != 0 ]]; then
#   echo FAIL
#   exit $result
# else
#   echo PASS
# fi
