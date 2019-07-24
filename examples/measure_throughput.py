import os
import time
from termcolor import colored

CmdNetBricks = {
	'start': './run_real.sh {task} 2>/dev/null &',
	'kill': 'sudo pkill {task}'
}

CmdPktgen = {
	'start': 'ssh -i /home/yangz/.ssh/id_rsa yangz@10.243.38.93 "cd ./pktgen/dpdk_zeroloss_dyn/ && bash run.sh ../l2.conf 0.1 32 60 1 {type}"',
	'kill': 'sudo pkill "ssh yangz@10.243.38.93" 2>/dev/null'
}

start_string = 'pkt sent, '
end_string = ' Mpps'


def task_exec(task, pktgen_type, throughput_res):
	print "start task %s" % (task,)
	os.system(CmdNetBricks['start'].format(task=task))

	print "start pktgen %s" % (pktgen_type,)
	pktgen_results = os.popen(CmdPktgen['start'].format(type=pktgen_type)).read()
	print "end pktgen %s" % (pktgen_type,)

	print pktgen_results
	start_index = pktgen_results.find(start_string) + len(start_string) 
	# this task executes error. 
	if start_index == -1:
		return -1 
	end_index = pktgen_results.find(end_string, start_index)
	if end_index == -1:
		return -1 

	throughput_val = pktgen_results[start_index: end_index]
	throughput_val = float(throughput_val)

	os.system(CmdNetBricks['kill'].format(task=task))
	print "kill task %s" % (task,)

	print colored("throughput_val: %lf" % (throughput_val,), 'blue')
	throughput_res.write(task + "," + pktgen_type + "," + str(throughput_val) + "\n")
	return 0

if __name__ == '__main__':
	throughput_res = open("throughput-eva/throughput.txt", 'w')
	
	# for task_cur in ["acl-fw", "dpi", "lpm", "maglev", "monitoring", "nat-tcp-v4", "acl-fw-ipsec", "dpi-ipsec", "lpm-ipsec", "maglev-ipsec", "monitoring-ipsec", "nat-tcp-v4-ipsec"]:
	# 	for pktgen_type in ["ICTF", "CAIDA64", "CAIDA256", "CAIDA512", "CAIDA1024", "ICTF_IPSEC", "CAIDA64_IPSEC", "CAIDA256_IPSEC", "CAIDA512_IPSEC", "CAIDA1024_IPSEC"]:
	task = "macswap"
	pktgen_type = "CAIDA64"
	status = task_exec(task, pktgen_type, throughput_res)
	if status == -1:
		print colored("%s %s fails" % (task, pktgen_type), 'red')
	else:
		print colored("%s %s succeeds" % (task, pktgen_type), 'green')

	throughput_res.close()
