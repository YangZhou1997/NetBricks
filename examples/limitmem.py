import os
import time
from termcolor import colored
import datetime
import threading
from threading import Event, Thread

# 5 pages from the monitoring to dpdk 
# cgroup seems including dpdk memory usage
# DPDK_MEM = (5 * 2 * 1024 * 1024)

CmdLimitMemBg = {
	'start': './limitmem {mem}M bash run_real.sh {task} {num_queue} 2>/dev/null &',
	'kill': 'sudo pkill limitmem && sudo pkill head && sudo pkill {task}'
}

CmdGetCgroupID = {
	'start': 'ps -ef | grep limitmem',
}

CmdGetCgroupMemUsage = {
	'start': 'cgget -g {cgroup_name} | grep memory.memsw.usage_in_bytes',
}

CmdGetCgroupMaxMemUsage = {
	'start': 'cgget -g {cgroup_name} | grep memory.memsw.max_usage_in_bytes',
}

CmdPktgen = {
	'start': 'ssh -i /home/yangz/.ssh/id_rsa yangz@10.243.38.93 "cd ./pktgen/dpdk_zeroloss_dyn/ && bash run_netbricks.sh ../l2.conf 0.1 32 60 1 {type}"',
	'kill': 'sudo pkill "ssh yangz@10.243.38.93" 2>/dev/null'
}


def get_cgroup_name():
	start_string = '/tmp/limitmem_'
	end_string = '_cgroup_closer'

	grep_results = os.popen(CmdGetCgroupID['start']).read()

	# find the latest cgroup name
	start_index = grep_results.rfind(start_string) + len(start_string) 
	# this task executes error. 
	if start_index == -1:
		return "Err" 
	end_index = grep_results.find(end_string, start_index)
	if end_index == -1:
		return "Err"

	cgroup_num = grep_results[start_index: end_index]
	return "memory:limitmem_" + cgroup_num

stop_mark = False
mem_usages = list()
max_mem_usage = 0

def cgroup_polling(cgroup_name):
	global stop_mark
	global mem_usages
	global max_mem_usage

	while 1 and (not stop_mark):
		time.sleep(0.01)
		memusage_results = os.popen(CmdGetCgroupMemUsage['start'].format(cgroup_name=cgroup_name)).read()
		cur_memusage = int(memusage_results.rstrip("\n").split()[1])
		mem_usages.append(cur_memusage)

		max_memusage_results = os.popen(CmdGetCgroupMaxMemUsage['start'].format(cgroup_name=cgroup_name)).read()
		max_mem_usage = int(max_memusage_results.rstrip("\n").split()[1])

def run_limitmem(task, pktgen, memsize):
	global stop_mark
	global mem_usages
	global max_mem_usage

	stop_mark = False
	mem_usages = list()
	max_mem_usage = 0

	# we do not set limit to the process memory
	os.system(CmdLimitMemBg['start'].format(mem=str(memsize), task=task, num_queue = 1))
	
	while 1:
		cgroup_name = get_cgroup_name()
		if cgroup_name == "Err":
			continue
		break
	print "cgroup_name: " + cgroup_name

	polling = threading.Thread(target=cgroup_polling, args=(cgroup_name,))
	polling.start()
	print "pooling starts"

	print "start pktgen %s" % (pktgen_type,)
	pktgen_results = os.popen(CmdPktgen['start'].format(type=pktgen_type)).read()
	print "end pktgen %s" % (pktgen_type,)
	print pktgen_results

	start_string = 'pkt sent, '
	end_string = ' Mpps'
	start_index = pktgen_results.find(start_string) + len(start_string) 
	# this task executes error. 
	if start_index == -1:
		print "pktgen errors, retrying..."
		stop_mark = True
		polling.join()
		os.system(CmdLimitMemBg['kill'].format(task = task))
		return -1
	end_index = pktgen_results.find(end_string, start_index)
	if end_index == -1:
		print "pktgen errors, retrying..."
		stop_mark = True
		polling.join()
		os.system(CmdLimitMemBg['kill'].format(task = task))
		return -1

	throughput_val = pktgen_results[start_index: end_index]
	throughput_val = float(throughput_val)
	print colored("throughput_val: %lf" % (throughput_val,), 'blue')

	stop_mark = True
	polling.join()
	os.system(CmdLimitMemBg['kill'].format(task = task))

	return 0


if __name__ == '__main__':
	now = datetime.datetime.now()
	limitmem_res = open("./memory-profiling/cgroup-log/memusage.txt_" + now.isoformat(), 'w')

	tasks = ["macswap"]
	pktgen_types = ["ICTF"]

	for task in tasks:
		for pktgen_type in pktgen_types:
			res = run_limitmem(task, pktgen_type, 7.5)

			total_mem_usages = map(lambda x: x / (1024 * 1024.0), mem_usages)
			max_total_mem_usages = max_mem_usage  / (1024 * 1024.0)		
			
			print total_mem_usages
			print colored("peak_total_mem_usage: " + str(max_total_mem_usages), 'green')

			limitmem_res.write(task + "," + pktgen_type + "\n")
			limitmem_res.write(str(total_mem_usages) + "\n")
			limitmem_res.write(str(max_total_mem_usages) + "\n")
			limitmem_res.flush()
	
	limitmem_res.close()