import os
import time
from termcolor import colored
import datetime

CmdNetBricks = {
	'start': './run_real_rule.sh {task} {num_queue} {num_rule} 2>/dev/null &',
	'kill': 'sudo pkill {task}'
}

CmdPktgen = {
	'start': 'ssh -i /home/yangz/.ssh/id_rsa yangz@10.243.38.93 "cd ./pktgen/dpdk_zeroloss_dyn/ && bash run_netbricks.sh ../l2.conf 0.1 32 60 1 {type}"',
	'kill': 'sudo pkill "ssh yangz@10.243.38.93" 2>/dev/null'
}

start_string = 'pkt sent, '
end_string = ' Mpps'

def kill_keyword(task):
	if "-ipsec" in task:
		return task[0: -6]
	elif "-ipsec-sha" in task:
		return task[0: -10]	
	else:
		return task

def task_exec_reboot(task, pktgen_types, num_queue, num_rule, repeat_num, throughput_res):
	# repeat the booting until succeeding
	# sometimes, failed dpdk application can reclaim hugepage.
	for i in range(repeat_num):
		for pktgen_type in pktgen_types:	
			fail_count_inner = 0
			while(1):
				print "start task %s" % (task,)
				os.system(CmdNetBricks['start'].format(task=task, num_queue=num_queue, num_rule=num_rule))
				time.sleep(5) # wait for task gets actually started
			
				print "start pktgen %s" % (pktgen_type,)
				pktgen_results = os.popen(CmdPktgen['start'].format(type=pktgen_type)).read()
				print "end pktgen %s" % (pktgen_type,)

				print pktgen_results
				start_index = pktgen_results.find(start_string) + len(start_string) 
				# this task executes error. 
				if start_index == -1:
					print colored("%s %s %s fails" % (task, pktgen_type, num_queue), 'red')
					fail_count_inner += 1
					os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
					time.sleep(5) # wait for the port being restored.
					continue
				end_index = pktgen_results.find(end_string, start_index)
				if end_index == -1:
					print colored("%s %s %s fails" % (task, pktgen_type, num_queue), 'red')
					os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
					time.sleep(5) # wait for the port being restored.
					fail_count_inner += 1
					continue
				
				if fail_count_inner > 5:
					return -1
				
				throughput_val = pktgen_results[start_index: end_index]
				throughput_val = float(throughput_val)

				start_index = pktgen_results.find("avg_latency: ") + len("avg_latency: ") 
				end_index = pktgen_results.find(", tail_latency: ", start_index)
				avg_latency_val = pktgen_results[start_index: end_index]
				avg_latency_val = float(avg_latency_val)

				start_index = pktgen_results.find(", tail_latency: ") + len(", tail_latency: ") 
				end_index = pktgen_results.find("\n", start_index)
				tail_latency_val = pktgen_results[start_index: end_index]
				tail_latency_val = float(tail_latency_val)

				print colored("throughput_val: %lf, avg_latency_val: %lf, tail_latency_val: %lf" % (throughput_val, avg_latency_val, tail_latency_val), 'blue')
				throughput_res.write(task + "," + pktgen_type + "," + str(num_queue) + "," + str(num_rule) + ',' + str(throughput_val) + "," + str(avg_latency_val) + "," + str(tail_latency_val) + "\n")
				throughput_res.flush()
				
				os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
				time.sleep(5) # wait for the port being restored.

				break

	return 0

tasks_reboot = ["dpi", "dpi-hs"]
pktgens = ["ICTF", "CAIDA64", "CAIDA256", "CAIDA512", "CAIDA1024"]

tasks_ipsec_reboot = ["dpi-ipsec", "dpi-hs-ipsec"]
pktgens_ipsec = ["ICTF_IPSEC", "CAIDA64_IPSEC", "CAIDA256_IPSEC", "CAIDA512_IPSEC", "CAIDA1024_IPSEC"]

tasks_ipsec_sha_reboot = ["dpi-ipsec-sha", "dpi-hs-ipsec-sha"]
pktgens_ipsec_sha = ["ICTF_IPSEC_SHA", "CAIDA64_IPSEC_SHA", "CAIDA256_IPSEC_SHA", "CAIDA512_IPSEC_SHA", "CAIDA1024_IPSEC_SHA"]

# num_queues = [1, 2, 4, 8, 16]
num_queues = [1, 2, 4]
# num_queues = [1]


# num_rules = [1000, 5000, 10000, 20000, 30000, 33471]
num_rules = [10000, 20000, 30000, 33471]


# ps -ef | grep release
# sudo kill -9 ####
# TIMES = 10
TIMES = 10
# Remaining 6 times not running.


if __name__ == '__main__':
	now = datetime.datetime.now()
	throughput_res = open("./throughput-eva/throughput.txt_" + now.isoformat(), 'w')
	fail_cases = list()

	run_count = 0
	fail_count = 0

	for num_rule in num_rules:
		if num_rule > 10000:
			for task in tasks_reboot:
				for num_queue in num_queues:
					run_count += 1
					status = task_exec_reboot(task, pktgens, num_queue, num_rule, TIMES, throughput_res)
					if status == -1:
						fail_count += 1
						fail_cases.append(task + " " + num_queue)

			for task in tasks_ipsec_reboot:
				for num_queue in num_queues:
					run_count += 1
					status = task_exec_reboot(task, pktgens_ipsec, num_queue, num_rule, TIMES, throughput_res)
					if status == -1:
						fail_count += 1
						fail_cases.append(task + " " + num_queue)
		
		for task in tasks_ipsec_sha_reboot:
			for num_queue in num_queues:
				run_count += 1
				status = task_exec_reboot(task, pktgens_ipsec_sha, num_queue, num_rule, TIMES, throughput_res)
				if status == -1:
					fail_count += 1
					fail_cases.append(task + " " + num_queue)
		
	print colored(("success runs: %d/%d", (run_count - fail_count), run_count), 'green')
	throughput_res.close()
