import os
import time
from termcolor import colored
import datetime

CmdNetBricks = {
	'start': './run_real.sh {task} {num_queue} 2>/dev/null &',
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
	else:
		return task

def task_exec_reboot(task, pktgen_types, num_queue, repeat_num, throughput_res):
	# repeat the booting until succeeding
	# sometimes, failed dpdk application can reclaim hugepage.
	for i in range(repeat_num):
		for pktgen_type in pktgen_types:	
			fail_count_inner = 0
			while(1):
				print "start task %s" % (task,)
				os.system(CmdNetBricks['start'].format(task=task, num_queue=num_queue))
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
				throughput_res.write(task + "," + pktgen_type + "," + str(num_queue) + "," + str(throughput_val) + "," + str(avg_latency_val) + "," + str(tail_latency_val) + "\n")
				throughput_res.flush()
				
				os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
				time.sleep(5) # wait for the port being restored.

				break

	return 0


def task_exec(task, pktgen_types, num_queue, repeat_num, throughput_res):
	# repeat the booting until succeeding
	fail_count_inner = 0
	test_pktgen = pktgen_types[0]
	# sometimes, failed dpdk application can reclaim hugepage.
	while(1):
		print "start task %s" % (task,)
		os.system(CmdNetBricks['start'].format(task=task, num_queue=num_queue))
		time.sleep(5) # wait for task gets actually started
	
		print "start pktgen %s" % (test_pktgen,)
		pktgen_results = os.popen(CmdPktgen['start'].format(type=test_pktgen)).read()
		print "end pktgen %s" % (test_pktgen,)

		print pktgen_results
		start_index = pktgen_results.find(start_string) + len(start_string) 
		# this task executes error. 
		if start_index == -1:
			print colored("%s %s %s fails" % (task, test_pktgen, num_queue), 'red')
			fail_count_inner += 1
			os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
			time.sleep(5) # wait for the port being restored.
			continue
		end_index = pktgen_results.find(end_string, start_index)
		if end_index == -1:
			print colored("%s %s %s fails" % (task, test_pktgen, num_queue), 'red')
			os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
			time.sleep(5) # wait for the port being restored.
			fail_count_inner += 1
			continue
		
		if fail_count_inner > 5:
			return -1
		else:
			break

	for i in range(repeat_num):
		for pktgen_type in pktgen_types:
			print "start pktgen %s" % (pktgen_type,)
			pktgen_results = os.popen(CmdPktgen['start'].format(type=pktgen_type)).read()
			print "end pktgen %s" % (pktgen_type,)

			print pktgen_results
			start_index = pktgen_results.find(start_string) + len(start_string) 
			end_index = pktgen_results.find(end_string, start_index)

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
			throughput_res.write(task + "," + pktgen_type + "," + str(num_queue) + "," + str(throughput_val) + "," + str(avg_latency_val) + "," + str(tail_latency_val) + "\n")
			throughput_res.flush()

	os.system(CmdNetBricks['kill'].format(task=kill_keyword(task)))
	time.sleep(5) # wait for the port being restored.

	return 0

tasks_ipsec_nonreboot = ["lpm-ipsec-sha", "maglev-ipsec-sha"]
tasks_ipsec_reboot = ["dpi-ipsec-sha", "acl-fw-ipsec-sha", "monitoring-ipsec-sha", "nat-tcp-v4-ipsec-sha"]
pktgens_ipsec = ["ICTF_IPSEC_SHA", "CAIDA64_IPSEC_SHA", "CAIDA256_IPSEC_SHA", "CAIDA512_IPSEC_SHA", "CAIDA1024_IPSEC_SHA"]
pktgens_ipsec_acl = ["ICTF_IPSEC_ACL_SHA", "CAIDA64_IPSEC_ACL_SHA", "CAIDA256_IPSEC_ACL_SHA", "CAIDA512_IPSEC_ACL_SHA", "CAIDA1024_IPSEC_ACL_SHA"]

num_queues = [1, 2, 4]
# num_queues = [1]

# ps -ef | grep release
# sudo kill -9 ####
TIMES = 1

if __name__ == '__main__':
	now = datetime.datetime.now()
	throughput_res = open("./throughput-eva/throughput.txt_" + now.isoformat(), 'w')
	fail_cases = list()

	run_count = 0
	fail_count = 0

	for task in tasks_ipsec_reboot:
		for num_queue in num_queues:
			run_count += 1
			if task == "acl-fw-ipsec-sha":
				status = task_exec_reboot(task, pktgens_ipsec_acl, num_queue, TIMES, throughput_res)
			else:
				status = task_exec_reboot(task, pktgens_ipsec, num_queue, TIMES, throughput_res)
			if status == -1:
				fail_count += 1
				fail_cases.append(task + " " + num_queue)

	for task in tasks_ipsec_nonreboot:
		for num_queue in num_queues:
			run_count += 1
			status = task_exec(task, pktgens_ipsec, num_queue, TIMES, throughput_res)
			if status == -1:
				fail_count += 1
				fail_cases.append(task + " " + num_queue)
	
	print colored(("success runs: %d/%d", (run_count - fail_count), run_count), 'green')
	throughput_res.close()
