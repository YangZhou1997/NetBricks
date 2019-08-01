import matplotlib
matplotlib.use('Agg')
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import rcParams
from collections import defaultdict
import brewer2mpl

 # brewer2mpl.get_map args: set name  set type  number of colors
bmap = brewer2mpl.get_map('Paired', 'qualitative', 12)
colors = bmap.mpl_colors

params = {
    'axes.labelsize': 18,
    'font.size': 18,
    'legend.fontsize': 18,
    'xtick.labelsize': 18,
    'ytick.labelsize': 18,
    'text.usetex': False,
    'figure.figsize': [20, 8],
    'legend.loc': 'best'
}
rcParams.update(params)

all_tasks = ["acl-fw-ipsec", "dpi-ipsec", "lpm-ipsec", "maglev-ipsec", "monitoring-ipsec", "nat-tcp-v4-ipsec"]

tasks = ["acl-fw-ipsec", "dpi-ipsec", "lpm-ipsec", "maglev-ipsec", "nat-tcp-v4-ipsec"]
pktgen_types = ["ICTF_IPSEC", "CAIDA64_IPSEC", "CAIDA256_IPSEC", "CAIDA512_IPSEC", "CAIDA1024_IPSEC"]

tasks_mon = ["monitoring-ipsec"]
pktgen_types_mon = map(lambda x: "chunck%d_ipsec.dat" % (x,), range(1))

num_queues = ["1", "2", "3", "4", "5", "6"]

# per-task mem_val vector
mem_val = defaultdict(list)
mem_val_min = defaultdict(float)
mem_val_med = defaultdict(float)
mem_val_max = defaultdict(float)

utli_ratio = defaultdict(list)
utli_ratio_min = defaultdict(float)
utli_ratio_med = defaultdict(float)
utli_ratio_max = defaultdict(float)


# first load **all** files to the dict
def load(filePath):
    with open(filePath, 'r') as f:
        raw_entry = f.readline()
        while raw_entry:
            key_array = raw_entry.rstrip("\n").split(",")
            mem_array = map(lambda x: float(x), f.readline().strip("[").rstrip("]\n").split(","))
            max_mem = float(f.readline().rstrip("\n"))

            # print entry_array
            mem_val[key_array[0]].append(max_mem)
            utli_ratio[key_array[0]].append((max_mem - mem_array[-1]) / max_mem)

            raw_entry = f.readline()


# then process data to get graph drawing data
def process_draw_data():
    for task in all_tasks:
        mem_val_min[task] = np.percentile(mem_val[task], 5)
        mem_val_med[task] = np.median(mem_val[task])
        mem_val_max[task] = np.percentile(mem_val[task], 95)

        utli_ratio_min[task] = np.percentile(utli_ratio[task], 5)
        utli_ratio_med[task] = np.median(utli_ratio[task])
        utli_ratio_max[task] = np.percentile(utli_ratio[task], 95)

# next, get maxmem vector indexed by task
def get_draw_data_for_maxmem():
    mem_vec_min = list()
    mem_vec_med = list()
    mem_vec_max = list()
    for task in all_tasks:
        mem_vec_min.append(mem_val_min[task])
        mem_vec_med.append(mem_val_med[task])
        mem_vec_max.append(mem_val_max[task])
    return mem_vec_min, mem_vec_med, mem_vec_max

# next, get utli vector indexed by task
def get_draw_data_for_utli():
    utli_vec_min = list()
    utli_vec_med = list()
    utli_vec_max = list()
    for task in all_tasks:
        utli_vec_min.append(utli_ratio_min[task])
        utli_vec_med.append(utli_ratio_med[task])
        utli_vec_max.append(utli_ratio_max[task])
    return utli_vec_min, utli_vec_med, utli_vec_max


# finally, draw graph by passing pktgen vector (index vector), and multiple throughput vector
# def

if __name__ == '__main__':
    load("../memory-profiling/cgroup-log/memusage.txt_2019-07-31T17:55:00.036708")

    process_draw_data()

    N = len(all_tasks)
    ind = np.arange(N) * 10 + 10    # the x locations for the groups
    width = 3.0       # the width of the bars: can also be len(x) sequence

    t_vec_min, t_vec_med, t_vec_max = get_draw_data_for_maxmem()
    yerr = np.zeros((2, len(t_vec_min)))
    yerr[0, :] = np.array(t_vec_med) - np.array(t_vec_min)
    yerr[1, :] = np.array(t_vec_max) - np.array(t_vec_med)
    p1 = plt.bar(ind, t_vec_med, width, yerr=yerr, color=colors[0], edgecolor = 'k', ecolor='k', align="center")

    plt.legend([p1], ["Maximum memory usage (MB)"])
    plt.ylabel("Maximum memory usage (MB)")
    plt.xticks(ind, all_tasks)
    plt.savefig('../figures/maxmem.pdf')
    plt.clf()


    t_vec_min, t_vec_med, t_vec_max = get_draw_data_for_utli()
    yerr = np.zeros((2, len(t_vec_min)))
    yerr[0, :] = np.array(t_vec_med) - np.array(t_vec_min)
    yerr[1, :] = np.array(t_vec_max) - np.array(t_vec_med)
    p1 = plt.bar(ind, t_vec_med, width, yerr=yerr, color=colors[0], edgecolor = 'k', ecolor='k', align="center")

    plt.legend([p1], ["Memory wasting ratio"])
    plt.ylabel("Memory wasting ratio")
    plt.xticks(ind, all_tasks)
    plt.savefig('../figures/memratio.pdf')
    plt.clf()
