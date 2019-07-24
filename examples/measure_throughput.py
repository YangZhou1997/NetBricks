import os

CmdNetBricks = {
	'start': './run_real.sh {task} 2>/dev/null &',
	'kill': 'sudo pkill "./run_real.sh" 2>/dev/null'
}

CmdPktgen = {
	'start': 'ssh yangz ./run_real.sh {task} 2>/dev/null &',
	'kill': 'sudo pkill "./run_real.sh" 2>/dev/null'
}

if __name__ == '__main__':
