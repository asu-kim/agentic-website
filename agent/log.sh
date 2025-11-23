#!/bin/bash 
# Use this script to log agent.py's output and execution latency. 

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
DIR="$ROOT/agent/log"
LOG="$DIR/log_$@.txt"
start=$(date +%s%N)

echo $0 $@ | tee "$LOG"

python "$@" 2>&1 | tee -a "$LOG"

end=$(date +%s%N)
latency_ms=$(( (end - start) / 1000000 ))
echo "----" | tee -a "$LOG"
echo "Execution latency: ${latency_ms} ms" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "log saved: $LOG"
