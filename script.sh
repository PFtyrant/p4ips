#!/bin/bash
sudo ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%cpu | head | grep tofino-model | awk '{print P4Zeek}' | xargs sudo kill -9 > /dev/null 2>&1
pps=10000
num=128

if [ "$3" != '' ];
then
    num=$3
    echo "num is $num"
fi

if [ "$4" != '' ];
then
    pps=$4
    echo "pps is $pps"
fi

if [ "$2" == 'yes' ];
then
    ./p4_build.sh ~/P4Zeek/P4Zeek.p4
fi

if [ $? -ne 0 ];
then
    exit
fi

echo [[[kill session]]]
tmux kill-session -t config

echo [[[new session]]]
tmux new-session -d -s config  # name is config

tmux select-window -t config:0

tmux send-keys -t config 'source set_sde.bash' C-m
# tmux send-keys -t config 'sudo $SDE_INSTALL/bin/dma_setup.sh' C-m
if [ $? -ne 0 ];
then
    exit
fi
tmux send-keys -t config 'bf_kdrv_mod_unload' C-m
# tmux send-keys -t config 'bf_kpkt_mod_unload' C-m
if [ $? -ne 0 ];
then
    exit
fi
tmux send-keys -t config 'bf_kdrv_mod_load $SDE_INSTALL' C-m
# tmux send-keys -t config 'bf_kpkt_mod_load $SDE_INSTALL' C-m
if [ $? -ne 0 ];
then
    exit
fi

# new add
# tmux send-keys -t config 'sudo ip link set enp6s0 up' C-m 
tmux send-keys -t config 'sudo ip link set enp4s0f1 up' C-m 


if [ $? == 0 ];
then
    tmux split-window -v -p 50 -t 0
    tmux send-keys -t 1 "cd ~/P4Zeek/" C-m
    tmux send-keys -t 1 "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE/build/bf-utils/third-party/bf-python" C-m
#    tmux send-keys -t 1 'export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/root/bf-sde-9.2.0/build/bf-drivers/src/.libs' C-m
    tmux send-keys -t 1 "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE/build/bf-utils/third-party/klish/.libs" C-m
    tmux send-keys -t 1 "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$SDE/install/lib" C-m
    tmux send-keys -t 1 "./P4Zeek_cp --install-dir $SDE/install --conf-file $SDE/install/share/p4/targets/tofino/P4Zeek.conf $num" C-m
fi

tmux select-pane -t 0 # back to index = 0
# tmux split-window -h -p 60 -t 0
tmux send-keys -t 0 "bfshell -f $HOME/P4Zeek/enter_bfshell.txt"
# tmux send-keys -t 1 'bfshell'
tmux select-pane -t 0
tmux split-window -h -p 30 -t 0
tmux send-keys -t 1 "ssh -o ServerAliveInterval=60 $1" C-m
tmux send-keys -t 1 "ulimit -n 65535" C-m
tmux send-keys -t 1 "sudo tcpreplay -i ens19 -p $pps -L $num ./pcap_file/15000_mac.pcap"
# tmux send-keys -t 1 "iperf -c 10.0.1.2 -p 9005 -n 3M -e -P $num"

tmux select-pane -t 2
tmux split-window -h -p 50 -t 2
tmux send-keys -t 3 "python $HOME/P4Zeek/send.py"
# tmux send-keys -t 3 "ssh -o ServerAliveInterval=60 P4-VM76" C-m
# tmux send-keys -t 3 "ulimit -n 65535" C-m
# tmux send-keys -t 3 "iperf -s -p 9005" C-m

tmux attach-session -t config
tmux select-window -t config:0


# tmux select-pane -t 1

