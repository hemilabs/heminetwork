#!/bin/sh

# Windows to monitor a fully hemi stack running with the provided compose
NAME=hemi

tmux start-server
tmux has-session -t $NAME 2>/dev/null
if [ "$?" -eq 1 ] ; then
    tmux new-session -d -s $NAME -n compose
	tmux new-window -t $NAME -n stats
	tmux new-window -t $NAME -n disk
	tmux new-window -t $NAME -n bitcoin
    tmux split-window -v -t $NAME:3
    tmux new-window -t $NAME -n l1
    tmux split-window -v -t $NAME:4
    tmux new-window -t $NAME -n l2
    tmux split-window -v -t $NAME:5
	tmux split-window -h -t $NAME:5.0
	tmux split-window -h -t $NAME:5.2
    tmux new-window -t $NAME -n l2-op-geth

	tmux send-keys -t $NAME:1 "docker stats" C-m
	tmux send-keys -t $NAME:2 "while true; do df -h; sleep 30; done" C-m

	# bitcoin
    tmux send-keys -t $NAME:3.0 "docker logs -f hemi-network-stack-bitcoind-1" C-m
    tmux send-keys -t $NAME:3.1 "docker logs -f hemi-network-stack-electrs-1" C-m
	# L1
    tmux send-keys -t $NAME:4.0 "docker logs -f hemi-network-stack-prysm-1" C-m
    tmux send-keys -t $NAME:4.1 "docker logs -f hemi-network-stack-geth-l1-1" C-m
	# L2
	tmux send-keys -t $NAME:5.0 "docker logs -f hemi-network-stack-bssd-1" C-m
	tmux send-keys -t $NAME:5.1 "docker logs -f hemi-network-stack-op-node-1" C-m
	tmux send-keys -t $NAME:5.2 "docker logs -f hemi-network-stack-bfgd-1" C-m
	tmux send-keys -t $NAME:5.3 "docker logs -f hemi-network-stack-bfgd-postgres-1" C-m
	tmux send-keys -t $NAME:6 "docker logs -f hemi-network-stack-op-geth-l2-1" C-m

    tmux select-window -t $NAME:0
fi

tmux set-option -t $NAME set-titles on
tmux set-option -t $NAME set-titles-string "#S"
tmux attach-session -d -t $NAME
