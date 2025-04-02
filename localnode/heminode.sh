#!/bin/sh
# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# tmux windows to monitor a full Hemi stack running with the provided compose
NAME=hemi

NETWORK="hemi"
if [ "$1" != "" ]; then
    NETWORK="hemi-$1"
fi

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
	tmux send-keys -t $NAME:3.0 "while true; do docker logs -f $NETWORK-stack-bitcoind-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:3.1 "while true; do docker logs -f $NETWORK-stack-electrs-1; echo 'NOT UP!!'; sleep 30; done" C-m
	# L1
	tmux send-keys -t $NAME:4.0 "while true; do docker logs -f $NETWORK-stack-prysm-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:4.1 "while true; do docker logs -f $NETWORK-stack-geth-l1-1; echo 'NOT UP!!'; sleep 30; done" C-m
	# L2
	tmux send-keys -t $NAME:5.0 "while true; do docker logs -f $NETWORK-stack-bssd-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:5.1 "while true; do docker logs -f $NETWORK-stack-op-node-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:5.2 "while true; do docker logs -f $NETWORK-stack-bfgd-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:5.3 "while true; do docker logs -f $NETWORK-stack-bfgd-postgres-1; echo 'NOT UP!!'; sleep 30; done" C-m
	tmux send-keys -t $NAME:6 "while true; do docker logs -f $NETWORK-stack-op-geth-l2-1; echo 'NOT UP!!'; sleep 30; done" C-m

	tmux select-window -t $NAME:0
fi

tmux set-option -t $NAME set-titles on
tmux set-option -t $NAME set-titles-string "#S"
tmux attach-session -d -t $NAME
