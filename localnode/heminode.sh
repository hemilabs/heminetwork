#!/bin/sh
# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# tmux windows to monitor a Hemi stack running with the provided compose
NAME=hemi

source ./.env

NETWORK="hemi"
if [ "$NET" == "testnet" ]; then
    NETWORK="hemi-testnet"
fi

tmux start-server
tmux has-session -t $NAME 2>/dev/null
if [ "$?" -eq 1 ] ; then
	tmux new-session -d -s $NAME -n compose
	i=0
	tmux new-window -t $NAME -n stats
	i=$((i+1))
	tmux split-window -v -t $NAME:$i
	if [ "$PROFILE" == "L1" ] || [ "$PROFILE" == "full" ]; then
		tmux new-window -t $NAME -n bitcoin
		i=$((i+1))
		tmux new-window -t $NAME -n eth
		i=$((i+1))
		tmux split-window -v -t $NAME:$i
	fi
	if [ "$PROFILE" == "hemi" ] || [ "$PROFILE" == "full" ]; then
		tmux new-window -t $NAME -n L2
		i=$((i+1))
		tmux split-window -v -t $NAME:$i
		tmux split-window -h -t $NAME:$i.0
	fi
	if [ "$PROFILE" == "hemi" ] || [ "$PROFILE" == "hemi-min" ] || [ "$PROFILE" == "full" ]; then
		tmux new-window -t $NAME -n l2-nodes
		i=$((i+1))
		tmux split-window -v -t $NAME:$i
		tmux split-window -h -t $NAME:$i.0
	fi

	i=0
	i=$((i+1))
	tmux send-keys -t $NAME:$i.0 "docker stats" C-m
	tmux send-keys -t $NAME:$i.1 "while true; do df -h; sleep 30; done" C-m
	i=$((i+1))

	if [ "$PROFILE" == "L1" ] || [ "$PROFILE" == "full" ]; then
		tmux send-keys -t $NAME:$i "while true; do docker logs -f $NETWORK-stack-bitcoind-1; echo 'NOT UP!!'; sleep 30; done" C-m
		i=$((i+1))
		tmux send-keys -t $NAME:$i.0 "while true; do docker logs -f $NETWORK-stack-prysm-1; echo 'NOT UP!!'; sleep 30; done" C-m
		tmux send-keys -t $NAME:$i.1 "while true; do docker logs -f $NETWORK-stack-geth-l1-1; echo 'NOT UP!!'; sleep 30; done" C-m
		i=$((i+1))
	fi
	if [ "$PROFILE" == "hemi" ] || [ "$PROFILE" == "full" ]; then
		tmux send-keys -t $NAME:$i.0 "while true; do docker logs -f $NETWORK-stack-bfgd-1; echo 'NOT UP!!'; sleep 30; done" C-m
		tmux send-keys -t $NAME:$i.1 "while true; do docker logs -f $NETWORK-stack-bfgd-postgres-1; echo 'NOT UP!!'; sleep 30; done" C-m
		tmux send-keys -t $NAME:$i.2 "while true; do docker logs -f $NETWORK-stack-electrs-1; echo 'NOT UP!!'; sleep 30; done" C-m
		i=$((i+1))
	fi
	if [ "$PROFILE" == "hemi" ] || [ "$PROFILE" == "hemi-min" ] || [ "$PROFILE" == "full" ]; then
		tmux send-keys -t $NAME:$i.1 "while true; do docker logs -f $NETWORK-stack-op-node-1; echo 'NOT UP!!'; sleep 30; done" C-m
		tmux send-keys -t $NAME:$i.2 "while true; do docker logs -f $NETWORK-stack-op-geth-l2-1; echo 'NOT UP!!'; sleep 30; done" C-m
		i=$((i+1))
	fi
	tmux select-window -t $NAME:0
fi

tmux set-option -t $NAME set-titles on
tmux set-option -t $NAME set-titles-string "#S"
tmux attach-session -d -t $NAME
