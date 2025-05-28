#! /bin/bash

set -evx

IFS=',' read -ra conductor_rpcs <<< "$OPCONDUCTOR_RPCS"
IFS=',' read -ra conductor_rafts <<< "$OPCONDUCTOR_RAFT_VOTERS"
IFS=',' read -ra opnode_rpcs <<< "$OPNODE_RPCS"
opnode_rpc=

# find the leader
for i in "${!conductor_rpcs[@]}"; do
  is_leader=$(curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_leader","params":[],"id":4}' "${conductor_rpcs[$i]}" | jq '.result')
  if [ "$is_leader" = 'true' ]; then
    opnode_rpc=${opnode_rpcs[$i]}
  fi
done


if [ "$opnode_rpc" = '' ]; then 
  echo "could not find leader, aborting"
  exit 1
fi

# pause each conductor so we can modify state
for rpc in "${conductor_rpcs[@]}"; do
  curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_pause","params":[],"id":4}' $rpc
done

for rpc in "${opnode_rpcs[@]}"; do
  curl -X POST -H "Content-Type: application/json" --data "{\"jsonrpc\":\"2.0\",\"method\":\"admin_stopSequencer\",\"params\":[],\"id\":3}" $rpc
done


# for each raft port in op-conductor, add as a voter.  this may error when adding self as a voter with the leader, but that's ok, the others should succeed
for raft in "${conductor_rafts[@]}"; do
    curl -X POST -H "Content-Type: application/json" --data  "{\"jsonrpc\":\"2.0\",\"method\":\"conductor_addServerAsVoter\",\"params\":[\"$raft\", \"$raft\"],\"id\":4}"  ${conductor_rpcs[0]}
done

# resume the conductors
for rpc in "${conductor_rpcs[@]}"; do
  curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_resume","params":[],"id":4}' $rpc
done

# restart the sequencer using the unsafe head from the leader's sync status
unsafe_head=$(curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"optimism_syncStatus","params":[],"id":2}'  $opnode_rpc | jq '.result.unsafe_l2.hash' )
echo "unsafe_head=$unsafe_head"
curl -X POST -H "Content-Type: application/json" --data  "{\"jsonrpc\":\"2.0\",\"method\":\"admin_startSequencer\",\"params\":[$unsafe_head],\"id\":3}"  $opnode_rpc
