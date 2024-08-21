#! /bin/bash

set -ev

curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_pause","params":[],"id":4}'  http://op-conductor:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_pause","params":[],"id":4}'  http://op-conductor-2:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_pause","params":[],"id":4}'  http://op-conductor-3:8547
curl -X POST -H "Content-Type: application/json" --data  "{\"jsonrpc\":\"2.0\",\"method\":\"admin_stopSequencer\",\"params\":[],\"id\":3}"  http://op-node:8547


curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"optimism_syncStatus","params":[],"id":1}'  http://op-node:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_addServerAsVoter","params":["op-conductor-2", "op-conductor-2:50051"],"id":4}'  http://op-conductor:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_addServerAsVoter","params":["op-conductor-3", "op-conductor-3:50052"],"id":4}'  http://op-conductor:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_resume","params":[],"id":4}'  http://op-conductor:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_resume","params":[],"id":4}'  http://op-conductor-2:8547
curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"conductor_resume","params":[],"id":4}'  http://op-conductor-3:8547

unsafe_head=$(curl -X POST -H "Content-Type: application/json" --data  '{"jsonrpc":"2.0","method":"optimism_syncStatus","params":[],"id":2}'  http://op-node:8547 | jq '.result.unsafe_l2.hash' )
echo "unsafe_head=$unsafe_head"
curl -X POST -H "Content-Type: application/json" --data  "{\"jsonrpc\":\"2.0\",\"method\":\"admin_startSequencer\",\"params\":[$unsafe_head],\"id\":3}"  http://op-node:8547
