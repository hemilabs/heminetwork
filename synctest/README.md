# synctest

Synctest is a package that allows a user to test when a node is synced (or not).
Synctest considers two nodes: an *experimental* node and a *control* node.


The experimental node is the one that you are syncing.  The control node is 
the node you're comparing the experimental node _against_. The control node
should be a healthy, synced node.

you may run synctest like so:


```shell
go run ./...
```

The following environment variables are used:

```
# the endpoint for the healthy op-geth you are testing against, 
# ex. hemi public rpc 
SYNCTESTER_CONTROL_OP_GETH_ENDPOINT"

# the endpoint for the op-geth you are testing
SYNCTESTER_EXPERIMENTAL_OP_GETH_ENDPOINT

# the tbc health endpoint for op-geth you are testing
SYNCTESTER_EXPERIMENTAL_OP_GETH_TBC_HEALTH_ENDPOINT

# (optional) the slack oauth token used to send notifications
SYNCTESTER_SLACK_OAUTH_TOKEN

# (optional) the slack channel id that you want to send notifications to
SYNCTESTER_SLACK_CHANNEL

# (optional) the slack url used for testing (i.e. mocking slack)
SYNCTESTER_SLACK_URL

# the network you're testing (ex. testnet), you may set this to any value,
# it's for notification clarity
SYNCTESTER_NETWORK

# the syncmode you're testing (ex. snap), you may set this to any value,
# it's for notification clarity
SYNCTESTER_SYNCMODE


# (optional, default 30 minutes) how many seconds there should be between each
# notification
SYNCTESTER_NOTIFY_BY_SECONDS

# (optional) when set to "true", this will ignore pulling from docker logs
# for notifications
SYNCTESTER_SKIP_DOCKER_LOGS

# (optional) the log level for the synctester program, defaults to INFO
SYNCTESTER_LOG_LEVEL
```

*Note:* if a slack variable is omitted, then synctest will
not send anything to slack 
