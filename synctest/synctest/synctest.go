// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package synctest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/juju/loggo/v2"
	"github.com/slack-go/slack"

	"github.com/hemilabs/heminetwork/v2/service/tbc"
)

// as of now, synctest gets its variables exclusively from the environment,
// there is no way to pass these as command args.  this works fine so YAGNI
const (
	controlOpGethEndpointEnv               = "SYNCTESTER_CONTROL_OP_GETH_ENDPOINT"
	experimentalOpGethEndpointEnv          = "SYNCTESTER_EXPERIMENTAL_OP_GETH_ENDPOINT"
	experimentalOpGethTbcHealthEndpointEnv = "SYNCTESTER_EXPERIMENTAL_OP_GETH_TBC_HEALTH_ENDPOINT"
	slackOauthTokenEnv                     = "SYNCTESTER_SLACK_OAUTH_TOKEN"
	slackChannelenv                        = "SYNCTESTER_SLACK_CHANNEL"
	slackURLEnv                            = "SYNCTESTER_SLACK_URL"
	networkEnv                             = "SYNCTESTER_NETWORK"
	syncmodeEnv                            = "SYNCTESTER_SYNCMODE"
	notifyByEnv                            = "SYNCTESTER_NOTIFY_BY_SECONDS"
	skipDockerLogsEnv                      = "SYNCTESTER_SKIP_DOCKER_LOGS"
	logLevelEnv                            = "SYNCTESTER_LOG_LEVEL"
)

var (
	tbcFetchHealthRetryCount = 10
	loopDelay                = 5 * time.Second
	log                      loggo.Logger
)

func init() {
	log = loggo.GetLogger("synctest")

	logLevel, _ := loggo.ParseLevel(os.Getenv(logLevelEnv))
	if logLevel == loggo.UNSPECIFIED {
		logLevel = loggo.INFO
	}

	log.Infof("logLevel = %d, logLevel from env = %s", logLevel, os.Getenv(logLevelEnv))

	log.SetLogLevel(logLevel)
}

func WaitForSync(ctx context.Context) error {
	return waitForSync(ctx)
}

func waitForSync(ctx context.Context) error {
	controlOpGethEndpoint := controlOpGethEndpointFromEnv()
	experimentalOpGethEndpoint := experimentalOpGethEndpointFromEnv()

	log.Infof("starting sync testing with configured endpoints: control (%s), experimental(%s)", controlOpGethEndpoint, experimentalOpGethEndpoint)

	lastNotifiedAt := time.Now().Add(-notifyByFromEnv())
	lastSyncInfo := tbc.SyncInfo{}
	lastl2BlockNumber := uint64(0)

	for {
		shouldNotify := time.Since(lastNotifiedAt) >= notifyByFromEnv()
		if err := reportProgress(ctx, &lastSyncInfo, shouldNotify); err != nil {
			return err
		}

		if shouldNotify {
			lastNotifiedAt = time.Now()
		}

		// only check if l2 tips match after tbc is synced
		if lastSyncInfo.Synced {
			matching, err := l2TipsMatch(ctx, &lastl2BlockNumber)
			if err != nil {
				return err
			}

			if matching {
				break
			}
		}

		select {
		case <-time.After(loopDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func reportProgress(ctx context.Context, lastSyncInfo *tbc.SyncInfo, notify bool) error {
	var syncInfo tbc.SyncInfo
	for i := range tbcFetchHealthRetryCount {
		resp, err := http.Get(fmt.Sprintf("%s", experimentalOpGethTbcHealthEndpointFromEnv()))
		if err != nil {
			log.Warningf("error getting tbc health: %s", err)
			return nil
		}

		defer resp.Body.Close()

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err) // should not happen
		}

		log.Tracef("tbc progress json: %v", string(b))

		if err := json.Unmarshal(b, &syncInfo); err != nil {
			log.Warningf("error unmarshaling tbc json %s: %s", string(b), err)
		} else {
			break
		}

		if i >= tbcFetchHealthRetryCount-1 {
			log.Warningf("could not retrieve TBC SyncInfo, skipping notification.")
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}

	experimentalOpGethEndpoint := experimentalOpGethEndpointFromEnv()

	l2Experiment, err := ethclient.Dial(experimentalOpGethEndpoint)
	if err != nil {
		log.Warningf("could not dial eth l2 experiment: %s\n", err)
		return nil
	}

	var experimentalBlock *types.Header

	if l2Experiment != nil {
		experimentalBlock, err = l2Experiment.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
		if err != nil {
			log.Warningf("error getting latest experiment block: %s\n", err)
			return nil
		}
	}

	l2BlockMsg := "L2 not started"

	if experimentalBlock != nil {
		l2BlockMsg = fmt.Sprintf("L2 Block: %s:%d", experimentalBlock.Hash().Hex(), experimentalBlock.Number)
	}

	dockerLogs := getLogsFromDocker(ctx, lastSyncInfo.Synced)

	log.Tracef(`
		sync progress:
		tx index %s:%d
		utxo index %s:%d
		keystone index %s:%d
		blockheader index %s:%d
		%s
		docker logs:
		%s`,
		syncInfo.Tx.Hash, syncInfo.Tx.Height,
		syncInfo.Utxo.Hash, syncInfo.Utxo.Height,
		syncInfo.Keystone.Hash, syncInfo.Keystone.Height,
		syncInfo.BlockHeader.Hash, syncInfo.BlockHeader.Height,
		l2BlockMsg, dockerLogs,
	)

	*lastSyncInfo = syncInfo

	if notify {
		notifyHooks(ctx, &syncInfo)
	}

	return nil
}

func notifyByFromEnv() time.Duration {
	secondsStr := os.Getenv(notifyByEnv)
	if secondsStr == "" {
		return time.Duration(30) * time.Minute
	}

	i, err := strconv.Atoi(secondsStr)
	if err != nil {
		panic(err)
	}

	return time.Duration(i) * time.Second
}

func notifySlackSuccess(ctx context.Context, controlHash *common.Hash, experimentHash *common.Hash) {
	slackToken := os.Getenv(slackOauthTokenEnv)
	slackChannel := os.Getenv(slackChannelenv)

	if slackToken == "" || slackChannel == "" {
		return
	}

	var api *slack.Client
	slackUrl := os.Getenv(slackURLEnv)
	if slackUrl == "" {
		api = slack.New(slackToken)
	} else {
		api = slack.New(slackToken, slack.OptionAPIURL(slackUrl))
	}

	msgOptions := []slack.MsgOption{
		slack.MsgOptionText(
			fmt.Sprintf("hashes match: network %s, syncmode %s, control %s == experiment %s", networkFromEnv(), syncmodeFromEnv(), controlHash.Hex(), experimentHash.Hex()),
			false,
		),
		slack.MsgOptionAsUser(true),
	}

	_, _, err := api.PostMessage(
		slackChannel,
		msgOptions...,
	)
	if err != nil {
		log.Warningf("error posting message to slack: %s", err)
	}
}

func generateMsgOptions(ctx context.Context, network string, syncmode string, l2BlockMsg string, syncInfo *tbc.SyncInfo) []slack.MsgOption {
	var color string
	switch network {
	case "mainnet":
		switch syncmode {
		case "snap":
			color = "#ff0000"
		case "full":
			color = "#ff6f00"
		}
	case "testnet":
		switch syncmode {
		case "snap":
			color = "#00FFFF"
		case "full":
			color = "#00ff48"
		}
	}

	blocks := []slack.Block{
		slack.NewSectionBlock(
			nil,
			[]*slack.TextBlockObject{
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Network:*\n%s", network), false, false),
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*Sync Mode:*\n%s", syncmode), false, false),
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*L2 Block:*\n%s", l2BlockMsg), false, false),
			},
			nil,
		),
		slack.NewDividerBlock(),
		slack.NewSectionBlock(
			nil,
			[]*slack.TextBlockObject{
				slack.NewTextBlockObject("mrkdwn",
					fmt.Sprintf("*Block Header Index:*\n`%s` at height %d",
						syncInfo.BlockHeader.Hash, syncInfo.BlockHeader.Height),
					false, false),
				slack.NewTextBlockObject("mrkdwn",
					fmt.Sprintf("*UTXO Index:*\n`%s` at height %d",
						syncInfo.Utxo.Hash, syncInfo.Utxo.Height),
					false, false),
				slack.NewTextBlockObject("mrkdwn",
					fmt.Sprintf("*Tx Index:*\n`%s` at height %d",
						syncInfo.Tx.Hash, syncInfo.Tx.Height),
					false, false),
				slack.NewTextBlockObject("mrkdwn",
					fmt.Sprintf("*Keystone Index:*\n`%s` at height %d",
						syncInfo.Keystone.Hash, syncInfo.Keystone.Height),
					false, false),
			},
			nil,
		),
	}

	attachment := slack.Attachment{
		Color: color,
		Blocks: slack.Blocks{
			BlockSet: blocks,
		},
	}

	msgOptions := []slack.MsgOption{
		slack.MsgOptionAttachments(attachment),
		slack.MsgOptionAsUser(true),
	}

	return msgOptions
}

func notifySlackHook(ctx context.Context, syncInfo *tbc.SyncInfo, dockerLogs string) {
	slackToken := os.Getenv(slackOauthTokenEnv)
	slackChannel := os.Getenv(slackChannelenv)

	if slackToken == "" || slackChannel == "" {
		return
	}

	var api *slack.Client
	slackUrl := os.Getenv(slackURLEnv)
	if slackUrl == "" {
		api = slack.New(slackToken)
	} else {
		api = slack.New(slackToken, slack.OptionAPIURL(slackUrl))
	}

	experimentalOpGethEndpoint := experimentalOpGethEndpointFromEnv()

	l2Experiment, err := ethclient.Dial(experimentalOpGethEndpoint)
	if err != nil {
		log.Warningf("could not dial eth l2 experiment: %s\n", err)
	}

	var experimentalBlock *types.Header

	if l2Experiment != nil {
		experimentalBlock, err = l2Experiment.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
		if err != nil {
			log.Warningf("error getting latest experiment block: %s\n", err)
		}
	}

	l2BlockMsg := "L2 not started"

	if experimentalBlock != nil {
		l2BlockMsg = fmt.Sprintf("L2 Block: %s:%d", experimentalBlock.Hash().Hex(), experimentalBlock.Number)
	}

	network := networkFromEnv()
	syncmode := syncmodeFromEnv()

	msgOptions := generateMsgOptions(ctx, network, syncmode, l2BlockMsg, syncInfo)

	_, _, err = api.PostMessage(
		slackChannel,
		msgOptions...,
	)
	if err != nil {
		log.Warningf("error posting message to slack: %s", err)
	}

	if dockerLogs != "" {
		msgOptions := []slack.MsgOption{slack.MsgOptionBlocks(
			slack.NewHeaderBlock(
				slack.NewTextBlockObject("plain_text", fmt.Sprintf("Docker Logs (%s %s)", networkFromEnv(), syncmodeFromEnv()), false, false),
			),
			slack.NewMarkdownBlock("", fmt.Sprintf("```%s```", dockerLogs)),
		)}

		_, _, err = api.PostMessage(
			slackChannel,
			msgOptions...,
		)
		if err != nil {
			log.Warningf("error posting markdown message to slack: %s", err)
		}
	}
}

func notifyHooks(ctx context.Context, syncInfo *tbc.SyncInfo) {
	// add hooks here for reporting progess to places outside of the test
	// itself (ex. slack)
	log.Tracef("notifying")
	var dockerLogs string
	if !skipDockerLogs() {
		dockerLogs = getLogsFromDocker(ctx, syncInfo.Synced)
	}
	notifySlackHook(ctx, syncInfo, dockerLogs)
}

func l2TipsMatch(ctx context.Context, lastl2BlockNumber *uint64) (bool, error) {
	controlOpGethEndpoint := controlOpGethEndpointFromEnv()
	experimentalOpGethEndpoint := experimentalOpGethEndpointFromEnv()

	l2Control, err := ethclient.Dial(controlOpGethEndpoint)
	if err != nil {
		return false, fmt.Errorf("could not dial eth l2 control: %s", err)
	}

	l2Experiment, err := ethclient.Dial(experimentalOpGethEndpoint)
	if err != nil {
		return false, fmt.Errorf("could not dial eth l2 experiment: %s", err)
	}

	controlBlock, err := l2Control.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if err != nil {
		return false, fmt.Errorf("error getting latest control block: %s", err)
	}

	experimentalBlock, err := l2Experiment.HeaderByNumber(ctx, big.NewInt(int64(rpc.LatestBlockNumber)))
	if err != nil {
		return false, fmt.Errorf("error getting latest experiment block: %s", err)
	}

	*lastl2BlockNumber = experimentalBlock.Number.Uint64()

	log.Tracef(
		"comparing hashes for latest blocks (control) %s ?= (experiment) %s", controlBlock.Hash().Hex(), experimentalBlock.Hash().Hex())

	controlHash := controlBlock.Hash()
	experimentHash := experimentalBlock.Hash()

	syncProgress, err := l2Experiment.SyncProgress(ctx)
	if err != nil {
		return false, fmt.Errorf("could not get sync progress: %s", err)
	}

	// if sync progress is nil, then we're synced according to op-geth
	if syncProgress != nil {
		return false, nil
	}

	// check if we're in 5 blocks from the tip
	for range 5 {
		matching := controlHash.Hex() == experimentHash.Hex()

		if matching {
			notifySlackSuccess(ctx, &controlHash, &experimentHash)
			return true, nil
		}

		controlBlock, err = l2Control.HeaderByHash(ctx, controlBlock.ParentHash)
		if err != nil {
			return false, fmt.Errorf("error getting control block parent by hash: %s", err)
		}

		controlHash = controlBlock.Hash()
	}

	return false, nil
}

func controlOpGethEndpointFromEnv() string {
	return fromEnvOrFail(controlOpGethEndpointEnv)
}

func experimentalOpGethEndpointFromEnv() string {
	return fromEnvOrFail(experimentalOpGethEndpointEnv)
}

func experimentalOpGethTbcHealthEndpointFromEnv() string {
	return fromEnvOrFail(experimentalOpGethTbcHealthEndpointEnv)
}

func networkFromEnv() string {
	n := os.Getenv(networkEnv)
	if n == "" {
		return "<not specified>"
	}
	return n
}

func syncmodeFromEnv() string {
	n := os.Getenv(syncmodeEnv)
	if n == "" {
		return "<not specified>"
	}
	return n
}

// this portion is untested for now
func getLogsFromDocker(ctx context.Context, reportNode bool) string {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Warningf("error creating docker client: %s", err)
		return ""
	}

	containers, err := dockerClient.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		log.Warningf("error getting a list of running containers: %s", err)
		return ""
	}

	var logs string
	for _, c := range containers {
		var isValidContainer bool
		for _, name := range c.Names {
			if strings.Contains(name, "op-geth") || (reportNode && strings.Contains(name, "op-node")) {
				isValidContainer = true
				break
			}
		}
		if !isValidContainer {
			continue
		}
		reader, err := dockerClient.ContainerLogs(ctx, c.ID, container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
		})
		if err != nil {
			log.Warningf("could not get logs from running container %s: %s", c.ID, err)
			return ""
		}

		b, err := io.ReadAll(reader)
		if err != nil {
			log.Warningf("could not read logs: %s", err)
			return ""
		}

		reader.Close()

		const byteCount = 1000
		if len(b) >= byteCount {
			b = b[len(b)-byteCount:]
		}
		logs = fmt.Sprintf("%s\n%s", logs, string(b))
	}
	return logs
}

func fromEnvOrFail(varName string) string {
	val := os.Getenv(varName)
	if val == "" {
		panic(fmt.Sprintf("%s not set", varName))
	}

	return val
}

func skipDockerLogs() bool {
	return os.Getenv(skipDockerLogsEnv) == "true"
}
