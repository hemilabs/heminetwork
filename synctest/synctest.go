// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
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
	networkMainnet  = "mainnet"
	networkTestnet  = "testnet"
	networkLocalnet = "localnet"
	syncmodeSnap    = "snap"
	syncmodeFull    = "full"
)

var (
	tbcFetchHealthRetryCount = 10
	loopDelay                = 5 * time.Second
	validNetworks            = []string{networkMainnet, networkTestnet, networkLocalnet}
	validSyncmodes           = []string{syncmodeSnap, syncmodeFull}
	errInvalidNetwork        = errors.New("invalid network")
	errInvalidSyncmode       = errors.New("invalid syncmode")
	log                      = loggo.GetLogger("synctest")
)

type config struct {
	ControlOpGethEndpoint               string        `env:"CONTROL_OP_GETH_ENDPOINT"`
	ExperimentalOpGethEndpoint          string        `env:"EXPERIMENTAL_OP_GETH_ENDPOINT"`
	ExperimentalOpGethTbcHealthEndpoint string        `env:"EXPERIMENTAL_OP_GETH_TBC_HEALTH_ENDPOINT"`
	SlackOauthToken                     string        `env:"SLACK_OAUTH_TOKEN"`
	SlackChannel                        string        `env:"SLACK_CHANNEL"`
	SlackURL                            string        `env:"SLACK_URL"`
	Network                             string        `env:"NETWORK"`
	Syncmode                            string        `env:"SYNCMODE"`
	NotifyBy                            time.Duration `env:"NOTIFY_BY"`
	SkipDockerLogs                      bool          `env:"SKIP_DOCKER_LOGS"`
	LogLevel                            string        `env:"LOG_LEVEL"`
}

func DefaultConfig() *config {
	return &config{
		NotifyBy: 30 * time.Minute,
	}
}

func configFromEnv() (*config, error) {
	c := DefaultConfig()
	envOpts := env.Options{Prefix: "SYNCTESTER_"}
	if err := env.ParseWithOptions(c, envOpts); err != nil {
		return nil, fmt.Errorf("could not parse env: %w", err)
	}

	if c.ControlOpGethEndpoint == "" {
		return nil, errors.New("control op-geth endpoint not set")
	}
	if c.ExperimentalOpGethEndpoint == "" {
		return nil, errors.New("experimental op-geth endpoint not set")
	}

	if c.ExperimentalOpGethTbcHealthEndpoint == "" {
		return nil, errors.New("op-geth tbc health endpoint not set")
	}

	if !slices.Contains(validNetworks, c.Network) {
		return nil, fmt.Errorf("%w: %s", errInvalidNetwork, c.Network)
	}
	if !slices.Contains(validSyncmodes, c.Syncmode) {
		return nil, fmt.Errorf("%w: %s", errInvalidSyncmode, c.Syncmode)
	}

	return c, nil
}

func waitForSync(ctx context.Context) error {
	c, err := configFromEnv()
	if err != nil {
		return err
	}

	if err := loggo.ConfigureLoggers(c.LogLevel); err != nil {
		return err
	}

	logLevel, _ := loggo.ParseLevel(c.LogLevel)
	if logLevel == loggo.UNSPECIFIED {
		logLevel = loggo.INFO
	}

	log.Infof("logLevel = %d, logLevel from env = %s", logLevel, c.LogLevel)

	log.Infof("starting sync testing with configured endpoints: control (%s), experimental(%s)", c.ControlOpGethEndpoint, c.ExperimentalOpGethEndpoint)

	lastNotifiedAt := time.Now().Add(-c.NotifyBy)
	lastSyncInfo := tbc.SyncInfo{}
	lastl2BlockNumber := uint64(0)

	for {
		shouldNotify := time.Since(lastNotifiedAt) >= c.NotifyBy
		if err := reportProgress(ctx, c, &lastSyncInfo, shouldNotify); err != nil {
			return err
		}

		if shouldNotify {
			lastNotifiedAt = time.Now()
		}

		// only check if l2 tips match
		matching, err := l2TipsMatch(ctx, c, &lastl2BlockNumber)
		if err != nil {
			log.Errorf("error checking if l2 tips match: %s", err)
		} else if matching {
			break
		}

		select {
		case <-time.After(loopDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func reportProgress(ctx context.Context, c *config, lastSyncInfo *tbc.SyncInfo, notify bool) error {
	var syncInfo tbc.SyncInfo
	for i := range tbcFetchHealthRetryCount {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ExperimentalOpGethTbcHealthEndpoint, nil)
		if err != nil {
			return fmt.Errorf("error creating new request: %w", err)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Warningf("error getting tbc health: %s", err)
			return nil
		}

		defer resp.Body.Close()

		if err := json.NewDecoder(resp.Body).Decode(&syncInfo); err != nil {
			return fmt.Errorf("decode tbc json: %w", err)
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

	l2Experiment, err := ethclient.Dial(c.ExperimentalOpGethEndpoint)
	if err != nil {
		log.Warningf("could not dial eth l2 experiment: %s\n", err)
		return nil
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

	dockerLogs := getLogsFromDocker(ctx)

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
		notifyHooks(ctx, c, &syncInfo)
	}

	return nil
}

func notifySlackSuccess(ctx context.Context, c *config, controlHash *common.Hash, experimentHash *common.Hash) {
	if c.SlackOauthToken == "" || c.SlackChannel == "" {
		return
	}

	var api *slack.Client
	if c.SlackURL == "" {
		api = slack.New(c.SlackOauthToken)
	} else {
		api = slack.New(c.SlackOauthToken, slack.OptionAPIURL(c.SlackURL))
	}

	msgOptions := []slack.MsgOption{
		slack.MsgOptionText(
			fmt.Sprintf("hashes match: network %s, syncmode %s, control %s == experiment %s", c.Network, c.Syncmode, controlHash.Hex(), experimentHash.Hex()),
			false,
		),
		slack.MsgOptionAsUser(true),
	}

	_, _, err := api.PostMessage(
		c.SlackChannel,
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

func notifySlackHook(ctx context.Context, c *config, syncInfo *tbc.SyncInfo, dockerLogs string) {
	if c.SlackOauthToken == "" || c.SlackChannel == "" {
		return
	}

	var api *slack.Client
	if c.SlackURL == "" {
		api = slack.New(c.SlackOauthToken)
	} else {
		api = slack.New(c.SlackOauthToken, slack.OptionAPIURL(c.SlackURL))
	}

	l2Experiment, err := ethclient.Dial(c.ExperimentalOpGethEndpoint)
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

	msgOptions := generateMsgOptions(ctx, c.Network, c.Syncmode, l2BlockMsg, syncInfo)

	_, _, err = api.PostMessage(
		c.SlackChannel,
		msgOptions...,
	)
	if err != nil {
		log.Warningf("error posting message to slack: %s", err)
	}

	if dockerLogs != "" {
		msgOptions := []slack.MsgOption{slack.MsgOptionBlocks(
			slack.NewHeaderBlock(
				slack.NewTextBlockObject("plain_text", fmt.Sprintf("Docker Logs (%s %s)", c.Network, c.Syncmode), false, false),
			),
			slack.NewMarkdownBlock("", fmt.Sprintf("```%s```", dockerLogs)),
		)}

		_, _, err = api.PostMessage(
			c.SlackChannel,
			msgOptions...,
		)
		if err != nil {
			log.Warningf("error posting markdown message to slack: %s", err)
		}
	}
}

func notifyHooks(ctx context.Context, c *config, syncInfo *tbc.SyncInfo) {
	// add hooks here for reporting progess to places outside of the test
	// itself (ex. slack)
	log.Tracef("notifying")
	var dockerLogs string
	if !c.SkipDockerLogs {
		dockerLogs = getLogsFromDocker(ctx)
	}
	notifySlackHook(ctx, c, syncInfo, dockerLogs)
}

func l2TipsMatch(ctx context.Context, c *config, lastl2BlockNumber *uint64) (bool, error) {
	l2Control, err := ethclient.Dial(c.ControlOpGethEndpoint)
	if err != nil {
		return false, fmt.Errorf("could not dial eth l2 control: %s", err)
	}

	l2Experiment, err := ethclient.Dial(c.ExperimentalOpGethEndpoint)
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
			notifySlackSuccess(ctx, c, &controlHash, &experimentHash)
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

// this portion is untested for now
func getLogsFromDocker(ctx context.Context) string {
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
			if strings.Contains(name, "op-geth") || strings.Contains(name, "op-node") {
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
