package main

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/juju/loggo"
	"nhooyr.io/websocket"
)

const logLevel = "INFO"

var log = loggo.GetLogger("mocktimism")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type bssWs struct {
	wg   sync.WaitGroup
	addr string
	conn *protocol.WSConn
}

// mocktimism is meant to be a temporary optimism mock that creates keystones
// at an interval, feel free to change to test.

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	c, _, err := websocket.Dial(ctx, os.Getenv("MOCKTIMISM_BSS_URL"), nil)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := c.Close(websocket.StatusNormalClosure, ""); err != nil {
			log.Errorf("error closing websocket: %s", err)
		}
	}()
	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       fillOutBytes("parentephash", 32),
		PrevKeystoneEPHash: fillOutBytes("prevkeystoneephash", 32),
		StateRoot:          fillOutBytes("stateroot", 32),
		EPHash:             fillOutBytes("ephash", 32),
	}

	go func() {
		for {
			cmd, _, response, err := bssapi.Read(ctx, bws.conn)
			if err != nil {
				return
			}

			log.Infof("received command %s\n", cmd)
			log.Infof("%v", spew.Sdump(response))
		}
	}()

	go func() {
		// create a new block every second, then view pop payouts and finalities

		firstL2Keystone := hemi.L2KeystoneAbbreviate(l2Keystone).Serialize()

		for {
			l2KeystoneRequest := bssapi.L2KeystoneRequest{
				L2Keystone: l2Keystone,
			}

			err = bssapi.Write(ctx, bws.conn, "someid", l2KeystoneRequest)
			if err != nil {
				log.Errorf("error: %s", err)
				return
			}

			l2Keystone.L1BlockNumber++
			l2Keystone.L2BlockNumber++

			time.Sleep(1 * time.Second)

			err = bssapi.Write(ctx, bws.conn, "someotherid", bssapi.PopPayoutsRequest{
				L2BlockForPayout: firstL2Keystone[:],
			})
			if err != nil {
				log.Errorf("error: %s", err)
				return
			}

			err = bssapi.Write(ctx, bws.conn, "someotheridz", bssapi.BTCFinalityByRecentKeystonesRequest{
				NumRecentKeystones: 100,
			})
			if err != nil {
				log.Errorf("error: %s", err)
				return
			}
		}
	}()

	time.Sleep(10 * time.Minute)
}

// fillOutBytes will take a string and return a slice of bytes
// with values from the string suffixed until a size with bytes '_'
func fillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, '_')
	}

	return result
}
