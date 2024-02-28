package bdf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo"
)

// XXX add tests

var (
	log = loggo.GetLogger("bdf")
	dfm sync.RWMutex
)

const (
	DefaultNet     = "testnet"
	HeightFilename = "height"
)

var (
	DefaultDataDir = filepath.Join(DefaultNet, "bitcoin_headers")
)

type LastHeight struct {
	Height int    `json:"height"`
	Hash   string `json:"hash"`
}

type Header struct {
	Height int    `json:"height"`
	Header string `json:"header"`
}

func ReadHeight(filename string) (int, string, error) {
	dfm.RLock()
	defer dfm.RUnlock()

	f, err := os.Open(filename)
	if err != nil {
		return 0, "", err
	}
	d := json.NewDecoder(f)
	var lh LastHeight
	err = d.Decode(&lh)
	if err != nil {
		f.Close()
		return 0, "", err
	}
	err = f.Close()
	if err != nil {
		return 0, "", err
	}
	return lh.Height, lh.Hash, nil
}

func ReadHeader(filename string) (*wire.BlockHeader, int, error) {
	dfm.RLock()
	defer dfm.RUnlock()

	f, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	d := json.NewDecoder(f)
	var h Header
	err = d.Decode(&h)
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	err = f.Close()
	if err != nil {
		return nil, 0, err
	}
	dh, err := hex.DecodeString(h.Header)
	if err != nil {
		return nil, 0, err
	}
	if len(dh) != 80 {
		return nil, 0, err
	}
	var wbh wire.BlockHeader
	err = wbh.Deserialize(bytes.NewReader(dh))
	if err != nil {
		return nil, 0, err
	}
	return &wbh, h.Height, nil
}

func Header2Bytes(wbh *wire.BlockHeader) ([]byte, error) {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func Header2ExactBytes(wbh *wire.BlockHeader, header *[80]byte) error {
	b, err := Header2Bytes(wbh)
	if err != nil {
		return err
	}
	if len(b) != 80 {
		return fmt.Errorf("should not happen length %v", len(b))
	}
	copy(header[:], b)
	return nil
}

func Header2Hex(wbh *wire.BlockHeader) (string, error) {
	b, err := Header2Bytes(wbh)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Hex2Header(header string) (*wire.BlockHeader, error) {
	blockHeader, err := hex.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("DecodeString: %v", err)
	}
	var bh wire.BlockHeader
	err = bh.Deserialize(bytes.NewReader(blockHeader))
	if err != nil {
		return nil, fmt.Errorf("Deserialize: %v", err)
	}
	return &bh, nil
}

// writeHeight reads the latest height and overwrites it if the provided height
// is higher. Poor mans for resolution :-)
func writeHeight(height int, hash, dir string) error {
	log.Tracef("WriteHeight %v %v", height, hash)
	defer log.Tracef("WriteHeight exit")

	var lh LastHeight
	filename := filepath.Join(dir, HeightFilename)
	f, err := os.Open(filename)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// do nothing
			defer f.Close()
		} else {
			return fmt.Errorf("Open: %v", err)
		}
	} else {
		defer f.Close()
		d := json.NewDecoder(f)
		err = d.Decode(&lh)
		if err != nil {
			return fmt.Errorf("%v corrupt: %v", filename, err)
		}
	}
	if lh.Height > height {
		log.Tracef("not overwriting height: %v > %v", lh.Height, height)
		return nil
	}
	fw, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("OpenFile: %v", err)
	}
	e := json.NewEncoder(fw)
	lh.Height = height
	lh.Hash = hash
	err = e.Encode(lh)
	if err != nil {
		return fmt.Errorf("Encode: %v", err)
	}
	return fw.Close()
}

// writeHeader writes a header. We pass the hash to verify that the header is correct.
func writeHeader(height int, hash, header, dir string) error {
	filename := filepath.Join(dir, hash)
	overwrite := false
	if !overwrite {
		_, err := os.Stat(filename)
		if err == nil {
			return fmt.Errorf("caught up at height: %v", height)
		}
	}
	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("Create: %v", err)
	}
	e := json.NewEncoder(f)
	err = e.Encode(Header{
		Height: height,
		Header: header,
	})
	if err != nil {
		f.Close()
		return fmt.Errorf("Encode: %v", err)
	}

	return f.Close()
}

func WriteHeader(height int, header, dir string) error {
	bh, err := Hex2Header(header)
	if err != nil {
		return fmt.Errorf("Hex2Header: %v", err)
	}

	dfm.Lock()
	defer dfm.Unlock()

	err = writeHeader(height, bh.BlockHash().String(), header, dir)
	if err != nil {
		return fmt.Errorf("writeHeader: %v", err)
	}
	err = writeHeight(height, bh.BlockHash().String(), dir)
	if err != nil {
		return fmt.Errorf("writeHeight: %v", err)
	}
	return nil
}
