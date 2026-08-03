// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/hemilabs/x/leveldb/leveldb"
	"github.com/hemilabs/x/leveldb/leveldb/opt"
)

func init() {
	registerCommand("level", "LevelDB manipulation", levelHandler)
}

func levelHandler(pctx context.Context, flags []string) error {
	grp := commandGroup{
		help: "Manipulate a LevelDB database directly.",
		commands: map[string]command{
			"open": {
				help: "Open a LevelDB database to verify it is readable.",
				args: map[string]argument{
					"db": {required: true, help: "path to the LevelDB directory"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ldb, err := leveldb.OpenFile(args["db"], &opt.Options{ErrorIfMissing: true})
					if err != nil {
						return fmt.Errorf("leveldb open: %w", err)
					}
					return ldb.Close()
				},
			},
			"recover": {
				help: "Attempt to recover a corrupted LevelDB database.",
				args: map[string]argument{
					"db": {required: true, help: "path to the LevelDB directory"},
				},
				run: func(ctx context.Context, args map[string]string) error {
					ldb, err := leveldb.RecoverFile(args["db"], &opt.Options{ErrorIfMissing: true})
					if err != nil {
						return fmt.Errorf("leveldb recover: %w", err)
					}
					return ldb.Close()
				},
			},
		},
	}

	fs := flag.NewFlagSet("level", flag.ExitOnError)
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	fs.Usage = func() { printGroupHelp("level", grp) }
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		fs.Usage()
		return nil
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	return dispatchGroup(ctx, grp, "level", fs.Args())
}
