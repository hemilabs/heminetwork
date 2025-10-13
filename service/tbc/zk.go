// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"

	"github.com/btcsuite/btcd/btcutil"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

func (s *Server) ZKBalanceByScriptHash(ctx context.Context, hash tbcd.ScriptHash) (btcutil.Amount, error) {
	log.Tracef("ZKBalanceByScriptHash")
	defer log.Tracef("ZKBalanceByScriptHash exit")

	balance, err := s.g.db.ZKBalanceByScriptHash(ctx, hash)
	if err != nil {
		return 0, err
	}
	return btcutil.Amount(int64(balance)), nil
}

func (s *Server) ZKValueAndScriptByOutpoint(ctx context.Context, op tbcd.Outpoint) (btcutil.Amount, []byte, error) {
	log.Tracef("ZKValueAndScriptByOutpoint")
	defer log.Tracef("ZKValueAndScriptByOutpoint exit")

	value, script, err := s.g.db.ZKValueAndScriptByOutpoint(ctx, op)
	if err != nil {
		return 0, nil, err
	}
	return btcutil.Amount(int64(value)), script, nil
}
