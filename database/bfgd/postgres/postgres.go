// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/juju/loggo"
	"github.com/lib/pq"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/postgres"
)

const (
	bfgdVersion = 6

	logLevel = "INFO"
	verbose  = false
)

const effectiveHeightSql = `
	COALESCE((SELECT MIN(height)

	FROM 
	(
		SELECT height FROM btc_blocks_can
			INNER JOIN pop_basis ON pop_basis.btc_block_hash 
				= btc_blocks_can.hash
			INNER JOIN l2_keystones ll ON ll.l2_keystone_abrev_hash 
				= pop_basis.l2_keystone_abrev_hash

		WHERE ll.l2_block_number >= l2_keystones.l2_block_number
	)), 0)
`

var log = loggo.GetLogger("bfgpostgres")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type pgdb struct {
	*postgres.Database
	db *sql.DB
}

var _ bfgd.Database = (*pgdb)(nil)

// Connect connects to a postgres database. This is only used in tests.
func Connect(ctx context.Context, uri string) (*sql.DB, error) {
	return postgres.Connect(ctx, uri)
}

func New(ctx context.Context, uri string) (*pgdb, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	pg, err := postgres.New(ctx, uri, bfgdVersion)
	if err != nil {
		return nil, err
	}
	log.Debugf("bfgdb database version: %v", bfgdVersion)
	p := &pgdb{
		Database: pg,
		db:       pg.DB(),
	}

	// first, refresh the materialized view so it can be used in case it was
	// never refreshed before this point
	err = p.refreshBTCBlocksCanonical(ctx)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func (pg *pgdb) Version(ctx context.Context) (int, error) {
	log.Tracef("Version")
	defer log.Tracef("Version exit")

	const selectVersion = `SELECT * FROM version LIMIT 1;`
	var dbVersion int
	if err := pg.db.QueryRowContext(ctx, selectVersion).Scan(&dbVersion); err != nil {
		return -1, err
	}
	return dbVersion, nil
}

func (pg *pgdb) L2KeystonesCount(ctx context.Context) (int, error) {
	log.Tracef("L2KeystonesCount")
	defer log.Tracef("L2KeystonesCount exit")

	const selectCount = `SELECT COUNT(*) FROM l2_keystones;`
	var count int
	if err := pg.db.QueryRowContext(ctx, selectCount).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (p *pgdb) L2KeystonesInsert(ctx context.Context, l2ks []bfgd.L2Keystone) error {
	log.Tracef("L2KeystonesInsert")
	defer log.Tracef("L2KeystonesInsert exit")

	if len(l2ks) == 0 {
		log.Errorf("empty l2 keystones, nothing to do")
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			log.Errorf("L2KeystonesInsert could not rollback db tx: %v",
				err)
			return
		}
	}()

	const qInsertL2Keystone = `
		INSERT INTO l2_keystones (
			l2_keystone_abrev_hash,
			l1_block_number,
			l2_block_number,
			parent_ep_hash,
			prev_keystone_ep_hash,
			state_root,
			ep_hash,
			version
		)

		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	for _, v := range l2ks {
		result, err := tx.ExecContext(ctx, qInsertL2Keystone, v.Hash,
			v.L1BlockNumber, v.L2BlockNumber, v.ParentEPHash,
			v.PrevKeystoneEPHash, v.StateRoot, v.EPHash, v.Version)
		if err != nil {
			if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
				switch err.Constraint {
				case "l2_keystone_abrev_hash_length",
					"state_root_length",
					"parent_ep_hash_length",
					"prev_keystone_ep_hash_length",
					"ep_hash_length":
					return database.ValidationError(err.Error())
				}

				log.Errorf("integrity violation occurred: %s", err.Constraint)
				return database.DuplicateError(fmt.Sprintf("constraint error: %s", err))
			}
			return fmt.Errorf("failed to insert l2 keystone: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to insert l2 keystone rows affected: %w", err)
		}
		if rows < 1 {
			return fmt.Errorf("failed to insert l2 keystone rows: %v", rows)
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (p *pgdb) L2KeystoneByAbrevHash(ctx context.Context, aHash [32]byte) (*bfgd.L2Keystone, error) {
	log.Tracef("L2KeystoneByAbrevHash")
	defer log.Tracef("L2KeystoneByAbrevHash exit")

	const q = `
		SELECT
			l2_keystone_abrev_hash,
			l1_block_number,
			l2_block_number,
			parent_ep_hash,
			prev_keystone_ep_hash,
			state_root,
			ep_hash,
			version,
			created_at,
			updated_at

		FROM l2_keystones
		WHERE l2_keystone_abrev_hash = $1
	`

	l2ks := &bfgd.L2Keystone{}
	row := p.db.QueryRowContext(ctx, q, aHash[:])
	if err := row.Scan(&l2ks.Hash, &l2ks.L1BlockNumber, &l2ks.L2BlockNumber,
		&l2ks.ParentEPHash, &l2ks.PrevKeystoneEPHash, &l2ks.StateRoot,
		&l2ks.EPHash, &l2ks.Version, &l2ks.CreatedAt, &l2ks.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, database.NotFoundError("l2 keystone not found")
		}
		return nil, err
	}
	return l2ks, nil
}

func (p *pgdb) L2KeystonesMostRecentN(ctx context.Context, n uint32) ([]bfgd.L2Keystone, error) {
	log.Tracef("L2KeystonesMostRecentN")
	defer log.Tracef("L2KeystonesMostRecentN exit")

	if n > 100 {
		n = 100
	}

	const q = `
		SELECT
			l2_keystone_abrev_hash,
			l1_block_number,
			l2_block_number,
			parent_ep_hash,
			prev_keystone_ep_hash,
			state_root,
			ep_hash,
			version,
			created_at,
			updated_at

		FROM l2_keystones
		ORDER BY l2_block_number DESC LIMIT $1
	`

	var ks []bfgd.L2Keystone
	rows, err := p.db.QueryContext(ctx, q, n)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var k bfgd.L2Keystone
		if err := rows.Scan(&k.Hash, &k.L1BlockNumber, &k.L2BlockNumber,
			&k.ParentEPHash, &k.PrevKeystoneEPHash, &k.StateRoot,
			&k.EPHash, &k.Version, &k.CreatedAt, &k.UpdatedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, database.NotFoundError("pop data not found")
			}
			return nil, err
		}
		ks = append(ks, k)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return ks, nil
}

func (p *pgdb) BtcBlockInsert(ctx context.Context, bb *bfgd.BtcBlock) error {
	log.Tracef("BtcBlockInsert")
	defer log.Tracef("BtcBlockInsert exit")
	const qBtcBlockInsert = `
		INSERT INTO btc_blocks (hash, header, height)
		VALUES ($1, $2, $3)
	`
	result, err := p.db.ExecContext(ctx, qBtcBlockInsert, bb.Hash, bb.Header,
		bb.Height)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			return database.DuplicateError(fmt.Sprintf("duplicate btc block entry: %s", err))
		}
		return fmt.Errorf("failed to insert btc block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to insert btc block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("failed to insert btc block rows: %v", rows)
	}

	return nil
}

func (p *pgdb) BtcBlockByHash(ctx context.Context, hash [32]byte) (*bfgd.BtcBlock, error) {
	log.Tracef("BtcBlockByHash")
	defer log.Tracef("BtcBlockByHash exit")

	const q = `
		SELECT hash, header, height, created_at, updated_at
		FROM btc_blocks
		WHERE hash = $1
	`

	bb := &bfgd.BtcBlock{}
	row := p.db.QueryRowContext(ctx, q, hash[:])
	if err := row.Scan(&bb.Hash, &bb.Header, &bb.Height, &bb.CreatedAt,
		&bb.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, database.NotFoundError("btc block not found")
		}
		return nil, err
	}
	return bb, nil
}

func (p *pgdb) BtcBlockHeightByHash(ctx context.Context, hash [32]byte) (uint64, error) {
	log.Tracef("BtcBlockHeightByHash")
	defer log.Tracef("BtcBlockHeightByHash exit")

	const q = `
		SELECT height
		FROM btc_blocks
		WHERE hash = $1
	`

	var height uint64
	row := p.db.QueryRowContext(ctx, q, hash[:])
	if err := row.Scan(&height); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, database.NotFoundError("btc block height not found")
		}
		return 0, err
	}
	return height, nil
}

func (p *pgdb) PopBasisInsertPopMFields(ctx context.Context, pb *bfgd.PopBasis) error {
	log.Tracef("PopBasisInsertPopMFields")
	defer log.Tracef("PopBasisInsertPopMFields exit")
	const qPopBlockInsert = `
		INSERT INTO pop_basis (
			btc_txid,
			btc_raw_tx,
			l2_keystone_abrev_hash,
			pop_miner_public_key
		)
		VALUES ($1, $2, $3, $4)
	`
	result, err := p.db.ExecContext(ctx, qPopBlockInsert, pb.BtcTxId, pb.BtcRawTx,
		pb.L2KeystoneAbrevHash, pb.PopMinerPublicKey)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			switch err.Constraint {
			case "btc_txid_length":
				return database.ValidationError("BtcTxId must be length 32")
			default:
				return database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", err.Error()))
			}
		}
		return fmt.Errorf("failed to insert pop block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to insert pop block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("failed to insert pop block rows: %v", rows)
	}

	return nil
}

func (p *pgdb) PopBasisUpdateBTCFields(ctx context.Context, pb *bfgd.PopBasis) (int64, error) {
	log.Tracef("PopBasisUpdateBTCFields")
	defer log.Tracef("PopBasisUpdateBTCFields exit")
	b, err := json.Marshal(pb.BtcMerklePath)
	if err != nil {
		return 0, err
	}

	q := `
		UPDATE pop_basis SET
			btc_block_hash = $1,
			btc_merkle_path = $2,
			pop_txid = $3,
			btc_tx_index = $4,
			updated_at = NOW()
		
		WHERE
			btc_txid = $5

		-- ensure these fields are null so that we
		-- don't overwrite another valid btc block (ex. a fork)
		AND btc_block_hash IS NULL
		AND btc_merkle_path IS NULL
		AND pop_txid IS NULL
		AND btc_tx_index IS NULL
	`

	result, err := p.db.ExecContext(ctx, q, pb.BtcHeaderHash, string(b), pb.PopTxId,
		pb.BtcTxIndex, pb.BtcTxId,
	)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			switch err.Constraint {
			case "pop_txid_length":
				return 0, database.ValidationError("PopTxId must be length 32")
			default:
				return 0, database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", err.Error()))
			}
		}
		return 0, fmt.Errorf("failed to insert pop block: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to insert pop block rows affected: %w", err)
	}

	return rows, nil
}

func (p *pgdb) PopBasisInsertFull(ctx context.Context, pb *bfgd.PopBasis) error {
	log.Tracef("PopBasisInsertFull")
	defer log.Tracef("PopBasisInsertFull exit")

	b, err := json.Marshal(pb.BtcMerklePath)
	if err != nil {
		return err
	}
	const qPopBlockInsert = `
		INSERT INTO pop_basis (
			btc_txid, 
			btc_raw_tx, 
			btc_block_hash, 
			btc_tx_index, 
			btc_merkle_path, 
			pop_txid, 
			l2_keystone_abrev_hash, 
			pop_miner_public_key
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (btc_txid, btc_raw_tx, btc_block_hash, btc_tx_index)
		DO NOTHING
	`
	result, err := p.db.ExecContext(ctx, qPopBlockInsert, pb.BtcTxId, pb.BtcRawTx,
		pb.BtcHeaderHash, pb.BtcTxIndex, string(b), pb.PopTxId,
		pb.L2KeystoneAbrevHash, pb.PopMinerPublicKey)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			switch err.Constraint {
			case "btc_txid_length":
				return database.ValidationError("BtcTxId must be length 32")
			case "pop_txid_length":
				return database.ValidationError("PopTxId must be length 32")
			default:
				return database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", err.Error()))
			}
		}
		return fmt.Errorf("failed to insert pop block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to insert pop block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("failed to insert pop block rows: %v", rows)
	}

	return nil
}

func (p *pgdb) PopBasisByL2KeystoneAbrevHash(ctx context.Context, aHash [32]byte, excludeUnconfirmed bool) ([]bfgd.PopBasis, error) {
	q := `
		SELECT
			id,
			btc_txid,
			btc_raw_tx,
			btc_block_hash,
			btc_tx_index,
			btc_merkle_path,
			pop_txid,
			l2_keystone_abrev_hash,
			pop_miner_public_key,
			created_at,
			updated_at

		FROM pop_basis
		WHERE l2_keystone_abrev_hash = $1
	`

	if excludeUnconfirmed == true {
		q += " AND btc_block_hash IS NOT NULL"
	}

	pbs := []bfgd.PopBasis{}
	log.Infof("querying for hash: %v", database.ByteArray(aHash[:]))
	rows, err := p.db.QueryContext(ctx, q, aHash[:])
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var popBasis bfgd.PopBasis
		var btcMerklePathTmp *string

		err := rows.Scan(
			&popBasis.ID,
			&popBasis.BtcTxId,
			&popBasis.BtcRawTx,
			&popBasis.BtcHeaderHash,
			&popBasis.BtcTxIndex,
			&btcMerklePathTmp,
			&popBasis.PopTxId,
			&popBasis.L2KeystoneAbrevHash,
			&popBasis.PopMinerPublicKey,
			&popBasis.CreatedAt,
			&popBasis.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if btcMerklePathTmp != nil {
			err = json.Unmarshal([]byte(*btcMerklePathTmp),
				&popBasis.BtcMerklePath)
			if err != nil {
				return nil, err
			}
		}
		pbs = append(pbs, popBasis)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return pbs, nil
}

// nextL2BTCFinalitiesPublished , given a block number (lessThanL2BlockNumber)
// will find the the next smallest published finality on the canoncial chain
func (p *pgdb) nextL2BTCFinalitiesPublished(ctx context.Context, lessThanL2BlockNumber uint32, limit int) ([]bfgd.L2BTCFinality, error) {
	sql := fmt.Sprintf(`
		SELECT
			btc_blocks_can.hash,
		    btc_blocks_can.height,
			l2_keystones.l2_keystone_abrev_hash,
			l2_keystones.l1_block_number,
			l2_keystones.l2_block_number,
			l2_keystones.parent_ep_hash,
			l2_keystones.prev_keystone_ep_hash,
			l2_keystones.state_root,
			l2_keystones.ep_hash,
			l2_keystones.version,
			%s,
			COALESCE((SELECT MAX(height) FROM btc_blocks_can), 0)
		FROM btc_blocks_can

		INNER JOIN pop_basis ON pop_basis.btc_block_hash = btc_blocks_can.hash
		INNER JOIN l2_keystones ON l2_keystones.l2_keystone_abrev_hash 
			= pop_basis.l2_keystone_abrev_hash

		WHERE l2_keystones.l2_block_number <= $1
		ORDER BY height DESC, l2_keystones.l2_block_number DESC LIMIT $2
	`, effectiveHeightSql)

	rows, err := p.db.QueryContext(ctx, sql, lessThanL2BlockNumber, limit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	finalities := []bfgd.L2BTCFinality{}

	for rows.Next() {
		var l2BtcFinality bfgd.L2BTCFinality
		err = rows.Scan(
			&l2BtcFinality.BTCPubHeaderHash,
			&l2BtcFinality.BTCPubHeight,
			&l2BtcFinality.L2Keystone.Hash,
			&l2BtcFinality.L2Keystone.L1BlockNumber,
			&l2BtcFinality.L2Keystone.L2BlockNumber,
			&l2BtcFinality.L2Keystone.ParentEPHash,
			&l2BtcFinality.L2Keystone.PrevKeystoneEPHash,
			&l2BtcFinality.L2Keystone.StateRoot,
			&l2BtcFinality.L2Keystone.EPHash,
			&l2BtcFinality.L2Keystone.Version,
			&l2BtcFinality.EffectiveHeight,
			&l2BtcFinality.BTCTipHeight,
		)
		if err != nil {
			return nil, err
		}

		finalities = append(finalities, l2BtcFinality)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return finalities, nil
}

// nextL2BTCFinalitiesAssumedUnpublished , given a block number (lessThanL2BlockNumber)
// will find the the next smallest published finality that is not within explicitExcludeL2BlockNumbers
// and assume it is unpublished (returning nothing for BTC fields)
func (p *pgdb) nextL2BTCFinalitiesAssumedUnpublished(ctx context.Context, lessThanL2BlockNumber uint32, limit int, explicitExcludeL2BlockNumbers []uint32) ([]bfgd.L2BTCFinality, error) {
	sql := fmt.Sprintf(`
		SELECT
			NULL,
			0,
			l2_keystones.l2_keystone_abrev_hash,
			l2_keystones.l1_block_number,
			l2_keystones.l2_block_number,
			l2_keystones.parent_ep_hash,
			l2_keystones.prev_keystone_ep_hash,
			l2_keystones.state_root,
			l2_keystones.ep_hash,
			l2_keystones.version,
			%s,
			COALESCE((SELECT MAX(height) FROM btc_blocks_can),0)

		FROM l2_keystones
		WHERE l2_block_number != ANY($3)
		AND l2_block_number <= $1
		ORDER BY l2_block_number DESC LIMIT $2
	`, effectiveHeightSql)

	rows, err := p.db.QueryContext(
		ctx,
		sql,
		lessThanL2BlockNumber,
		limit,
		pq.Array(explicitExcludeL2BlockNumbers),
	)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	finalities := []bfgd.L2BTCFinality{}

	for rows.Next() {
		var l2BtcFinality bfgd.L2BTCFinality
		err = rows.Scan(
			&l2BtcFinality.BTCPubHeaderHash,
			&l2BtcFinality.BTCPubHeight,
			&l2BtcFinality.L2Keystone.Hash,
			&l2BtcFinality.L2Keystone.L1BlockNumber,
			&l2BtcFinality.L2Keystone.L2BlockNumber,
			&l2BtcFinality.L2Keystone.ParentEPHash,
			&l2BtcFinality.L2Keystone.PrevKeystoneEPHash,
			&l2BtcFinality.L2Keystone.StateRoot,
			&l2BtcFinality.L2Keystone.EPHash,
			&l2BtcFinality.L2Keystone.Version,
			&l2BtcFinality.EffectiveHeight,
			&l2BtcFinality.BTCTipHeight,
		)
		if err != nil {
			return nil, err
		}
		l2BtcFinality.BTCPubHeight = -1
		finalities = append(finalities, l2BtcFinality)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return finalities, nil
}

// L2BTCFinalityMostRecent gets the most recent L2BtcFinalities sorted
// descending by l2_block_number
func (p *pgdb) L2BTCFinalityMostRecent(ctx context.Context, limit uint32) ([]bfgd.L2BTCFinality, error) {
	if limit > 100 {
		return nil, fmt.Errorf(
			"limit cannot be greater than 100, received %d",
			limit,
		)
	}

	tip, err := p.canonicalChainTipL2BlockNumber(ctx)
	if err != nil {
		return nil, err
	}

	// we found no canonical tip, return nothing
	if tip == nil {
		return []bfgd.L2BTCFinality{}, nil
	}

	finalities := []bfgd.L2BTCFinality{}

	// first, get all of the most recent published finalities up to the limit
	// from the tip
	publishedFinalities, err := p.nextL2BTCFinalitiesPublished(
		ctx,
		*tip,
		int(limit),
	)
	if err != nil {
		return nil, err
	}
	pfi := 0

	// it is possible that there will be some unpublished finalities between
	// the published
	// ones, get all finalities up to the limit that are NOT in published.
	// IMPORTANT NOTE: we call these explicity "assumed unpublished"
	// instead of explicity looking for unpublished
	// finalities, because a finality could get published between these two
	// queries.  this is why we call these "assumed".  the idea is to make
	// this worst-case scenario slighty out-of-date, rather than incorrect
	excludeL2BlockNumbers := []uint32{}
	for _, v := range publishedFinalities {
		excludeL2BlockNumbers = append(
			excludeL2BlockNumbers,
			v.L2Keystone.L2BlockNumber,
		)
	}

	unpublishedFinalities, err := p.nextL2BTCFinalitiesAssumedUnpublished(
		ctx,
		*tip,
		int(limit),
		excludeL2BlockNumbers)
	if err != nil {
		return nil, err
	}

	for {

		var publishedFinality *bfgd.L2BTCFinality
		if pfi < len(publishedFinalities) {
			publishedFinality = &publishedFinalities[pfi]
		}

		var finality *bfgd.L2BTCFinality

		var unpublishedFinality *bfgd.L2BTCFinality
		for _, u := range unpublishedFinalities {
			if u.L2Keystone.L2BlockNumber <= *tip {
				unpublishedFinality = &u
				break
			}
		}

		if publishedFinality == nil {
			finality = unpublishedFinality
		} else if unpublishedFinality == nil {
			finality = publishedFinality
			pfi++
		} else if publishedFinality.L2Keystone.L2BlockNumber >=
			unpublishedFinality.L2Keystone.L2BlockNumber {
			finality = publishedFinality
			pfi++
		} else {
			finality = unpublishedFinality
		}

		// if we couldn't find finality, there are no more possibilities
		if finality == nil {
			break
		}

		finalities = append(finalities, *finality)
		if uint32(len(finalities)) >= limit {
			break
		}

		if finality.L2Keystone.L2BlockNumber == 0 {
			break
		}

		*tip = finality.L2Keystone.L2BlockNumber - 1
	}

	return finalities, nil
}

// L2BTCFinalityByL2KeystoneAbrevHash queries for finalities by L2KeystoneAbrevHash
// and returns them descending by l2_block_number
func (p *pgdb) L2BTCFinalityByL2KeystoneAbrevHash(ctx context.Context, l2KeystoneAbrevHashes []database.ByteArray) ([]bfgd.L2BTCFinality, error) {
	log.Tracef("L2BTCFinalityByL2KeystoneAbrevHash")
	defer log.Tracef("L2BTCFinalityByL2KeystoneAbrevHash exit")

	if len(l2KeystoneAbrevHashes) > 100 {
		return nil, errors.New("l2KeystoneAbrevHashes cannot be longer than 100")
	}

	sql := fmt.Sprintf(`
		SELECT
			btc_blocks_can.hash,
			COALESCE(btc_blocks_can.height, 0),
			l2_keystones.l2_keystone_abrev_hash,
			l2_keystones.l1_block_number,
			l2_keystones.l2_block_number,
			l2_keystones.parent_ep_hash,
			l2_keystones.prev_keystone_ep_hash,
			l2_keystones.state_root,
			l2_keystones.ep_hash,
			l2_keystones.version,
			%s,
			COALESCE((SELECT MAX(height) FROM btc_blocks_can),0)

		FROM l2_keystones
		LEFT JOIN pop_basis ON l2_keystones.l2_keystone_abrev_hash 
			= pop_basis.l2_keystone_abrev_hash
		LEFT JOIN btc_blocks_can ON pop_basis.btc_block_hash 
			= btc_blocks_can.hash

		WHERE l2_keystones.l2_keystone_abrev_hash = ANY($1)

		ORDER BY l2_keystones.l2_block_number DESC
	`, effectiveHeightSql)

	l2KeystoneAbrevHashesStr := [][]byte{}
	for _, l := range l2KeystoneAbrevHashes {
		l2KeystoneAbrevHashesStr = append(l2KeystoneAbrevHashesStr, []byte(l))
	}

	// XXX this doesn't go here
	log.Infof("the hashes are %v", l2KeystoneAbrevHashesStr)

	rows, err := p.db.QueryContext(ctx, sql, pq.Array(l2KeystoneAbrevHashesStr))
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	finalities := []bfgd.L2BTCFinality{}

	for rows.Next() {
		var l2BtcFinality bfgd.L2BTCFinality
		err = rows.Scan(
			&l2BtcFinality.BTCPubHeaderHash,
			&l2BtcFinality.BTCPubHeight,
			&l2BtcFinality.L2Keystone.Hash,
			&l2BtcFinality.L2Keystone.L1BlockNumber,
			&l2BtcFinality.L2Keystone.L2BlockNumber,
			&l2BtcFinality.L2Keystone.ParentEPHash,
			&l2BtcFinality.L2Keystone.PrevKeystoneEPHash,
			&l2BtcFinality.L2Keystone.StateRoot,
			&l2BtcFinality.L2Keystone.EPHash,
			&l2BtcFinality.L2Keystone.Version,
			&l2BtcFinality.EffectiveHeight,
			&l2BtcFinality.BTCTipHeight,
		)
		if err != nil {
			return nil, err
		}

		if l2BtcFinality.BTCPubHeaderHash == nil {
			l2BtcFinality.BTCPubHeight = -1
		}
		finalities = append(finalities, l2BtcFinality)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return finalities, nil
}

// BtcBlockCanonicalHeight returns the highest height of btc blocks on the
// canonical chain
func (p *pgdb) BtcBlockCanonicalHeight(ctx context.Context) (uint64, error) {
	log.Tracef("BtcBlockCanonicalHeight")
	defer log.Tracef("BtcBlockCanonicalHeight exit")

	sql := `
		SELECT COALESCE(MAX(height),0) 
		FROM btc_blocks_can
	`

	rows, err := p.db.QueryContext(ctx, sql)
	if err != nil {
		return 0, err
	}

	defer rows.Close()

	for rows.Next() {
		var result uint64
		err = rows.Scan(&result)
		if err != nil {
			return 0, err
		}

		return result, nil
	}

	if err = rows.Err(); err != nil {
		return 0, err
	}

	return 0, errors.New("should not get here")
}

func (p *pgdb) AccessPublicKeyInsert(ctx context.Context, publicKey *bfgd.AccessPublicKey) error {
	log.Tracef("AccessPublicKeyInsert")
	defer log.Tracef("AccessPublicKeyInsert exit")

	const sql = `
		INSERT INTO access_public_keys (
			public_key
		) VALUES ($1)
	`

	_, err := p.db.ExecContext(ctx, sql, publicKey.PublicKey)
	if err != nil {
		pqErr := err.(*pq.Error)
		if pqErr.Constraint == "access_public_keys_pkey" {
			return database.DuplicateError("public key already exists")
		}

		return err
	}

	return nil
}

func (p *pgdb) AccessPublicKeyExists(ctx context.Context, publicKey *bfgd.AccessPublicKey) (bool, error) {
	log.Tracef("AccessPublicKeyExists")
	defer log.Tracef("AccessPublicKeyExists exit")

	const sql = `
		SELECT EXISTS (
			SELECT * FROM access_public_keys WHERE public_key = $1
		)
	`

	rows, err := p.db.QueryContext(ctx, sql, publicKey.PublicKey)
	if err != nil {
		return false, err
	}

	defer rows.Close()

	for rows.Next() {
		var exists bool
		err = rows.Scan(&exists)
		if err != nil {
			return false, err
		}

		return exists, nil
	}

	if err = rows.Err(); err != nil {
		return false, err
	}

	return false, errors.New("should not get here")
}

func (p *pgdb) AccessPublicKeyDelete(ctx context.Context, publicKey *bfgd.AccessPublicKey) error {
	log.Tracef("AccessPublicKeyDelete")
	log.Tracef("AccessPublicKeyDelete exit")

	sql := fmt.Sprintf(`
		WITH deleted AS (
			DELETE FROM access_public_keys WHERE public_key = $1
			RETURNING *
		) SELECT count(*) FROM deleted;
	`)

	rows, err := p.db.QueryContext(ctx, sql, publicKey.PublicKey)
	if err != nil {
		return err
	}

	for rows.Next() {
		var count int
		if err := rows.Scan(&count); err != nil {
			return err
		}

		return database.NotFoundError("public key not found")
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}

// canonicalChainTipL2BlockNumber gets our best guess of the canonical tip
// and returns it.  it finds the highest btc block with an associated
// l2 keystone where only 1 btc block exists at that height
func (p *pgdb) canonicalChainTipL2BlockNumber(ctx context.Context) (*uint32, error) {
	log.Tracef("canonicalChainTipL2BlockNumber")
	defer log.Tracef("canonicalChainTipL2BlockNumber exit")

	sql := fmt.Sprintf(`
		SELECT l2_keystones.l2_block_number

		FROM btc_blocks_can

		INNER JOIN pop_basis ON pop_basis.btc_block_hash = btc_blocks_can.hash
		INNER JOIN l2_keystones ON l2_keystones.l2_keystone_abrev_hash 
			= pop_basis.l2_keystone_abrev_hash
	
		ORDER BY l2_block_number DESC LIMIT 1
	`)

	rows, err := p.db.QueryContext(ctx, sql)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var l2BlockNumber uint32
		err := rows.Scan(&l2BlockNumber)
		if err != nil {
			return nil, err
		}

		return &l2BlockNumber, nil
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return nil, nil
}

func (p *pgdb) refreshBTCBlocksCanonical(ctx context.Context) error {
	// XXX this probably should be REFRESH MATERIALIZED VIEW CONCURRENTLY
	// however, this is more testable at the moment and we're in a time crunch,
	// this works
	sql := "REFRESH MATERIALIZED VIEW btc_blocks_can"
	_, err := p.db.ExecContext(ctx, sql)
	if err != nil {
		return err
	}

	return nil
}
