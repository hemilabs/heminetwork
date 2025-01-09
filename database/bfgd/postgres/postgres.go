// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"
	"encoding/hex"
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
	bfgdVersion = 13

	logLevel = "INFO"
	verbose  = false
)

var log = loggo.GetLogger("bfgpostgres")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
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

func (p *pgdb) Version(ctx context.Context) (int, error) {
	log.Tracef("Version")
	defer log.Tracef("Version exit")

	const selectVersion = `SELECT * FROM version LIMIT 1;`
	var dbVersion int
	if err := p.db.QueryRowContext(ctx, selectVersion).Scan(&dbVersion); err != nil {
		return -1, err
	}
	return dbVersion, nil
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

		ON CONFLICT DO NOTHING
	`

	for _, v := range l2ks {
		_, err := tx.ExecContext(ctx, qInsertL2Keystone, v.Hash,
			v.L1BlockNumber, v.L2BlockNumber, v.ParentEPHash,
			v.PrevKeystoneEPHash, v.StateRoot, v.EPHash, v.Version)
		if err != nil {
			var pgErr *pq.Error
			if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
				switch pgErr.Constraint {
				case "l2_keystone_abrev_hash_length",
					"state_root_length",
					"parent_ep_hash_length",
					"prev_keystone_ep_hash_length",
					"ep_hash_length":
					return database.ValidationError(pgErr.Error())
				}

				log.Errorf("integrity violation occurred: %s", pgErr.Constraint)
				return database.DuplicateError(fmt.Sprintf("constraint error: %s", pgErr))
			}
			return fmt.Errorf("insert l2 keystone: %w", err)
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

func (p *pgdb) L2KeystonesMostRecentN(ctx context.Context, n uint32, page uint32) ([]bfgd.L2Keystone, error) {
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
		ORDER BY l2_block_number DESC, l2_keystone_abrev_hash DESC OFFSET $1 LIMIT $2
	`

	var ks []bfgd.L2Keystone
	rows, err := p.db.QueryContext(ctx, q, page*n, n)
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
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
			return database.DuplicateError(fmt.Sprintf("duplicate btc block entry: %s", pgErr))
		}
		return fmt.Errorf("insert btc block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert btc block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("insert btc block rows: %v", rows)
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
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
			switch pgErr.Constraint {
			case "btc_txid_length":
				return database.ValidationError("BtcTxId must be length 32")
			default:
				return database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", pgErr.Error()))
			}
		}
		return fmt.Errorf("insert pop block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert pop block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("insert pop block rows: %v", rows)
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
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
			switch pgErr.Constraint {
			case "pop_txid_length":
				return 0, database.ValidationError("PopTxId must be length 32")
			default:
				return 0, database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", pgErr.Error()))
			}
		}
		return 0, fmt.Errorf("insert pop block: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("insert pop block rows affected: %w", err)
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
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
			switch pgErr.Constraint {
			case "btc_txid_length":
				return database.ValidationError("BtcTxId must be length 32")
			case "pop_txid_length":
				return database.ValidationError("PopTxId must be length 32")
			default:
				return database.DuplicateError(fmt.Sprintf("duplicate pop block entry: %s", pgErr.Error()))
			}
		}
		return fmt.Errorf("insert pop block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert pop block rows affected: %w", err)
	}
	if rows < 1 {
		return fmt.Errorf("insert pop block rows: %v", rows)
	}

	return nil
}

func (p *pgdb) PopBasisByL2KeystoneAbrevHash(ctx context.Context, aHash [32]byte, excludeUnconfirmed bool, page uint32) ([]bfgd.PopBasis, error) {
	// can change later as needed
	limit := uint32(100)

	// start at page 0
	offset := limit * page

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

	if excludeUnconfirmed {
		q += " AND btc_block_hash IS NOT NULL"
	}

	// use ORDER BY so pagination maintains an order of some sort (so we don't
	// respond multiple times with the same record on different pages)
	q += " ORDER BY id OFFSET $2 LIMIT $3"

	pbs := []bfgd.PopBasis{}
	log.Infof("querying for hash: %v", database.ByteArray(aHash[:]))
	rows, err := p.db.QueryContext(ctx, q, aHash[:], offset, limit)
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

func (p *pgdb) L2KeystoneLowestBtcBlockUpsert(ctx context.Context, l2KeystoneAbrevHash database.ByteArray) error {
	sql := `
		WITH lowest_btc_block AS (
			SELECT btc_blocks_can.hash, btc_blocks_can.height
			FROM pop_basis
			INNER JOIN btc_blocks_can ON btc_blocks_can.hash = pop_basis.btc_block_hash
			WHERE pop_basis.l2_keystone_abrev_hash = $1
			ORDER BY btc_blocks_can.height ASC LIMIT 1
		)
		INSERT INTO l2_keystones_lowest_btc_block (l2_keystone_abrev_hash, btc_block_hash, btc_block_height)
		VALUES (
			$1,
			(SELECT hash FROM lowest_btc_block),
			(SELECT height FROM lowest_btc_block)
		)
		ON CONFLICT (l2_keystone_abrev_hash) DO UPDATE SET btc_block_hash = EXCLUDED.btc_block_hash 
		WHERE l2_keystones_lowest_btc_block.btc_block_hash != EXCLUDED.btc_block_hash
	`

	_, err := p.db.ExecContext(ctx, sql, l2KeystoneAbrevHash)
	if err != nil {
		return err
	}

	return nil
}

// BackfillL2KeystonesLowestBtcBlocks (should only) runs on startup and is
// a quick check that all existing keystones have an associated lowest btc
// block if it exists.  this is essential for new deploys
func (p *pgdb) BackfillL2KeystonesLowestBtcBlocks(ctx context.Context, pageSize uint32) error {
	limit := pageSize
	page := uint32(0)

	for {
		l2ks, err := p.L2KeystonesMostRecentN(ctx, limit, page)
		if err != nil && !errors.Is(err, database.ErrNotFound) {
			return err
		}

		if len(l2ks) == 0 {
			log.Infof("done backfilling l2 keystones <-> lowest btc block")
			return nil
		}

		for _, ks := range l2ks {
			log.Tracef("backfilling l2keystone=%s, l2blocknumber=%d", hex.EncodeToString(ks.Hash), ks.L2BlockNumber)
			if err := p.L2KeystoneLowestBtcBlockUpsert(ctx, ks.Hash); err != nil {
				return err
			}
		}
		page++
	}
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

	l2Keystones, err := p.L2KeystonesMostRecentN(ctx, limit, 0)
	if err != nil {
		return nil, err
	}

	finalities := []bfgd.L2BTCFinality{}

	hashes := []database.ByteArray{}
	for _, l := range l2Keystones {
		hashes = append(hashes, l.Hash)
	}

	page := uint32(0)
	for {
		finalitiesTmp, err := p.L2BTCFinalityByL2KeystoneAbrevHash(ctx, hashes, page, 100)
		if err != nil {
			return nil, err
		}

		if len(finalitiesTmp) == 0 {
			break
		}

		for _, f := range finalitiesTmp {
			finalities = append(finalities, f)
			if uint32(len(finalities)) >= limit {
				return finalities, nil
			}
		}

		page++
	}

	return finalities, nil
}

// L2BTCFinalityByL2KeystoneAbrevHash queries for finalities by L2KeystoneAbrevHash
// and returns them descending by l2_block_number
func (p *pgdb) L2BTCFinalityByL2KeystoneAbrevHash(ctx context.Context, l2KeystoneAbrevHashes []database.ByteArray, page uint32, limit uint32) ([]bfgd.L2BTCFinality, error) {
	log.Tracef("L2BTCFinalityByL2KeystoneAbrevHash")
	defer log.Tracef("L2BTCFinalityByL2KeystoneAbrevHash exit")

	if len(l2KeystoneAbrevHashes) > 100 {
		return nil, errors.New("l2KeystoneAbrevHashes cannot be longer than 100")
	}

	// don't let users query for more than 100 at a time, default 0 to 100 for
	// backwards compatibility
	if limit > 100 || limit == 0 {
		log.Tracef("limit was set to %d, defaulting to 100", limit)
		limit = 100
	}

	sql := `
		SELECT
			btc_block_hash,
			COALESCE(btc_block_height, 0),
			l2_keystones.l2_keystone_abrev_hash,
			l2_keystones.l1_block_number,
			l2_keystones.l2_block_number,
			l2_keystones.parent_ep_hash,
			l2_keystones.prev_keystone_ep_hash,
			l2_keystones.state_root,
			l2_keystones.ep_hash,
			l2_keystones.version,
			COALESCE((SELECT height
				FROM 
				(
					SELECT height FROM btc_blocks_can
					INNER JOIN l2_keystones_lowest_btc_block lll
					ON lll.btc_block_hash = btc_blocks_can.hash
					INNER JOIN l2_keystones ll
					ON ll.l2_keystone_abrev_hash = lll.l2_keystone_abrev_hash
					WHERE ll.l2_block_number >= l2_keystones.l2_block_number
					AND height > (SELECT height FROM btc_blocks_can ORDER BY height DESC LIMIT 1) - 100
					ORDER BY height ASC LIMIT 1
				)), 0),
			COALESCE((SELECT height FROM btc_blocks_can ORDER BY height DESC LIMIT 1),0)

		FROM l2_keystones
		LEFT JOIN l2_keystones_lowest_btc_block
		ON l2_keystones.l2_keystone_abrev_hash = l2_keystones_lowest_btc_block.l2_keystone_abrev_hash

		WHERE l2_keystones.l2_keystone_abrev_hash = ANY($1)

		ORDER BY l2_keystones.l2_block_number DESC

		OFFSET $2

		LIMIT $3
	`

	l2KeystoneAbrevHashesStr := [][]byte{}
	for _, l := range l2KeystoneAbrevHashes {
		l2KeystoneAbrevHashesStr = append(l2KeystoneAbrevHashesStr, []byte(l))
	}

	// XXX this doesn't go here
	log.Infof("the hashes are %v", l2KeystoneAbrevHashesStr)

	rows, err := p.db.QueryContext(ctx, sql, pq.Array(l2KeystoneAbrevHashesStr), page*limit, limit)
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

	const q = `SELECT COALESCE(MAX(height),0) FROM btc_blocks_can LIMIT 1`

	var result uint64
	if err := p.db.QueryRowContext(ctx, q).Scan(&result); err != nil {
		return 0, err
	}

	return result, nil
}

// BtcBlocksHeightsWithNoChildren returns the heights of blocks stored in the
// database that do not have any children, these represent possible forks that
// have not been handled yet.
func (p *pgdb) BtcBlocksHeightsWithNoChildren(ctx context.Context) ([]uint64, error) {
	log.Tracef("BtcBlocksHeightsWithNoChildren")
	defer log.Tracef("BtcBlocksHeightsWithNoChildren exit")

	// Query all heights from btc_blocks where the block does not have any
	// children and there are no other blocks at the same height with children.
	// Excludes the tip because it will not have any children.
	const q = `
		SELECT height FROM btc_blocks bb1
		WHERE NOT EXISTS (SELECT * FROM btc_blocks bb2 WHERE substr(bb2.header, 5, 32) = bb1.hash)
		AND NOT EXISTS (
			SELECT * FROM btc_blocks bb3 WHERE bb1.height = bb3.height 
			AND EXISTS (
				SELECT * FROM btc_blocks bb4 WHERE substr(bb4.header, 5, 32) = bb3.hash
			)
		)
		ORDER BY height DESC
		OFFSET $1 + 1
		LIMIT 100
	`

	var heights []uint64
	for offset := 0; ; offset += 100 {
		rows, err := p.db.QueryContext(ctx, q, offset)
		if err != nil {
			return nil, err
		}
		defer rows.Close()

		startingLength := len(heights)
		for rows.Next() {
			var v uint64
			if err := rows.Scan(&v); err != nil {
				return nil, err
			}
			heights = append(heights, v)
		}

		if startingLength == len(heights) {
			return heights, nil
		}

		if rows.Err() != nil {
			return nil, rows.Err()
		}
	}
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

func (p *pgdb) BtcTransactionBroadcastRequestInsert(ctx context.Context, serializedTx []byte, txId string) error {
	log.Tracef("BtcTransactionBroadcastRequestInsert")
	defer log.Tracef("BtcTransactionBroadcastRequestInsert exit")

	const insertSql = `
		INSERT INTO btc_transaction_broadcast_request 
		(tx_id, serialized_tx)
		VALUES ($1, $2)
	`
	_, err := p.db.ExecContext(ctx, insertSql, txId, serializedTx)
	if err != nil {
		var pgErr *pq.Error
		if errors.As(err, &pgErr) && pgErr.Code.Class().Name() == "integrity_constraint_violation" {
			return database.DuplicateError(fmt.Sprintf("duplicate entry: %s", pgErr))
		}
		return fmt.Errorf("failed to insert btc_transaction_broadcast_request: %w", err)
	}

	return nil
}

// BtcTransactionBroadcastRequestGetNext
func (p *pgdb) BtcTransactionBroadcastRequestGetNext(ctx context.Context, onlyNew bool) ([]byte, error) {
	log.Tracef("BtcTransactionBroadcastRequestGetNext")
	defer log.Tracef("BtcTransactionBroadcastRequestGetNext exit")

	onlyNewClause := " next_broadcast_attempt_at IS NOT NULL AND next_broadcast_attempt_at <= NOW() "
	if onlyNew {
		onlyNewClause = " next_broadcast_attempt_at IS NULL "
	}

	orderClause := " ORDER BY last_broadcast_attempt_at ASC "
	if onlyNew {
		orderClause = " ORDER BY created_at ASC "
	}

	querySql := fmt.Sprintf(`
		UPDATE btc_transaction_broadcast_request 
		SET last_broadcast_attempt_at = NOW(), 
		
		next_broadcast_attempt_at = NOW() + INTERVAL '1 minute' + RANDOM() * INTERVAL '240 seconds' 
		
		WHERE tx_id = (
			SELECT tx_id FROM btc_transaction_broadcast_request
			WHERE 
			%s
			AND broadcast_at IS NULL
			AND created_at > NOW() - INTERVAL '30 minutes'
			%s
			FOR UPDATE
			LIMIT 1
		)
		RETURNING serialized_tx
	`, onlyNewClause, orderClause)

	var serializedTx []byte
	err := p.db.QueryRowContext(ctx, querySql).Scan(&serializedTx)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("could not get next btc_transaction_broadcast_request: %w", err)
		}
		// Query may return 1 or 0 rows.
		return nil, nil
	}

	return serializedTx, nil
}

// BtcTransactionBroadcastRequestConfirmBroadcast sets a broadcast request to
// "broadcasted" so it doesn't get attempted again
func (p *pgdb) BtcTransactionBroadcastRequestConfirmBroadcast(ctx context.Context, txId string) error {
	log.Tracef("BtcTransactionBroadcastRequestConfirmBroadcast")
	defer log.Tracef("BtcTransactionBroadcastRequestConfirmBroadcast exit")

	const querySql = `
		UPDATE btc_transaction_broadcast_request 
		SET broadcast_at = NOW()
		WHERE tx_id = $1
	`
	_, err := p.db.ExecContext(ctx, querySql, txId)
	if err != nil {
		return fmt.Errorf("could not confirm broadcast: %w", err)
	}

	return nil
}

func (p *pgdb) BtcTransactionBroadcastRequestSetLastError(ctx context.Context, txId string, lastErr string) error {
	log.Tracef("BtcTransactionBroadcastRequestSetLastError")
	defer log.Tracef("BtcTransactionBroadcastRequestSetLastError exit")

	const querySql = `
		UPDATE btc_transaction_broadcast_request 
		SET last_error = $2 WHERE tx_id = $1
	`
	_, err := p.db.ExecContext(ctx, querySql, txId, lastErr)
	if err != nil {
		return fmt.Errorf("could not confirm broadcast: %w", err)
	}

	return nil
}

func (p *pgdb) BtcTransactionBroadcastRequestTrim(ctx context.Context) error {
	log.Tracef("BtcTransactionBroadcastRequestSetLastError")
	defer log.Tracef("BtcTransactionBroadcastRequestSetLastError exit")

	const querySql = `
		DELETE FROM btc_transaction_broadcast_request 
		WHERE created_at < NOW() - INTERVAL '1 hour'
	`
	_, err := p.db.ExecContext(ctx, querySql)
	if err != nil {
		return fmt.Errorf("could not trim broadcast: %w", err)
	}

	return nil
}
