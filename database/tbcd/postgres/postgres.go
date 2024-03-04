// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/postgres"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/juju/loggo"
	"github.com/lib/pq"
)

const (
	tbcdVersion = 1

	logLevel = "INFO"
	verbose  = false
)

var log = loggo.GetLogger("tbcpostgres")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type pgdb struct {
	*postgres.Database
	db *sql.DB
}

var _ tbcd.Database = (*pgdb)(nil)

// Connect connects to a postgres database. This is only used in tests.
func Connect(ctx context.Context, uri string) (*sql.DB, error) {
	return postgres.Connect(ctx, uri)
}

func New(ctx context.Context, uri string) (*pgdb, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	pg, err := postgres.New(ctx, uri, tbcdVersion)
	if err != nil {
		return nil, err
	}
	log.Debugf("tbcdb database version: %v", tbcdVersion)
	p := &pgdb{
		Database: pg,
		db:       pg.DB(),
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

func (p *pgdb) BlockHeaderByHash(ctx context.Context, hash []byte) (*tbcd.BlockHeader, error) {
	log.Tracef("BlockHeaderByHash")
	defer log.Tracef("BlockHeaderByHash exit")

	const selectHeader = `SELECT * FROM block_headers WHERE hash = $1;`

	var bh tbcd.BlockHeader
	row := p.db.QueryRowContext(ctx, selectHeader, hash)
	if err := row.Scan(&bh.Hash, &bh.Height, &bh.Header, &bh.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, database.NotFoundError("btc block not found")
		}
		return nil, err
	}
	return &bh, nil
}

func (p *pgdb) BlockHeadersBest(ctx context.Context) ([]tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersBest")
	defer log.Tracef("BlockHeadersBest exit")

	const selectHeadersBest = `SELECT * FROM block_headers WHERE height = (SELECT max(height) FROM block_headers);`

	bhs := make([]tbcd.BlockHeader, 0, 3)
	rows, err := p.db.QueryContext(ctx, selectHeadersBest)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var bh tbcd.BlockHeader
		if err := rows.Scan(&bh.Hash, &bh.Height, &bh.Header, &bh.CreatedAt); err != nil {
			if err == sql.ErrNoRows {
				return nil, database.NotFoundError("block header data not found")
			}
			return nil, err
		}
		bhs = append(bhs, bh)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return bhs, nil
}

func (p *pgdb) BlockHeadersMissing(ctx context.Context, count int) ([]tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersMissing")
	defer log.Tracef("BlockHeadersMissing exit")

	const selectHeadersMissing = `
		SELECT bh.hash,bh.height,bh.header,bh.created_at FROM block_headers bh
		WHERE NOT EXISTS (SELECT * FROM blocks b WHERE b.hash=bh.hash)
		ORDER BY bh.height ASC
		LIMIT $1;`

	bhs := make([]tbcd.BlockHeader, 0, count)
	rows, err := p.db.QueryContext(ctx, selectHeadersMissing, count)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var bh tbcd.BlockHeader
		if err := rows.Scan(&bh.Hash, &bh.Height, &bh.Header, &bh.CreatedAt); err != nil {
			if err == sql.ErrNoRows {
				return nil, database.NotFoundError("block header data not found")
			}
			return nil, err
		}
		bhs = append(bhs, bh)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return bhs, nil
}

func (p *pgdb) BlockHeadersInsert(ctx context.Context, bhs []tbcd.BlockHeader) error {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if len(bhs) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("BlockHeadersInsert could not rollback db tx: %v",
				err)
			return
		}
	}()

	const qBlockHeaderInsert = `
		INSERT INTO block_headers (hash, height, header)
		VALUES ($1, $2, $3)
	`
	for k := range bhs {
		result, err := tx.ExecContext(ctx, qBlockHeaderInsert, bhs[k].Hash,
			bhs[k].Height, bhs[k].Header)
		if err != nil {
			if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
				return database.DuplicateError(fmt.Sprintf("duplicate hash height entry: %s", err))
			}
			return fmt.Errorf("failed to insert hash height: %v", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to insert hash height rows affected: %v", err)
		}
		if rows < 1 {
			return fmt.Errorf("failed to insert hash height rows: %v", rows)
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (p *pgdb) BlockInsert(ctx context.Context, b *tbcd.Block) (int64, error) {
	log.Tracef("BlockInsert")
	defer log.Tracef("BlockInsert exit")

	const qBlockInsert = `
		WITH inserted AS (
			INSERT INTO blocks (hash, block)
			VALUES ($1, $2) RETURNING hash
		) SELECT bh.height FROM inserted i INNER JOIN block_headers bh ON bh.hash=i.hash;
	`
	rows, err := p.db.QueryContext(ctx, qBlockInsert, b.Hash, b.Block)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			return -1, database.DuplicateError(fmt.Sprintf("duplicate block entry: %s", err))
		}
		return -1, fmt.Errorf("failed to insert block: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var height int64
		if err := rows.Scan(&height); err != nil {
			return 0, err
		}
		return height, nil
	}

	return -1, errors.New("should not get here")
}

func (p *pgdb) PeersInsert(ctx context.Context, peers []tbcd.Peer) error {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	if len(peers) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("peers insert could not rollback db tx: %v",
				err)
			return
		}
	}()

	const qPeersInsert = `
		INSERT INTO peers (address, port, last_at)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING;
	`
	for k := range peers {
		result, err := tx.ExecContext(ctx, qPeersInsert, peers[k].Address,
			peers[k].Port, peers[k].LastAt)
		if err != nil {
			return fmt.Errorf("failed to insert peer: %v", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to insert peer rows affected: %v", err)
		}
		if rows < 1 {
			return fmt.Errorf("failed to insert peers rows: %v", rows)
		}
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	return nil
}

func (p *pgdb) PeerDelete(ctx context.Context, host, port string) error {
	log.Tracef("PeerDelete")
	defer log.Tracef("PeerDelete exit")

	qDeletePeer := fmt.Sprintf(`DELETE FROM peers WHERE address=$1 AND port=$2`)
	rows, err := p.db.QueryContext(ctx, qDeletePeer, host, port)
	if err != nil {
		return err
	}

	for rows.Next() {
		var count int
		if err := rows.Scan(&count); err != nil {
			return err
		}

		return database.NotFoundError("address not found")
	}

	if err := rows.Err(); err != nil {
		return err
	}

	return nil
}

func (p *pgdb) PeersRandom(ctx context.Context, count int) ([]tbcd.Peer, error) {
	log.Tracef("PeersRandom")
	defer log.Tracef("PeersRandom exit")

	const qSelectRandom = `SELECT * FROM peers ORDER BY RANDOM() LIMIT $1;`

	peers := make([]tbcd.Peer, 0, count)
	rows, err := p.db.QueryContext(ctx, qSelectRandom, count)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var peer tbcd.Peer
		if err := rows.Scan(&peer.Address, &peer.Port, &peer.LastAt, &peer.CreatedAt); err != nil {
			if err == sql.ErrNoRows {
				return nil, database.NotFoundError("peer data not found")
			}
			return nil, err
		}
		peers = append(peers, peer)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	return peers, nil
}
