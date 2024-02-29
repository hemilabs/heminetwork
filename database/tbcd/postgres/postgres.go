// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"
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
