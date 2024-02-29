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

func (p *pgdb) BtcHashHeightInsert(ctx context.Context, bhh []tbcd.BtcHashHeight) error {
	log.Tracef("BtcHashHeightInsert")
	defer log.Tracef("BtcHashHeightInsert exit")

	if len(bhh) == 0 {
		return nil
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("BtcHashHeightInsert could not rollback db tx: %v",
				err)
			return
		}
	}()

	const qBtcHashHeightInsert = `
		INSERT INTO btc_hash_height (hash, height)
		VALUES ($1, $2)
	`
	for k := range bhh {
		result, err := tx.ExecContext(ctx, qBtcHashHeightInsert, bhh[k].Hash,
			bhh[k].Height)
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
