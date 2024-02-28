// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"

	"github.com/hemilabs/heminetwork/database/postgres"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/juju/loggo"
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
