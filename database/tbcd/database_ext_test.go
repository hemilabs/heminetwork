// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd_test

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/hemilabs/heminetwork/database/tbcd/postgres"
)

const testDBPrefix = "tbcdtestdb"

func createTestDB(ctx context.Context, t *testing.T) (tbcd.Database, *sql.DB, func()) {
	t.Helper()

	pgURI := os.Getenv("PGTESTURI")
	if pgURI == "" {
		t.Skip("PGTESTURI environment variable is not set, skipping...")
	}

	var (
		cleanup     func()
		ddb, sdb    *sql.DB
		needCleanup = true
	)
	defer func() {
		if !needCleanup {
			return
		}
		if sdb != nil {
			sdb.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		if ddb != nil {
			ddb.Close()
		}
	}()

	ddb, err := postgres.Connect(ctx, pgURI)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	dbn := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(9999)
	dbName := fmt.Sprintf("%v_%d", testDBPrefix, dbn)

	t.Logf("Creating test database %v", dbName)

	qCreateDB := fmt.Sprintf("CREATE DATABASE %v", dbName)
	if _, err := ddb.ExecContext(ctx, qCreateDB); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup = func() {
		t.Logf("Removing test database %v", dbName)
		qDropDB := fmt.Sprintf("DROP DATABASE %v", dbName)
		if _, err := ddb.ExecContext(ctx, qDropDB); err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		ddb.Close()
	}

	u, err := url.Parse(pgURI)
	if err != nil {
		t.Fatalf("Failed to parse postgresql URI: %v", err)
	}
	u.Path = dbName

	sdb, err = postgres.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Load schema.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	applySQLFiles(ctx, t, sdb, filepath.Join(wd, "./scripts/*.sql"))

	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	needCleanup = false

	return db, sdb, cleanup
}

func applySQLFiles(ctx context.Context, t *testing.T, sdb *sql.DB, path string) {
	t.Helper()

	sqlFiles, err := filepath.Glob(path)
	if err != nil {
		t.Fatalf("Failed to get schema files: %v", err)
	}
	sort.Strings(sqlFiles)
	for _, sqlFile := range sqlFiles {
		t.Logf("Applying SQL file %v", filepath.Base(sqlFile))
		sql, err := ioutil.ReadFile(sqlFile)
		if err != nil {
			t.Fatalf("Failed to read SQL file: %v", err)
		}
		if _, err := sdb.ExecContext(ctx, string(sql)); err != nil {
			t.Fatalf("Failed to execute SQL: %v", err)
		}
	}
}

func TestDatabaseTestData(t *testing.T) {
	ctx := context.Background()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	// Load test data.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	applySQLFiles(ctx, t, sdb, filepath.Join(wd, "./scripts/testdata/*.sql"))
}

func TestDatabasePostgres(t *testing.T) {
	ctx := context.Background()

	db, sdb, cleanup := createTestDB(ctx, t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	// Version, no need to verify because it is explicitely tested on db open
	version, err := db.Version(ctx)
	if err != nil {
		t.Fatalf("Failed to get Version: %v", err)
	}
	t.Logf("db version: %v", version)
}