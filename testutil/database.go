// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"

	bfgd "github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
)

const testDBPrefix = "bfgdtestdb"

// CreateTestDB creates a temporary Postgres database for tests and returns:
// - typed database interface
// - raw *sql.DB connection for executing SQL directly
// - cleanup function to drop the test database
func CreateTestDB(ctx context.Context, t *testing.T) (bfgd.Database, *sql.DB, func()) {
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
			_ = sdb.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		if ddb != nil {
			_ = ddb.Close()
		}
	}()

	var err error
	ddb, err = postgres.Connect(ctx, pgURI)
	if err != nil {
		t.Skipf("PostgreSQL server is not available: %v", err)
	}

	dbName := fmt.Sprintf("%v_%d", testDBPrefix, os.Getpid())
	t.Logf("Creating test database %v", dbName)

	if _, err := ddb.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %v", dbName)); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup = func() {
		t.Logf("Removing test database %v", dbName)
		if _, err := ddb.ExecContext(ctx, fmt.Sprintf("DROP DATABASE %v", dbName)); err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		_ = ddb.Close()
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

	// Load schema from bfgd scripts
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	ApplySQLFiles(ctx, t, sdb, filepath.Join(wd, "../../database/bfgd/scripts/*.sql"))

	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	needCleanup = false
	return db, sdb, cleanup
}

// CreateTestDBWithURI creates a temporary Postgres database for tests and returns:
// - typed database interface
// - database URI string
// - raw *sql.DB connection for executing SQL directly
// - cleanup function to drop the test database
func CreateTestDBWithURI(ctx context.Context, t *testing.T) (bfgd.Database, string, *sql.DB, func()) {
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
			_ = sdb.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		if ddb != nil {
			_ = ddb.Close()
		}
	}()

	var err error
	ddb, err = postgres.Connect(ctx, pgURI)
	if err != nil {
		t.Skipf("PostgreSQL server is not available: %v", err)
	}

	dbName := fmt.Sprintf("%v_%d", testDBPrefix, os.Getpid())
	t.Logf("Creating test database %v", dbName)

	if _, err := ddb.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %v", dbName)); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup = func() {
		t.Logf("Removing test database %v", dbName)
		if _, err := ddb.ExecContext(ctx, fmt.Sprintf("DROP DATABASE %v WITH (FORCE)", dbName)); err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		_ = ddb.Close()
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

	// Load schema from bfgd scripts
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	ApplySQLFiles(ctx, t, sdb, filepath.Join(wd, "../../database/bfgd/scripts/*.sql"))

	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	needCleanup = false
	return db, u.String(), sdb, cleanup
}

// ApplySQLFiles executes all SQL scripts matching the glob path against the given db.
func ApplySQLFiles(ctx context.Context, t *testing.T, sdb *sql.DB, path string) {
	t.Helper()

	sqlFiles, err := filepath.Glob(path)
	if err != nil {
		t.Fatalf("Failed to get schema files: %v", err)
	}
	sort.Strings(sqlFiles)

	for _, sqlFile := range sqlFiles {
		t.Logf("Applying SQL file %v", filepath.Base(sqlFile))
		sqlBytes, err := os.ReadFile(sqlFile)
		if err != nil {
			t.Fatalf("Failed to read SQL file: %v", err)
		}
		if _, err := sdb.ExecContext(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("Failed to execute SQL: %v", err)
		}
	}
}

// L2KeystonesCount returns count of rows in l2_keystones table.
func L2KeystonesCount(ctx context.Context, db *sql.DB) (int, error) {
	const selectCount = `SELECT COUNT(*) FROM l2_keystones;`

	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	var count int
	if err := conn.QueryRowContext(ctx, selectCount).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
