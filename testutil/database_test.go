// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"context"
	"database/sql"
	"testing"
)

// TestCreateTestDB tests the CreateTestDB function.
func TestCreateTestDB(t *testing.T) {
	ctx := context.Background()

	// Test that CreateTestDB returns expected types and cleanup function
	db, sdb, cleanup := CreateTestDB(ctx, t)
	defer cleanup()

	// Verify that we got valid database objects
	if db == nil {
		t.Fatal("Expected non-nil database interface")
	}
	if sdb == nil {
		t.Fatal("Expected non-nil sql.DB")
	}

	// Test that cleanup function is callable
	if cleanup == nil {
		t.Fatal("Expected non-nil cleanup function")
	}

	// Test basic database operations
	count, err := L2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatalf("Failed to get count: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 keystones in new database, got %d", count)
	}
}

// TestL2KeystonesCount tests the L2KeystonesCount function
func TestL2KeystonesCount(t *testing.T) {
	ctx := context.Background()
	_, sdb, cleanup := CreateTestDB(ctx, t)
	defer cleanup()

	// Test count on empty database
	count, err := L2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatalf("Failed to get count: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 keystones in empty database, got %d", count)
	}

	// Test with invalid database connection
	invalidDB := &sql.DB{} // This will cause an error when used
	_, err = L2KeystonesCount(ctx, invalidDB)
	if err == nil {
		t.Fatal("Expected error with invalid database connection")
	}
}

// TestApplySQLFiles tests the ApplySQLFiles function
func TestApplySQLFiles(t *testing.T) {
	ctx := context.Background()
	_, sdb, cleanup := CreateTestDB(ctx, t)
	defer cleanup()

	// Test with non-existent path
	ApplySQLFiles(ctx, t, sdb, "/non/existent/path/*.sql")
	// This should fail with a file not found error, but the test framework
	// will handle the failure appropriately

	// Test with valid SQL files (this would require actual SQL files)
	// For now, we just test that the function exists and can be called
	// In a real test environment, you would have actual SQL files to test with
}

// TestDatabaseOperations tests various database operations
func TestDatabaseOperations(t *testing.T) {
	ctx := context.Background()
	db, sdb, cleanup := CreateTestDB(ctx, t)
	defer cleanup()

	// Test that we can perform basic database operations
	// This is a basic smoke test to ensure the database is working

	// Test that we can execute a simple query
	_, err := sdb.ExecContext(ctx, "SELECT 1")
	if err != nil {
		t.Fatalf("Failed to execute simple query: %v", err)
	}

	// Test that we can use the typed database interface
	// This would depend on the specific methods available in the bfgd.Database interface
	// For now, we just verify that the interface is not nil
	if db == nil {
		t.Fatal("Database interface is nil")
	}
}

// TestCreateTestDBWithURI tests the CreateTestDBWithURI function.
func TestCreateTestDBWithURI(t *testing.T) {
	ctx := context.Background()

	// Test that CreateTestDBWithURI returns expected types and cleanup function
	db, uri, sdb, cleanup := CreateTestDBWithURI(ctx, t)
	defer cleanup()

	// Verify that we got valid database objects
	if db == nil {
		t.Fatal("Expected non-nil database interface")
	}
	if sdb == nil {
		t.Fatal("Expected non-nil sql.DB")
	}
	if uri == "" {
		t.Fatal("Expected non-empty database URI")
	}

	// Test that cleanup function is callable
	if cleanup == nil {
		t.Fatal("Expected non-nil cleanup function")
	}

	// Test basic database operations
	count, err := L2KeystonesCount(ctx, sdb)
	if err != nil {
		t.Fatalf("Failed to get count: %v", err)
	}
	if count != 0 {
		t.Errorf("Expected 0 keystones in new database, got %d", count)
	}
}
