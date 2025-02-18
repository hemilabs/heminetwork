// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package level

import (
	"context"
	"fmt"
)

// v2 upgrade the database from v1 to v2.
// Changes:
// Move utxoindexhash, txindexhash and keystoneindexhash from metadata database
// to their respective index databases.
func (l *ldb) v2(ctx context.Context) error {
	log.Tracef("v2")
	defer log.Tracef("v2 exit")

	//mdDB := l.pool[MetadataDB]
	//value, err := mdDB.Get([]byte(versionKey), nil)
	//if err != nil {
	//	return -1, fmt.Errorf("version: %w", err)
	//}

	log.Infof("Upgrading database from v1 to v2")

	return fmt.Errorf("not yet")
}
