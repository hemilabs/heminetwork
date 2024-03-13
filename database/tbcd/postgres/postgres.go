// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"sync"

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
	mtx sync.Mutex

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

func (p *pgdb) BlockHeadersByHeight(ctx context.Context, height uint64) ([]tbcd.BlockHeader, error) {
	log.Tracef("BlockHeadersByHeight")
	defer log.Tracef("BlockHeadersByHeight exit")

	return nil, fmt.Errorf("BlockHeadersByHeight not yet")
}

func (p *pgdb) BlocksMissing(ctx context.Context, count int) ([]tbcd.BlockIdentifier, error) {
	log.Tracef("BlocksMissing")
	defer log.Tracef("BlocksMissing exit")

	p.mtx.Lock()
	defer p.mtx.Unlock()

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		// Isolation: sql.LevelRepeatableRead,
		// Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return nil, err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("block headers missing could not rollback db tx: %v",
				err)
			return
		}
	}()

	s, err := tx.PrepareContext(ctx, `
		SELECT bh.hash,bh.height,bh.header,bh.created_at FROM block_headers bh
		WHERE NOT EXISTS (SELECT * FROM blocks b WHERE b.hash=bh.hash)
		ORDER BY bh.height ASC
		LIMIT $1;
	`)
	if err != nil {
		return nil, fmt.Errorf("could not prepare block headers missing: %v", err)
	}

	bis := make([]tbcd.BlockIdentifier, 0, count)
	rows, err := s.QueryContext(ctx, count)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var bi tbcd.BlockIdentifier
		if err := rows.Scan(&bi.Hash, &bi.Height); err != nil {
			if err == sql.ErrNoRows {
				return nil, database.NotFoundError("block missing data not found")
			}
			return nil, err
		}
		bis = append(bis, bi)
	}

	if rows.Err() != nil {
		return nil, rows.Err()
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return bis, nil
}

func (p *pgdb) BlockHeadersInsert(ctx context.Context, bhs []tbcd.BlockHeader) error {
	log.Tracef("BlockHeadersInsert")
	defer log.Tracef("BlockHeadersInsert exit")

	if len(bhs) == 0 {
		return nil
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		// Isolation: sql.LevelRepeatableRead,
		// Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return err
	}

	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("block headers insert could not rollback db tx: %v",
				err)
			return
		}
	}()

	s, err := tx.PrepareContext(ctx, `
		INSERT INTO block_headers (hash, height, header)
		VALUES ($1, $2, $3)
	`)
	if err != nil {
		return fmt.Errorf("could not prepare block headers insert: %v", err)
	}
	for k := range bhs {
		result, err := s.ExecContext(ctx, bhs[k].Hash, bhs[k].Height,
			bhs[k].Header)
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

	p.mtx.Lock()
	defer p.mtx.Unlock()

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		// Isolation: sql.LevelRepeatableRead,
		// Isolation: sql.LevelSerializable,
	})
	if err != nil {
		return -1, err
	}
	defer func() {
		err := tx.Rollback()
		if err != nil && err != sql.ErrTxDone {
			log.Errorf("block insert could not rollback db tx: %v",
				err)
			return
		}
	}()

	s, err := tx.PrepareContext(ctx, `
		WITH inserted AS (
			INSERT INTO blocks (hash, block)
			VALUES ($1, $2) RETURNING hash
		) SELECT bh.height FROM inserted i INNER JOIN block_headers bh ON bh.hash=i.hash;
	`)
	if err != nil {
		return -1, fmt.Errorf("could not prepare block insert: %v", err)
	}
	rows, err := s.QueryContext(ctx, b.Hash, b.Block)
	if err != nil {
		if err, ok := err.(*pq.Error); ok && err.Code.Class().Name() == "integrity_constraint_violation" {
			return -1, database.DuplicateError(fmt.Sprintf("duplicate block entry: %s", err))
		}
		return -1, fmt.Errorf("failed to insert block: %v", err)
	}
	defer rows.Close()

	var height int64
	for rows.Next() {
		if err := rows.Scan(&height); err != nil {
			if err == sql.ErrNoRows {
				return -1, database.NotFoundError("block not found")
			}
			return -1, err
		}
	}
	if err := rows.Err(); err != nil {
		return -1, err
	}

	err = tx.Commit()
	if err != nil {
		return -1, err
	}

	return height, nil
}

func hp(host, port string) string {
	return net.JoinHostPort(host, port)
}

type ByAddress []tbcd.Peer

func (a ByAddress) Len() int { return len(a) }
func (a ByAddress) Less(i, j int) bool {
	return hp(a[i].Host, a[i].Port) < hp(a[j].Host, a[j].Port)
}
func (a ByAddress) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func (p *pgdb) PeersInsert(ctx context.Context, peers []tbcd.Peer) error {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	if len(peers) == 0 {
		return nil
	}

	// Sort peers to not upset pq when inserting large number of records
	// that are out of order. This does not work 100% but the remaining failures
	// will heal themselves due to all the retries.
	//
	// This looks pretty dumb but mostly works around this issue:
	// https://dba.stackexchange.com/questions/194756/deadlock-with-multi-row-inserts-despite-on-conflict-do-nothing/195220#195220
	sort.Sort(ByAddress(peers))

	tx, err := p.db.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelReadCommitted,
		// Isolation: sql.LevelRepeatableRead,
		// Isolation: sql.LevelSerializable,
	})
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

	s, err := tx.PrepareContext(ctx, `
		INSERT INTO PEERS (host, port, last_at)
		VALUES ($1, $2, $3)
		ON CONFLICT DO NOTHING;
	`)
	if err != nil {
		return fmt.Errorf("could not prepare peers insert: %v", err)
	}
	for k := range peers {
		result, err := s.ExecContext(ctx, peers[k].Host, peers[k].Port,
			peers[k].LastAt)
		if err != nil {
			return fmt.Errorf("failed to insert peer: %v", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to insert peer rows affected: %v", err)
		}
		if rows < 1 {
			return database.ZeroRowsError(fmt.Sprintf("failed to insert peers rows: %v", rows))
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

	qDeletePeer := fmt.Sprintf(`DELETE FROM peers WHERE host=$1 AND port=$2`)
	// XXX add prepared statement here
	rows, err := p.db.QueryContext(ctx, qDeletePeer, host, port)
	if err != nil {
		return err
	}

	for rows.Next() {
		var count int
		if err := rows.Scan(&count); err != nil {
			return err
		}

		return database.NotFoundError("host not found")
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
	// XXX add prepared statement here
	rows, err := p.db.QueryContext(ctx, qSelectRandom, count)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var peer tbcd.Peer
		if err := rows.Scan(&peer.Host, &peer.Port, &peer.LastAt, &peer.CreatedAt); err != nil {
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
