// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/lib/pq"

	"github.com/hemilabs/heminetwork/database"
)

const (
	logLevel = "INFO"
	verbose  = false
)

var log = loggo.GetLogger("postgres")

func init() {
	loggo.ConfigureLoggers(logLevel)
}

type psqlNotification struct {
	name     database.NotificationName     // Expected notification type
	callback database.NotificationCallback // Callback for notification
	payload  reflect.Type                  // Payload type
}

type Database struct {
	mtx  sync.RWMutex
	ntfn map[database.NotificationName]*psqlNotification // Notification handlers

	listener        *pq.Listener   // Postgres listener
	listenerCloseCh chan struct{}  // Postgres listener close channel
	wg              sync.WaitGroup // Wait group for notification handler exit

	uri  string // database connection string
	pool *sql.DB
}

var _ database.Database = (*Database)(nil)

// Connect connects to a postgres database. This is only used in tests.
func Connect(ctx context.Context, uri string) (*sql.DB, error) {
	pool, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	if err := pool.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}
	return pool, nil
}

func (p *Database) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	p.mtx.Lock()
	if p.listenerCloseCh != nil {
		close(p.listenerCloseCh)
	}
	err := p.pool.Close()
	p.mtx.Unlock()

	p.wg.Wait()

	return err
}

func (p *Database) DB() *sql.DB {
	log.Tracef("DB")
	defer log.Tracef("DB exit")
	return p.pool
}

// ntfnWrapper is the data type of notifications that come from the database.
type ntfnWrapper struct {
	Table   string          `json:"table"`    // Table name
	Action  string          `json:"action"`   // Action that led to notification
	DataNew json.RawMessage `json:"data_new"` // JSON payload for new row
	DataOld json.RawMessage `json:"data_old"` // JSON payload for old row
}

func (p *Database) ntfnEventHandler(pqn *pq.Notification) {
	log.Tracef("ntfnEventHandler notify: %v", spew.Sdump(pqn))

	// A nil notification can be received on database shutdown.
	if pqn == nil {
		return
	}

	var nw ntfnWrapper
	if err := json.Unmarshal([]byte(pqn.Extra), &nw); err != nil {
		// We can't do much more than just logging it.
		log.Errorf("ntfnEventHandler unmarshal error: %v", err)
		return
	}
	// log.Tracef("%v", spew.Sdump(nw))

	p.mtx.RLock()
	pn, ok := p.ntfn[database.NotificationName(nw.Table)]
	p.mtx.RUnlock()

	// This notification was for a table/event that we have not registered
	// for, so ignore it.
	if !ok {
		return
	}

	// Convert JSON to structure.
	payloadNew := reflect.New(pn.payload).Interface()
	if err := json.Unmarshal([]byte(nw.DataNew), &payloadNew); err != nil {
		log.Errorf("ntfnEventHandler decode: %v", err)
		return
	}

	payloadOld := reflect.Zero(reflect.PtrTo(pn.payload)).Interface()
	if len(nw.DataOld) > 0 && !bytes.Equal(nw.DataOld, []byte("null")) {
		payloadOld = reflect.New(pn.payload).Interface()
		if err := json.Unmarshal([]byte(nw.DataOld), &payloadOld); err != nil {
			log.Errorf("ntfnEventHandler decode: %v", err)
			return
		}
	}

	log.Debugf("ntfnEventHandler: calling callback %v %v", nw.Action, nw.Table)
	log.Tracef("ntfnEventHandler: payload new %v", spew.Sdump(payloadNew))
	log.Tracef("ntfnEventHandler: payload old %v", spew.Sdump(payloadOld))

	pn.callback(nw.Table, nw.Action, payloadNew, payloadOld)
}

// ntfnListenHandler listens for database notifications.
func (p *Database) ntfnListenHandler(ctx context.Context) {
	log.Tracef("ntfnListenHandler")
	defer func() {
		// Close listener
		if err := p.listener.Close(); err != nil {
			log.Errorf("ntfnListenHandler close listener: %v", err)
		}

		p.mtx.Lock()
		p.listener = nil
		p.mtx.Unlock()

		p.wg.Done()

		log.Tracef("ntfnListenHandler exit")
	}()

	for {
		select {
		case <-ctx.Done():
			log.Tracef("ntfnListenHandler: context done")
			return

		case <-p.listenerCloseCh:
			log.Tracef("ntfnListenHandler: closing listener")
			return

		case pqn := <-p.listener.Notify:
			// TODO: Consider limiting the number of notifications being
			// processed at the same time.
			go p.ntfnEventHandler(pqn)

		case <-time.After(60 * time.Second):
			go func() {
				// log.Tracef("ntfnHandler: ping")
				p.listener.Ping()
			}()
		}
	}
}

// RegisterNotification registers a call back for database notifications.
//
// Note that this currently launches a connection+go routine to listen for
// notifications. It may be an idea to switch this code to only launch a single
// go routine for all notifications.
func (p *Database) RegisterNotification(ctx context.Context, n database.NotificationName, f database.NotificationCallback, payload any) error {
	log.Tracef("RegisterNotification")

	p.mtx.Lock()
	defer p.mtx.Unlock()

	if _, ok := p.ntfn[n]; ok {
		return fmt.Errorf("notification already registered: %v", n)
	}

	pn := &psqlNotification{
		name:     n,
		callback: f,
		payload:  reflect.TypeOf(payload),
	}
	log.Tracef("RegisterNotification: %v", n)
	p.ntfn[n] = pn

	if p.listener == nil {
		// XXX this might have to become a callback as well.
		reportProblem := func(ev pq.ListenerEventType, err error) {
			if err != nil {
				log.Debugf("notification error %v", spew.Sdump(ev))
				log.Errorf("notification error (%v): %v", n, err)
			}
		}

		p.listener = pq.NewListener(p.uri, 10*time.Second, time.Minute,
			reportProblem)
		if err := p.listener.Listen("events"); err != nil {
			return err
		}
		p.listenerCloseCh = make(chan struct{})

		p.wg.Add(1)
		go p.ntfnListenHandler(ctx)
	}

	return nil
}

func (p *Database) UnregisterNotification(n database.NotificationName) error {
	log.Tracef("UnregisterNotification")
	defer log.Tracef("UnregisterNotification exit")

	p.mtx.Lock()
	defer p.mtx.Unlock()

	if _, ok := p.ntfn[n]; !ok {
		return fmt.Errorf("handler not found: %v", n)
	}
	delete(p.ntfn, n)

	if len(p.ntfn) == 0 && p.listenerCloseCh != nil {
		close(p.listenerCloseCh)
		p.listenerCloseCh = nil
	}

	return nil
}

func New(ctx context.Context, puri string, version int) (*Database, error) {
	log.Tracef("New")
	defer log.Tracef("New exit")

	// Setup and connect to database.
	pool, err := sql.Open("postgres", puri)
	if err != nil {
		return nil, fmt.Errorf("postgres open: %w", err)
	}
	pool.SetConnMaxLifetime(0)
	pool.SetMaxIdleConns(5)
	pool.SetMaxOpenConns(5)
	if err := pool.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	// Verify version.
	const selectVersion = `SELECT * FROM version LIMIT 1;`
	var dbVersion int
	if err := pool.QueryRowContext(ctx, selectVersion).Scan(&dbVersion); err != nil {
		return nil, err
	}
	if version != dbVersion {
		return nil, fmt.Errorf("wrong database version: expected %v, got %v", version, dbVersion)
	}

	return &Database{
		pool: pool,
		uri:  puri,
		ntfn: make(map[database.NotificationName]*psqlNotification),
	}, nil
}
