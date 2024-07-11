// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"github.com/hemilabs/heminetwork/hemi"
)

// EventHandler is a function that can handle an event.
type EventHandler = func(event EventType, data any)

// EventType represents a type of event.
type EventType int

const (
	// EventTypeMineKeystone is an event dispatched when a L2 keystone is being
	// mined.
	EventTypeMineKeystone EventType = iota + 1

	// EventTypeTransactionBroadcast is an event dispatched when a Bitcoin
	// transaction has been broadcast to the network.
	EventTypeTransactionBroadcast
)

// EventMineKeystone is the data for EventTypeMineKeystone.
type EventMineKeystone struct {
	Keystone *hemi.L2Keystone
}

// EventTransactionBroadcast is the data for EventTypeTransactionBroadcast.
type EventTransactionBroadcast struct {
	Keystone *hemi.L2Keystone
	TxHash   string
}

// RegisterEventHandler registers an event handler to receive all events
// dispatched by the miner. The dispatched events can be filtered by EventType
// when received.
func (m *Miner) RegisterEventHandler(handler EventHandler) {
	m.eventHandlersMtx.Lock()
	defer m.eventHandlersMtx.Unlock()
	m.eventHandlers = append(m.eventHandlers, handler)
}

// dispatchEvent calls all registered event handlers with the given eventType
// and data. It is recommended to call this function in a go routine to avoid
// blocking operation while the event is being dispatched, as all event handlers
// will be executed synchronously.
func (m *Miner) dispatchEvent(eventType EventType, data any) {
	m.eventHandlersMtx.RLock()
	defer m.eventHandlersMtx.RUnlock()
	for _, handler := range m.eventHandlers {
		handler(eventType, data)
	}
}
