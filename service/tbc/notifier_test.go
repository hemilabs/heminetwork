package tbc

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

func TestNotifier(t *testing.T) {
	type testTableItem struct {
		name      string
		block     bool
		capacity  uint64
		listeners []bool // if listener should listen for messages
		messages  int
		deadlock  bool
	}

	tests := []testTableItem{
		{
			name:     "no listeners",
			block:    true,
			capacity: 0,
			messages: 5,
		},
		{
			name:      "single blocking",
			block:     true,
			capacity:  5,
			listeners: []bool{true},
			messages:  10,
		},
		{
			name:      "single blocking timeout",
			block:     true,
			capacity:  5,
			listeners: []bool{false},
			messages:  10,
			deadlock:  true,
		},
		{
			name:      "single non blocking",
			block:     false,
			capacity:  5,
			listeners: []bool{false},
			messages:  10,
		},
		{
			name:      "many blocking",
			block:     true,
			capacity:  5,
			listeners: []bool{true, true, true, true},
			messages:  10,
		},
		{
			name:      "many blocking timeout",
			block:     true,
			capacity:  5,
			listeners: []bool{true, true, false, false},
			messages:  10,
			deadlock:  true,
		},
		{
			name:      "many non blocking",
			block:     false,
			capacity:  5,
			listeners: []bool{true, true, false, false},
			messages:  10,
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				var finished bool
				context.AfterFunc(ctx, func() {
					finished = true
				})

				n := NewNotifier(tti.block)

				for _, listen := range tti.listeners {
					l, err := n.Subscribe(ctx, tti.capacity)
					if err != nil {
						panic(err)
					}
					go func() {
						defer l.Unsubscribe()
						if listen {
							for {
								select {
								case <-ctx.Done():
									return
								case <-l.Listen():
								}
							}
						}
						<-ctx.Done()
					}()
				}

				go func() {
					for range tti.messages {
						if err := n.Notify(ctx, notification("test")); err != nil {
							if !errors.Is(err, context.Canceled) {
								panic(err)
							}
							return
						}
					}
					cancel()
				}()

				synctest.Wait()

				if !tti.deadlock && !finished {
					t.Fatal("test deadlocked")
				} else if tti.deadlock && finished {
					t.Fatal("expected test deadlock")
				}
			})
		})
	}
}

func TestNotifierUnsubscribe(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		n := NewNotifier(true)

		l, err := n.Subscribe(ctx, 0)
		if err != nil {
			panic(err)
		}

		var sent bool
		go func() {
			if err := n.Notify(ctx, notification("test")); err != nil {
				panic(err)
			}
			sent = true
		}()

		synctest.Wait()
		if sent {
			t.Fatal("expected notifications to be blocked")
		}

		l.Unsubscribe()

		synctest.Wait()
		if !sent {
			t.Fatal("notifications still blocked after unsubscribe")
		}
	})
}
