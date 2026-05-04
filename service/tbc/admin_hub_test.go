// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/davecgh/go-spew/spew"
)

func TestHubSubscribe(t *testing.T) {
	const subCount = 3
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		h := NewHub(ctx)

		cid, l, err := h.NewSession(ctx, true)
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		jrun := func(jctx context.Context, id string) {
			defer wg.Done()
			if err := h.BroadcastProgress(jctx, id, JobStatusCompleted); err != nil {
				panic(err)
			}
		}

		// Create some jobs and subscribe to all but one
		subIDs := make(map[string]struct{})
		for i := range subCount + 1 {
			jid, err := h.NewJob(SyncIndexersToHashJob, jrun)
			if err != nil {
				t.Fatal(err)
			}
			if i < subCount {
				h.Subscribe(cid, jid)
				subIDs[jid] = struct{}{}
			}
			wg.Add(1)
			if err := h.StartJob(jid); err != nil {
				t.Fatal(err)
			}
		}

		// Check if we received the correct notifications
		for range subCount {
			msg, err := l.Listen(ctx)
			if err != nil {
				t.Fatal(err)
			}

			// sanity check
			if !h.IsSubscribed(cid, msg.ID) {
				t.Fatalf("unexpected notification from %s", msg.ID)
			}
			if msg.Msg != string(JobStatusCompleted) {
				t.Fatalf("got %s, wanted %s", msg.Msg, JobStatusCompleted)
			}
			if msg.Type != string(SyncIndexersToHashJob) {
				t.Fatalf("got %s, wanted %s", msg.Type, SyncIndexersToHashJob)
			}
			h.Unsubscribe(cid, msg.ID)
		}

		// send notifications again after unsubscribing
		for jid := range subIDs {
			wg.Add(1)
			if err := h.StartJob(jid); err != nil {
				t.Fatal(err)
			}
		}

		wg.Wait()

		tctx, cancel := context.WithCancel(ctx)
		go func() {
			msg, err := l.Listen(tctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					panic(err)
				}
				return
			}
			panic("message received: " + spew.Sdump(msg))
		}()

		synctest.Wait()
		cancel()
	})
}

func TestHubJobLifecycle(t *testing.T) {
	const jobCount = 3

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	h := NewHub(ctx)
	cid, l, err := h.NewSession(ctx, true)
	if err != nil {
		t.Fatal(err)
	}

	// Not found errors
	if err := h.StartJob("fake"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
	}
	if err := h.CancelJob("fake"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
	}
	if _, err := h.JobStatus("fake"); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
	}
	err = h.BroadcastProgress(ctx, "fake", JobStatusFailed)
	if !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
	}

	// Get current jobs
	jobs := h.JobList()
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs, got %d", len(jobs))
	}

	// Create multiple jobs
	var wg sync.WaitGroup
	jobIDs := make(map[string]bool)
	for range jobCount {
		jrun := func(jctx context.Context, id string) {
			// Decrement wg to ensure job is running
			wg.Done()

			// Wait for job to be cancelled
			<-jctx.Done()

			// Broadcast cancellation to client
			if err := h.BroadcastProgress(ctx, id, JobStatusFailed); err != nil {
				panic(err)
			}
		}

		jid, err := h.NewJob(SyncIndexersToHashJob, jrun)
		if err != nil {
			t.Fatal(err)
		}

		jobIDs[jid] = false
		h.Subscribe(cid, jid)

		wg.Add(1)
		if err := h.StartJob(jid); err != nil {
			t.Fatal(err)
		}
	}

	// Wait for all jobs to start
	wg.Wait()

	// Ensure every job is in the hub
	jobs = h.JobList()
	if len(jobs) != jobCount {
		t.Fatalf("expected %d jobs, got %d", jobCount, len(jobs))
	}

	for _, j := range jobs {
		found, ok := jobIDs[j.JobID]
		if !ok {
			t.Fatalf("unexpected job %s", j.JobID)
		}
		if found {
			t.Fatalf("job duplicate %s", j.JobID)
		}

		// Cancel the job
		if err := h.CancelJob(j.JobID); err != nil {
			t.Fatal(err)
		}

		// Mark job as found to ensure there are no duplicates in the
		// hub's job list
		jobIDs[j.JobID] = true
	}

	// Client listens for every cancellation broadcast
	for range jobCount {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Msg != string(JobStatusFailed) {
			t.Fatalf("got %s, wanted %s", msg.Msg, JobStatusCompleted)
		}
		if !h.IsSubscribed(cid, msg.ID) {
			t.Fatalf("unexpected notification from %s", msg.ID)
		}

		// Delete the job
		h.DeleteJob(msg.ID)

		// Post-deletion checks
		if h.IsSubscribed(cid, msg.ID) {
			t.Fatalf("client still subscribed after job deletion: %s", msg.ID)
		}
		if err := h.StartJob(msg.ID); !errors.Is(err, ErrJobNotFound) {
			t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
		}
		if err := h.CancelJob(msg.ID); !errors.Is(err, ErrJobNotFound) {
			t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
		}
		if _, err := h.JobStatus(msg.ID); !errors.Is(err, ErrJobNotFound) {
			t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
		}
		err = h.BroadcastProgress(ctx, "fake", JobStatusFailed)
		if !errors.Is(err, ErrJobNotFound) {
			t.Fatalf("unexpected err %v, wanted %v", err, ErrJobNotFound)
		}
	}

	// Make sure no jobs are returned
	jobs = h.JobList()
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs, got %d", len(jobs))
	}
}

func TestHubMultipleBroadcasters(t *testing.T) {
	tests := []struct {
		name           string
		numSubscribers int
	}{
		{
			name:           "no subscribers",
			numSubscribers: 0,
		},
		{
			name:           "single subscriber",
			numSubscribers: 1,
		},
		{
			name:           "multiple subscribers",
			numSubscribers: 3,
		},
	}

	// This test guarantees that the clients receive the notifications,
	// that a job doesn't block during notifications if it has no
	// subscriptions, and that unsubscribed notifiers don't receive
	// notifications from the job.
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()

				h := NewHub(ctx)

				var wg sync.WaitGroup
				jrun := func(jctx context.Context, id string) {
					if err := h.BroadcastProgress(jctx, id, JobStatusRunning); err != nil {
						panic(err)
					}

					// If the clients receive the next notification after being
					// unsubscribed, they will panic. Depending on the order of
					// execution, the job may move into the next notification
					// before the clients unsubscribe. As such, explicitly wait
					// for all of them to unsubscribe before sending the next one.
					wg.Wait()

					if err := h.BroadcastProgress(jctx, id, JobStatusCompleted); err != nil {
						panic(err)
					}
				}

				jid, err := h.NewJob(SyncIndexersToHashJob, jrun)
				if err != nil {
					t.Fatal(err)
				}

				// Create some clients and subscribe them
				listeners := make(map[string]*Listener, tt.numSubscribers)
				for range tt.numSubscribers {
					cid, l, err := h.NewSession(ctx, true)
					if err != nil {
						t.Fatal(err)
					}
					// Force the listener to be blocking (no buffer)
					h.sessions[cid].listener.ch = make(chan Notification)
					h.Subscribe(cid, jid)
					listeners[cid] = l
				}
				if err := h.StartJob(jid); err != nil {
					t.Fatal(err)
				}

				// Wait until job is blocked for notifying or ends
				synctest.Wait()

				// Ensure if no subscriptions, the job ended, and if
				// it has subscribers, it blocked during the first
				// notification.
				info, err := h.JobStatus(jid)
				if err != nil {
					t.Fatal(err)
				}
				if tt.numSubscribers > 0 && jobStatus(info.Status) != JobStatusRunning {
					t.Fatal("job did not wait for subscribers to listen")
				} else if tt.numSubscribers == 0 && jobStatus(info.Status) != JobStatusCompleted {
					t.Fatal("job blocked with no subscribers")
				}

				for cid, l := range listeners {
					wg.Add(1)
					go func() {
						for {
							msg, err := l.Listen(ctx)
							if err != nil {
								if !errors.Is(err, context.Canceled) {
									panic(err)
								}
								return
							}
							if msg.Msg != string(JobStatusRunning) {
								panic(fmt.Sprintf("status: got %s, wanted %s", msg.Msg, JobStatusRunning))
							}
							if msg.ID != jid {
								panic(fmt.Sprintf("jobID: got %s, wanted %s", msg.ID, jid))
							}
							h.Unsubscribe(cid, jid)
							wg.Done()
						}
					}()
				}

				synctest.Wait()
			})
		})
	}
}

func TestHubSubscribeIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		h := NewHub(ctx)

		jrun := func(jctx context.Context, id string) {
			if err := h.BroadcastProgress(jctx, id, JobStatusRunning); err != nil {
				panic(err)
			}
		}

		jid, err := h.NewJob(SyncIndexersToHashJob, jrun)
		if err != nil {
			t.Fatal(err)
		}

		cid, l, err := h.NewSession(ctx, true)
		if err != nil {
			t.Fatal(err)
		}

		// Subscribe multiple times.
		h.Subscribe(cid, jid)
		h.Subscribe(cid, jid)
		h.Subscribe(cid, jid)

		if err := h.StartJob(jid); err != nil {
			t.Fatal(err)
		}

		if !h.IsSubscribed(cid, jid) {
			t.Fatal("client should be subscribed")
		}

		var msgCount int
		go func() {
			// If client receives multiple messages
			// due to subscribing to the same job
			// multiple times, panic.
			for {
				_, err := l.Listen(ctx)
				if err != nil {
					if !errors.Is(err, context.Canceled) {
						panic(err)
					}
					return
				}
				if msgCount > 0 {
					panic("multiple messages received")
				}
				msgCount++
			}
		}()

		synctest.Wait()
	})
}

func TestHubDeleteSession(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		h := NewHub(ctx)

		var done bool
		jrun := func(jctx context.Context, id string) {
			if err := h.BroadcastProgress(jctx, id, JobStatusRunning); err != nil {
				panic(err)
			}
			done = true
		}

		jid, err := h.NewJob(SyncIndexersToHashJob, jrun)
		if err != nil {
			t.Fatal(err)
		}

		cid, _, err := h.NewSession(ctx, true)
		if err != nil {
			t.Fatal(err)
		}

		// Force the listener to be blocking (no buffer)
		h.sessions[cid].listener.ch = make(chan Notification)

		// Subscribe
		h.Subscribe(cid, jid)

		// Start the job
		if err := h.StartJob(jid); err != nil {
			t.Fatal(err)
		}

		// Wait until job is sending notification
		synctest.Wait()
		if done {
			t.Fatal("job did not wait for client listen")
		}

		// Delete Session
		h.DeleteSession(cid)

		// Check that notifier got unblocked
		synctest.Wait()
		if !done {
			t.Fatal("job still stuck after session deleted")
		}
	})
}

func TestHubNoop(t *testing.T) {
	ctx := t.Context()
	h := NewHub(ctx)

	h.Subscribe("fake_client", "fake_job")
	h.Unsubscribe("fake_client", "fake_job")
	h.DeleteJob("fake_job")
	h.DeleteSession("fake_client")
}
