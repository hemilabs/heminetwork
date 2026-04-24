// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync"

	tapi "github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
)

var ErrJobNotFound = errors.New("job not found")

type jobStatus string

const (
	JobStatusPending   jobStatus = "pending"
	JobStatusRunning   jobStatus = "running"
	JobStatusCompleted jobStatus = "completed"
	JobStatusFailed    jobStatus = "failed"
)

type jobType string

const SyncIndexersToHashJob jobType = "sync-indexers-to-hash"

type JobRunFunc func(context.Context, string)

// Jobs are long-lived tasks that keep a status of their execution.
// They should generally not be maintained on their own, and one
// should instead manage and interact with them using an AdminHub.
//
// A new job is `pending`, should be `running` when executing,
// and can either become `completed` or `failed`, depending on
// whether it succeeds or fails.
//
// Jobs keep a JobRunFunc that holds the logic for it's own
// execution. They keep track of its own context, and can be
// cancelled mid-execution.
type job struct {
	jobType jobType
	status  jobStatus
	run     JobRunFunc
	ctx     context.Context
	cancel  context.CancelFunc
}

func (j *job) updateStatus(js jobStatus) {
	j.status = js
}

func (j *job) info() (jobType, jobStatus) {
	return j.jobType, j.status
}

// Clients are subscribers to jobs and get notified by them.
// They should generally not be maintained on their own, and one
// should instead manage and interact with them using an AdminHub.
//
// Clients have a single notifier (through which jobs can notify them),
// as well as a single listener (where they can listen for notifications
// from every job they are subscribed to).
type client struct {
	notifier *Notifier
	listener *Listener
}

// AdminHub manages jobs, clients, and the communication between them.
//
// It keeps track of every job, client, and their subscriptions. For
// subscriptions, the hub keeps a map of JobIDs that ultimately map to
// the notifier of every subscribed client.
//
// Most actions related to jobs and clients should be performed using the
// AdminHub's methods, including: job and client creation / deletion,
// subscribing / unsubscribing, job execution / cancellation, and
// client notification.
type AdminHub struct {
	mtx sync.RWMutex
	ctx context.Context // Long-lived context

	// JobID -> Job
	jobs map[string]*job

	// ClientID -> Client
	sessions map[string]*client

	// JobID -> ClientID -> Client Notifier
	subscriptions map[string]map[string]*Notifier
}

func NewHub(ctx context.Context) *AdminHub {
	return &AdminHub{
		jobs:          make(map[string]*job),
		sessions:      make(map[string]*client),
		subscriptions: make(map[string]map[string]*Notifier),
		ctx:           ctx,
	}
}

func (h *AdminHub) NewJob(jt jobType, jr JobRunFunc) (string, error) {
	jctx, cancel := context.WithCancel(h.ctx)
	j := &job{
		jobType: jt,
		run:     jr,
		status:  JobStatusPending,
		ctx:     jctx,
		cancel:  cancel,
	}

	for {
		// Create random hexadecimal string to use as an ID
		id, err := randHexId(16)
		if err != nil {
			cancel()
			return "", fmt.Errorf("generate job id: %w", err)
		}

		// Ensure the key is not already in use, if it is then try again.
		h.mtx.Lock()
		if _, ok := h.jobs[id]; ok {
			h.mtx.Unlock()
			continue
		}
		h.jobs[id] = j
		h.mtx.Unlock()

		return id, nil
	}
}

func (h *AdminHub) DeleteJob(jobID string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	delete(h.subscriptions, jobID)

	if job, ok := h.jobs[jobID]; ok {
		job.cancel()
		delete(h.jobs, jobID)
	}
}

func (h *AdminHub) StartJob(jobID string) error {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	j, ok := h.jobs[jobID]
	if !ok {
		return ErrJobNotFound
	}

	go j.run(j.ctx, jobID)
	return nil
}

func (h *AdminHub) JobStatus(jobID string) (tapi.JobInfo, error) {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	j, ok := h.jobs[jobID]
	if !ok {
		return tapi.JobInfo{}, ErrJobNotFound
	}

	tp, st := j.info()
	return tapi.JobInfo{
		JobID:   jobID,
		JobType: string(tp),
		Status:  string(st),
	}, nil
}

func (h *AdminHub) JobList() []tapi.JobInfo {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	jobList := make([]tapi.JobInfo, 0, len(h.jobs))
	for id, j := range h.jobs {
		tp, st := j.info()
		jobList = append(jobList, tapi.JobInfo{
			JobID:   id,
			JobType: string(tp),
			Status:  string(st),
		})
	}
	return jobList
}

func (h *AdminHub) CancelJob(jobID string) error {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	j, ok := h.jobs[jobID]
	if !ok {
		return ErrJobNotFound
	}

	j.cancel()
	return nil
}

func (h *AdminHub) NewSession(ctx context.Context, blocking bool) (string, *Listener, error) {
	client := &client{
		notifier: NewNotifier(blocking),
	}

	var err error
	client.listener, err = client.notifier.Subscribe(ctx, 10)
	if err != nil {
		return "", nil, err
	}

	for {
		// Create random hexadecimal string to use as an ID
		id, err := randHexId(16)
		if err != nil {
			client.listener.Unsubscribe()
			return "", nil, fmt.Errorf("generate admin session id: %w", err)
		}

		// Ensure the key is not already in use, if it is then try again.
		h.mtx.Lock()
		if _, ok := h.sessions[id]; ok {
			h.mtx.Unlock()
			continue
		}
		h.sessions[id] = client
		h.mtx.Unlock()

		return id, client.listener, nil
	}
}

func (h *AdminHub) IsSubscribed(clientID, jobID string) bool {
	h.mtx.RLock()
	defer h.mtx.RUnlock()

	if _, ok := h.subscriptions[jobID]; !ok {
		return false
	}

	_, ok := h.subscriptions[jobID][clientID]
	return ok
}

func (h *AdminHub) DeleteSession(clientID string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if client, ok := h.sessions[clientID]; ok {
		client.listener.Unsubscribe()
		delete(h.sessions, clientID)
	}

	// This isn't great, but the alternative is having a reverse
	// map to lookup subscriptions by clientID, and this should never
	// get particularly big.
	for jid := range h.subscriptions {
		delete(h.subscriptions[jid], clientID)
	}
}

func (h *AdminHub) Subscribe(clientID, jobID string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	_, ok := h.jobs[jobID]
	if !ok {
		return
	}

	client, ok := h.sessions[clientID]
	if !ok {
		return
	}

	if _, ok = h.subscriptions[jobID]; !ok {
		h.subscriptions[jobID] = make(map[string]*Notifier)
	}
	if _, ok := h.subscriptions[jobID][clientID]; !ok {
		h.subscriptions[jobID][clientID] = client.notifier
	}
}

// Unsubscribe unsubscribes a client from a job's notifications.
// Unsubscribing is not enough to unblock a job waiting to notify
// this client. That requires cancelling the job's notifier context,
// which is done explicitly when deleting the session.
func (h *AdminHub) Unsubscribe(clientID, jobID string) {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if _, ok := h.subscriptions[jobID]; ok {
		delete(h.subscriptions[jobID], clientID)
	}
}

// BroadcastProgress sends a message to clients subscribed to a specific job.
// This is best effort: if a client subscribes during the notification process,
// they will not be notified. Deleting or unsubscribing from a job during the
// notification process does not stop the notifications from being sent.
func (h *AdminHub) BroadcastProgress(ctx context.Context, jobID string, status jobStatus) error {
	h.mtx.RLock()
	job, hasJobs := h.jobs[jobID]
	if !hasJobs {
		h.mtx.RUnlock()
		return ErrJobNotFound
	}

	_, hasSubs := h.subscriptions[jobID]
	if !hasSubs {
		job.updateStatus(status)
		h.mtx.RUnlock()
		return nil
	}

	tp, _ := job.info()
	job.updateStatus(status)

	subs := maps.Clone(h.subscriptions[jobID])
	h.mtx.RUnlock()

	msg := NotificationJob(jobID, tp, status)

	for _, n := range subs {
		if err := n.Notify(ctx, msg); err != nil {
			if !errors.Is(err, context.Canceled) {
				return err
			}
		}
	}
	return nil
}
