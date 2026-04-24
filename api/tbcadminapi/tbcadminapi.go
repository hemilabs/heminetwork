// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcadminapi

import (
	"context"
	"fmt"
	"maps"
	"reflect"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
)

const (
	APIVersion = 1

	CmdSyncIndexersToHashRequest = "tbcadmin-sync-indexers-to-hash-request"

	// Job lifecycle
	CmdJobStatusRequest = "tbcadmin-job-status-request"

	CmdJobSubscribeRequest = "tbcadmin-job-subscribe-request"

	CmdJobCancelRequest  = "tbcadmin-job-cancel-request"
	CmdJobCancelResponse = "tbcadmin-job-cancel-response"

	CmdJobListRequest  = "tbcadmin-job-list-request"
	CmdJobListResponse = "tbcadmin-job-list-response"

	// Server notification for job progress/completion
	CmdJobUpdateNotification = "tbcadmin-job-update-notification"
)

var (
	APIVersionRoute = fmt.Sprintf("v%d", APIVersion)
	RouteAdminWs    = fmt.Sprintf("/%s/admin/ws", APIVersionRoute)
)

// JobInfo is a summary of a job.
type JobInfo struct {
	JobID   string `json:"job_id"`
	JobType string `json:"job_type"`
	Status  string `json:"status"`
}

// JobStatusRequest asks for the current status of a job.
type JobStatusRequest struct {
	JobID string `json:"job_id"`
}

type JobSubscribeRequest struct {
	JobID string `json:"job_id"`
}

// JobCancelRequest asks the server to cancel a running job.
type JobCancelRequest struct {
	JobID string `json:"job_id"`
}

// JobCancelResponse is returned after a cancel attempt.
type JobCancelResponse struct {
	JobID string          `json:"job_id"`
	Error *protocol.Error `json:"error,omitempty"`
}

// JobListRequest asks the server to list all jobs.
type JobListRequest struct{}

// JobListResponse returns all known jobs.
type JobListResponse struct {
	Jobs  []JobInfo       `json:"jobs"`
	Error *protocol.Error `json:"error,omitempty"`
}

// JobUpdateNotification is pushed by the server to the client when a
// job's status changes. It uses the same message ID as the original
// JobUpdateNotification so the client can correlate.
type JobUpdateNotification struct {
	Job   JobInfo         `json:"job"`
	Error *protocol.Error `json:"error,omitempty"`
}

type SyncIndexersToHashRequest struct {
	Hash chainhash.Hash `json:"hash"`
}

var commands = map[protocol.Command]reflect.Type{
	CmdJobStatusRequest:      reflect.TypeFor[JobStatusRequest](),
	CmdJobCancelRequest:      reflect.TypeFor[JobCancelRequest](),
	CmdJobCancelResponse:     reflect.TypeFor[JobCancelResponse](),
	CmdJobListRequest:        reflect.TypeFor[JobListRequest](),
	CmdJobListResponse:       reflect.TypeFor[JobListResponse](),
	CmdJobSubscribeRequest:   reflect.TypeFor[JobSubscribeRequest](),
	CmdJobUpdateNotification: reflect.TypeFor[JobUpdateNotification](),

	CmdSyncIndexersToHashRequest: reflect.TypeFor[SyncIndexersToHashRequest](),
}

func init() {
	// Merge tbcapi commands so the admin connection can also serve all
	// normal TBC API requests as a superset.
	maps.Copy(commands, tbcapi.APICommands())
}

type tbcAdminAPI struct{}

func (a *tbcAdminAPI) Commands() map[protocol.Command]reflect.Type {
	return commands
}

func APICommands() map[protocol.Command]reflect.Type {
	return maps.Clone(commands)
}

// Write is the low level primitive of a protocol Write. One should generally
// not use this function and use WriteConn and Call instead.
func Write(ctx context.Context, c protocol.APIConn, id string, payload any) error {
	return protocol.Write(ctx, c, &tbcAdminAPI{}, id, payload)
}

// Read is the low level primitive of a protocol Read. One should generally
// not use this function and use ReadConn instead.
func Read(ctx context.Context, c protocol.APIConn) (protocol.Command, string, any, error) {
	return protocol.Read(ctx, c, &tbcAdminAPI{})
}

// Call is a blocking call. One should use ReadConn when using Call or else the
// completion will end up in the Read instead of being completed as expected.
func Call(ctx context.Context, c *protocol.Conn, payload any) (protocol.Command, string, any, error) {
	return c.Call(ctx, &tbcAdminAPI{}, payload)
}

// WriteConn writes to Conn. It is equivalent to Write but exists for symmetry
// reasons.
func WriteConn(ctx context.Context, c *protocol.Conn, id string, payload any) error {
	return c.Write(ctx, &tbcAdminAPI{}, id, payload)
}

// ReadConn reads from Conn and performs callbacks. One should use ReadConn over
// Read when mixing Write, WriteConn and Call.
func ReadConn(ctx context.Context, c *protocol.Conn) (protocol.Command, string, any, error) {
	return c.Read(ctx, &tbcAdminAPI{})
}
