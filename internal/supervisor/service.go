// SPDX-License-Identifier: GPL-3.0-or-later

// Package supervisor is the control plane: it owns the store, the RPC surface
// and the worker set. It never opens an outbound protocol connection.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/version"
)

// Service implements the supervisor's RPC methods over a Store.
type Service struct {
	st store.Store

	startedAt time.Time

	mu      sync.RWMutex
	workers map[role.Role]WorkerStatus
}

// WorkerStatus is one worker's last known state, as reported over RPC.
type WorkerStatus struct {
	Role      role.Role `json:"role"`
	PID       int       `json:"pid"`
	Alive     bool      `json:"alive"`
	StartedAt time.Time `json:"started_at"`
	Rests     int       `json:"rests"`
}

// New builds a Service and registers its methods on d.
func New(st store.Store, d *rpc.Dispatcher) *Service {
	s := &Service{
		st:        st,
		startedAt: time.Now(),
		workers:   map[role.Role]WorkerStatus{},
	}
	for _, r := range role.WorkerRoles() {
		s.workers[r] = WorkerStatus{Role: r}
	}
	s.register(d)
	return s
}

func (s *Service) register(d *rpc.Dispatcher) {
	d.Register(rpc.MethodStatus, s.status)
	d.Register(rpc.MethodRoles, s.roles)
	d.Register(rpc.MethodJobsList, s.jobsList)
	d.Register(rpc.MethodJobsAdd, s.jobsAdd)
	d.Register(rpc.MethodJobsPause, s.jobsPause)
	d.Register(rpc.MethodJobsResume, s.jobsResume)
	d.Register(rpc.MethodJobsRemove, s.jobsRemove)
}

// StatusParams is the (empty) parameter set for sharza.status.
type StatusParams struct{}

// Status is the reply to sharza.status.
type Status struct {
	Version       string         `json:"version"`
	Commit        string         `json:"commit"`
	Role          role.Role      `json:"role"`
	PID           int            `json:"pid"`
	StartedAt     time.Time      `json:"started_at"`
	UptimeSeconds float64        `json:"uptime_seconds"`
	SchemaVersion int            `json:"schema_version"`
	Workers       []WorkerStatus `json:"workers"`
	Jobs          int            `json:"jobs"`
}

func (s *Service) status(context.Context, json.RawMessage) (any, error) {
	schema, err := s.st.SchemaVersion()
	if err != nil {
		return nil, fmt.Errorf("schema version: %w", err)
	}
	jobs, err := s.st.Jobs()
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	return Status{
		Version:       version.Version,
		Commit:        version.Commit,
		Role:          role.Supervisor,
		PID:           selfPID(),
		StartedAt:     s.startedAt,
		UptimeSeconds: time.Since(s.startedAt).Seconds(),
		SchemaVersion: schema,
		Workers:       s.workerSnapshot(),
		Jobs:          len(jobs),
	}, nil
}

// RolesReply advertises which roles this build supports.
type RolesReply struct {
	Available []role.Role `json:"available"`
	Workers   []role.Role `json:"workers"`
}

func (s *Service) roles(context.Context, json.RawMessage) (any, error) {
	return RolesReply{Available: role.All(), Workers: role.WorkerRoles()}, nil
}

func (s *Service) jobsList(context.Context, json.RawMessage) (any, error) {
	jobs, err := s.st.Jobs()
	if err != nil {
		return nil, fmt.Errorf("list jobs: %w", err)
	}
	return jobs, nil
}

// AddJobParams is the parameter set for sharza.jobs.add.
type AddJobParams struct {
	// ID is optional; the supervisor generates one when empty. Clients pass
	// it to make an add idempotent across a retry.
	ID   string   `json:"id"`
	Name string   `json:"name"`
	Size int64    `json:"size"`
	URIs []string `json:"uris"`
	// Verified must be false for any source without a content hash, such
	// as Gnutella. The client may request it, but the supervisor decides
	// what is stored, because getting this wrong is a data-integrity claim.
	Verified bool `json:"verified"`
}

// AddJobReply is the reply to sharza.jobs.add.
type AddJobReply struct {
	Job store.Job `json:"job"`
}

func (s *Service) jobsAdd(_ context.Context, params json.RawMessage) (any, error) {
	var p AddJobParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if len(p.URIs) == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "at least one uri is required")
	}
	if p.Size < 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "size must not be negative")
	}

	id := p.ID
	if id == "" {
		id = NewJobID()
	}
	if p.Name == "" {
		p.Name = id
	}

	// A client may request verification, but the supervisor decides what is
	// stored. Without a content hash there is nothing to verify against, so
	// a client-supplied "verified" flag is ignored rather than trusted:
	// getting this wrong is a data-integrity claim made to the user.
	verified := allSourcesHashed(p.URIs)

	j := store.Job{
		ID:       id,
		Name:     p.Name,
		State:    store.StateQueued,
		Size:     p.Size,
		URIs:     p.URIs,
		Verified: verified,
	}
	if err := s.st.AddJob(j); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			return nil, rpc.Errorf(rpc.CodeFailedPrecond, "job %s already exists", id)
		}
		return nil, fmt.Errorf("add job: %w", err)
	}
	return AddJobReply{Job: j}, nil
}

type jobIDParams struct {
	ID string `json:"id"`
}

func (s *Service) jobsPause(_ context.Context, params json.RawMessage) (any, error) {
	return s.setState(params, store.StatePaused)
}

func (s *Service) jobsResume(_ context.Context, params json.RawMessage) (any, error) {
	return s.setState(params, store.StateQueued)
}

// JobReply is the reply to a single-job mutation.
type JobReply struct {
	Job store.Job `json:"job"`
}

func (s *Service) setState(params json.RawMessage, want store.State) (any, error) {
	var p jobIDParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if p.ID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "id is required")
	}

	j, err := s.st.Job(p.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, rpc.Errorf(rpc.CodeFailedPrecond, "no such job %s", p.ID)
		}
		return nil, fmt.Errorf("get job: %w", err)
	}

	// Pausing a finished job is a client bug, not a race worth papering
	// over: the job can never resume, so the call must say so.
	if j.State.Terminal() {
		return nil, rpc.Errorf(rpc.CodeFailedPrecond,
			"job %s is %s and cannot change state", j.ID, j.State)
	}

	j.State = want
	if err := s.st.UpdateJob(j); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, rpc.Errorf(rpc.CodeFailedPrecond, "no such job %s", p.ID)
		}
		return nil, fmt.Errorf("update job: %w", err)
	}
	return JobReply{Job: j}, nil
}

func (s *Service) jobsRemove(_ context.Context, params json.RawMessage) (any, error) {
	var p jobIDParams
	if err := decodeParams(params, &p); err != nil {
		return nil, err
	}
	if p.ID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "id is required")
	}
	if err := s.st.RemoveJob(p.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, rpc.Errorf(rpc.CodeFailedPrecond, "no such job %s", p.ID)
		}
		return nil, fmt.Errorf("remove job: %w", err)
	}
	return JobReply{Job: store.Job{ID: p.ID, State: store.StateRemoved}}, nil
}

// ReportWorker records a worker's observed state. Only the supervisor calls it.
//
// A role this build does not know about is ignored: a stale report from a
// downgraded or renamed role must not appear in the advertised worker set,
// or clients will try to supervise a worker that no longer exists.
func (s *Service) ReportWorker(r role.Role, pid int, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.workers[r]; !known {
		return
	}
	w := s.workers[r]
	w.Role = r
	if alive && !w.Alive {
		w.StartedAt = time.Now()
	}
	if !alive && w.Alive {
		w.Rests++
	}
	w.PID = pid
	w.Alive = alive
	s.workers[r] = w
}

// ReportAllWorkersDown marks every worker as not alive. Used when the
// supervisor runs without spawning them, so the UI says "not running" rather
// than showing a blank that reads as "unknown".
func (s *Service) ReportAllWorkersDown() {
	for _, r := range role.WorkerRoles() {
		s.ReportWorker(r, 0, false)
	}
}

func (s *Service) workerSnapshot() []WorkerStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]WorkerStatus, 0, len(s.workers))
	for _, w := range s.workers {
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}

func decodeParams[T any](params json.RawMessage, out *T) error {
	if len(params) == 0 {
		return rpc.Errorf(rpc.CodeInvalidParams, "params are required")
	}
	if err := json.Unmarshal(params, out); err != nil {
		return rpc.Errorf(rpc.CodeInvalidParams, "invalid params: %v", err)
	}
	return nil
}
