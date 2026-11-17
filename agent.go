// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"errors"
	"sync"
	"time"
)

// NoopHandler just discards any event.
func NoopHandler() Handler {
	return func(Event) {}
}

// NewAgent initializes and returns new Agent with provided handler.
// If h is nil, the NoopHandler will be used.
func NewAgent(h Handler) *Agent {
	if h == nil {
		h = NoopHandler()
	}
	a := &Agent{
		transactions: make(map[transactionID]agentTransaction),
		handler:      h,
	}

	return a
}

// Agent is low-level abstraction over transaction list that
// handles concurrency (all calls are goroutine-safe) and
// time outs (via Collect call).
type Agent struct {
	// transactions is map of transactions that are currently
	// in progress. Event handling is done in such way when
	// transaction is unregistered before agentTransaction access,
	// minimizing mux lock and protecting agentTransaction from
	// data races via unexpected concurrent access.
	transactions map[transactionID]agentTransaction
	closed       bool       // all calls are invalid if true
	mux          sync.Mutex // protects transactions and closed
	handler      Handler    // handles transactions
}

// Handler handles state changes of transaction.
//
// Handler is called on transaction state change.
// Usage of e is valid only during call, user must
// copy needed fields explicitly.
type Handler func(e Event)

// Event is passed to Handler describing the transaction event.
// Do not reuse outside Handler.
type Event struct {
	TransactionID [TransactionIDSize]byte
	Message       *Message
	Error         error
}

// agentTransaction represents transaction in progress.
// Concurrent access is invalid.
type agentTransaction struct {
	id       transactionID
	deadline time.Time
}

var (
	// ErrTransactionStopped indicates that transaction was manually stopped.
	ErrTransactionStopped = errors.New("transaction is stopped")
	// ErrTransactionNotExists indicates that agent failed to find transaction.
	ErrTransactionNotExists = errors.New("transaction not exists")
	// ErrTransactionExists indicates that transaction with same id is already
	// registered.
	ErrTransactionExists = errors.New("transaction exists with same id")
)

// StopWithError removes transaction from list and calls handler with
// provided error. Can return ErrTransactionNotExists and ErrAgentClosed.
func (a *Agent) StopWithError(id [TransactionIDSize]byte, err error) error {
	a.mux.Lock()
	if a.closed {
		a.mux.Unlock()

		return ErrAgentClosed
	}
	t, exists := a.transactions[id]
	delete(a.transactions, id)
	h := a.handler
	a.mux.Unlock()
	if !exists {
		return ErrTransactionNotExists
	}
	h(Event{
		TransactionID: t.id,
		Error:         err,
	})

	return nil
}

// Stop stops transaction by id with ErrTransactionStopped, blocking
// until handler returns.
func (a *Agent) Stop(id [TransactionIDSize]byte) error {
	return a.StopWithError(id, ErrTransactionStopped)
}

// ErrAgentClosed indicates that agent is in closed state and is unable
// to handle transactions.
var ErrAgentClosed = errors.New("agent is closed")

// Start registers transaction with provided id and deadline.
// Could return ErrAgentClosed, ErrTransactionExists.
//
// Agent handler is guaranteed to be eventually called.
func (a *Agent) Start(id [TransactionIDSize]byte, deadline time.Time) error {
	a.mux.Lock()
	defer a.mux.Unlock()
	if a.closed {
		return ErrAgentClosed
	}
	_, exists := a.transactions[id]
	if exists {
		return ErrTransactionExists
	}
	a.transactions[id] = agentTransaction{
		id:       id,
		deadline: deadline,
	}

	return nil
}

// agentCollectCap is initial capacity for Agent.Collect slices,
// sufficient to make function zero-alloc in most cases.
const agentCollectCap = 100

// ErrTransactionTimeOut indicates that transaction has reached deadline.
var ErrTransactionTimeOut = errors.New("transaction is timed out")

// Collect terminates all transactions that have deadline before provided
// time, blocking until all handlers will process ErrTransactionTimeOut.
// Will return ErrAgentClosed if agent is already closed.
//
// It is safe to call Collect concurrently but makes no sense.
func (a *Agent) Collect(gcTime time.Time) error {
	toRemove := make([]transactionID, 0, agentCollectCap)
	a.mux.Lock()
	if a.closed {
		// Doing nothing if agent is closed.
		// All transactions should be already closed
		// during Close() call.
		a.mux.Unlock()

		return ErrAgentClosed
	}
	// Adding all transactions with deadline before gcTime
	// to toCall and toRemove slices.
	// No allocs if there are less than agentCollectCap
	// timed out transactions.
	for id, t := range a.transactions {
		if t.deadline.Before(gcTime) {
			toRemove = append(toRemove, id)
		}
	}
	// Un-registering timed out transactions.
	for _, id := range toRemove {
		delete(a.transactions, id)
	}
	// Calling handler does not require locked mutex,
	// reducing lock time.
	h := a.handler
	a.mux.Unlock()
	// Sending ErrTransactionTimeOut to handler for all transactions,
	// blocking until last one.
	event := Event{
		Error: ErrTransactionTimeOut,
	}
	for _, id := range toRemove {
		event.TransactionID = id
		h(event)
	}

	return nil
}

// Process incoming message, synchronously passing it to handler.
//
// A message is only delivered when a transaction with the same ID is
// currently registered. The matching registration is consumed atomically, so
// a duplicate, forged or late message that arrives after the transaction
// terminated (or after its ID was reused by a newer transaction) is ignored
// instead of being able to start, complete or cancel a transaction it does
// not belong to. Indications and other messages without a registered
// transaction are still forwarded once, so a fallback handler can observe
// data indications the agent does not manage.
func (a *Agent) Process(m *Message) error {
	event := Event{
		TransactionID: m.TransactionID,
		Message:       m,
	}
	a.mux.Lock()
	if a.closed {
		a.mux.Unlock()

		return ErrAgentClosed
	}
	h := a.handler
	_, registered := a.transactions[m.TransactionID]
	if registered {
		// Consume the registration only when it actually belongs to this ID,
		// making the delivery exactly-once for that registration.
		delete(a.transactions, m.TransactionID)
	}
	a.mux.Unlock()
	if !registered {
		// No live transaction: still surface the packet once to the handler
		// (for example a TURN data indication), but never as a terminal event
		// of a registered transaction.
		h(event)

		return nil
	}
	h(event)

	return nil
}

// SetHandler sets agent handler to h.
func (a *Agent) SetHandler(h Handler) error {
	a.mux.Lock()
	if a.closed {
		a.mux.Unlock()

		return ErrAgentClosed
	}
	a.handler = h
	a.mux.Unlock()

	return nil
}

// Close terminates all transactions with ErrAgentClosed and renders Agent to
// closed state.
//
// Each registered transaction receives exactly one terminal event. Handlers
// are invoked without holding the agent mutex so they can safely re-enter the
// agent (for example from a Client closing its transactions), and any message
// or timeout arriving after the transactions were collected is ignored instead
// of delivering a second event for a terminated transaction.
func (a *Agent) Close() error {
	e := Event{
		Error: ErrAgentClosed,
	}
	a.mux.Lock()
	if a.closed {
		a.mux.Unlock()

		return ErrAgentClosed
	}
	// Snapshot the pending transactions and detach them under the lock so
	// that concurrent Process/Collect/Stop calls cannot observe them once
	// Close has started. The handlers run after the mutex is released to
	// avoid deadlocking on agents whose handlers re-enter the agent.
	pending := make([]agentTransaction, 0, len(a.transactions))
	for _, t := range a.transactions {
		pending = append(pending, t)
	}
	a.transactions = nil
	a.closed = true
	h := a.handler
	a.handler = nil
	a.mux.Unlock()

	// Every waiter gets exactly one terminal event.
	for _, t := range pending {
		e.TransactionID = t.id
		h(e)
	}

	return nil
}

type transactionID [TransactionIDSize]byte
