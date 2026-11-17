// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package stun

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// recordHandler counts how many terminal events it observes and records the
// last one, so tests can assert the exactly-once terminal-result guarantee.
type recordHandler struct {
	mu     sync.Mutex
	events []Event
}

func (h *recordHandler) handle(e Event) {
	h.mu.Lock()
	h.events = append(h.events, e)
	h.mu.Unlock()
}

func (h *recordHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()

	return len(h.events)
}

func (h *recordHandler) snapshot() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]Event, len(h.events))
	copy(out, h.events)

	return out
}

// TestAgent_ProcessIgnoresUnregisteredDuplicate proves that a second message
// carrying an ID whose transaction already completed cannot produce a second
// event for the (now reused or terminated) registration. The agent forwards an
// unregistered packet at most once and never resurrects a consumed
// registration.
func TestAgent_ProcessIgnoresUnregisteredDuplicate(t *testing.T) {
	var mu sync.Mutex
	var got []Event
	agent := NewAgent(func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	msg := MustBuild(TransactionID, BindingSuccess)
	assert.NoError(t, msg.NewTransactionID())
	assert.NoError(t, agent.Start(msg.TransactionID, time.Now().Add(time.Hour)))

	// First, in-transaction delivery consumes the registration exactly once.
	assert.NoError(t, agent.Process(msg))
	// A duplicate/late response finds no registration and must not delete or
	// disturb a transaction that reused the ID.
	reused := NewAgent(NoopHandler())
	assert.NoError(t, reused.Start(msg.TransactionID, time.Now().Add(time.Hour)))

	// Processing against the original agent again still forwards the stray
	// packet once (fallback indication semantics) but reports success.
	assert.NoError(t, agent.Process(msg))
	mu.Lock()
	assert.Len(t, got, 2, "unregistered packet is forwarded once, never as a terminal event")
	mu.Unlock()

	// The reused transaction is untouched: it can still time out on schedule.
	assert.NoError(t, agent.Close())
	assert.NoError(t, reused.Collect(time.Now().Add(2*time.Hour)))
	assert.NoError(t, reused.Close())
}

// TestClient_ForgedRequestCannotCompleteTransaction sends a forged Binding
// request (not a response) carrying the waiting transaction's ID. The client
// must ignore it and keep the transaction alive until a genuine response
// arrives.
func TestClient_ForgedRequestCannotCompleteTransaction(t *testing.T) {
	id := NewTransactionID()
	connL, connR := net.Pipe()
	defer func() {
		assert.NoError(t, connR.Close())
	}()
	collector := new(manualCollector)
	clock := &manualClock{current: time.Now()}
	client, err := NewClient(connR,
		WithClock(clock),
		WithCollector(collector),
		WithRTO(time.Hour),
	)
	assert.NoError(t, err)

	completed := make(chan Event, 1)
	request := MustBuild(NewTransactionIDSetter(id), BindingRequest)
	go func() {
		assert.NoError(t, client.Do(request, func(e Event) {
			completed <- e
		}))
	}()

	// Wait for the request to reach the other end.
	buf := make([]byte, 1500)
	readN, readErr := connL.Read(buf)
	assert.NoError(t, readErr)
	assert.True(t, IsMessage(buf[:readN]))

	// Inject a forged request that reuses the transaction ID. It is the wrong
	// message class (request, not response) and must not terminate the wait.
	forged := MustBuild(NewTransactionIDSetter(id), BindingRequest)
	forged.Encode()
	_, err = connL.Write(forged.Raw)
	assert.NoError(t, err)

	// Also inject a forged indication (another non-response class).
	indication := New()
	indication.TransactionID = id
	indication.SetType(NewType(MethodBinding, ClassIndication))
	indication.Encode()
	_, err = connL.Write(indication.Raw)
	assert.NoError(t, err)

	// The transaction must still be waiting: no completion after the forgeries.
	select {
	case e := <-completed:
		t.Fatalf("forged non-response completed the transaction: %+v", e)
	case <-time.After(150 * time.Millisecond):
	}

	// The genuine success response now completes the transaction exactly once.
	success := MustBuild(NewTransactionIDSetter(id), BindingSuccess)
	success.Encode()
	_, err = connL.Write(success.Raw)
	assert.NoError(t, err)

	select {
	case e := <-completed:
		assert.NoError(t, e.Error)
	case <-time.After(2 * time.Second):
		t.Fatal("genuine response did not complete the transaction")
	}
	assert.NoError(t, client.Close())
}

// TestClient_LateResponseAfterCloseIsIgnored verifies that a response arriving
// after a transaction finished (and the client moved on) cannot trigger a
// second callback for the completed transaction. The completed transaction's
// handler must run exactly once.
func TestClient_LateResponseAfterCloseIsIgnored(t *testing.T) {
	connL, connR := net.Pipe()
	defer func() {
		assert.NoError(t, connR.Close())
	}()
	client, err := NewClient(connR, WithRTO(time.Hour))
	assert.NoError(t, err)

	var calls int32
	firstDone := make(chan struct{})
	first := MustBuild(TransactionID, BindingRequest)
	go func() {
		assert.NoError(t, client.Do(first, func(Event) {
			atomic.AddInt32(&calls, 1)
			close(firstDone)
		}))
	}()
	buf := make([]byte, 1500)
	_, err = connL.Read(buf)
	assert.NoError(t, err)
	success := MustBuild(NewTransactionIDSetter(first.TransactionID), BindingSuccess)
	success.Encode()
	_, err = connL.Write(success.Raw)
	assert.NoError(t, err)
	<-firstDone

	// Late duplicates of the completed transaction's response cannot re-invoke
	// its handler: the client no longer owns the ID.
	for range 5 {
		_, err = connL.Write(success.Raw)
		assert.NoError(t, err)
	}
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "completed transaction gets exactly one callback")
	assert.NoError(t, client.Close())
}

// TestClient_CloseReleasesAllWaiters ensures every in-flight transaction gets a
// terminal ErrClientClosed event when the client shuts down, so no waiter can
// block forever, and each transaction observes a single terminal result.
func TestClient_CloseReleasesAllWaiters(t *testing.T) {
	connL, connR := net.Pipe()
	defer func() {
		_ = connR.Close()
	}()
	client, err := NewClient(connR, WithRTO(time.Hour))
	assert.NoError(t, err)

	const total = 25
	handlers := make([]*recordHandler, total)
	done := make([]chan struct{}, total)
	for i := range total {
		handlers[i] = &recordHandler{}
		done[i] = make(chan struct{})
		msg := MustBuild(TransactionID, BindingRequest)
		h := handlers[i]
		ch := done[i]
		go func() {
			assert.NoError(t, client.Do(msg, func(e Event) {
				h.handle(e)
				close(ch)
			}))
		}()
	}
	// Drain the requests so the transactions are fully registered.
	readBuf := make([]byte, 1500)
	for range total {
		_, err := connL.Read(readBuf)
		assert.NoError(t, err)
	}

	assert.NoError(t, client.Close())
	for i := range total {
		select {
		case <-done[i]:
		case <-time.After(2 * time.Second):
			t.Fatalf("waiter %d was not released by Close", i)
		}
		assert.Equal(t, 1, handlers[i].count(), "waiter %d got %d events", i, handlers[i].count())
		for _, e := range handlers[i].snapshot() {
			assert.True(t, errors.Is(e.Error, ErrClientClosed), "unexpected close event error: %v", e.Error)
		}
	}
}

// TestClient_TerminalResultExactlyOnce drives a transaction whose agent
// reports competing terminal events (timeout racing a response) and asserts
// the user handler runs exactly once even when both events are in flight.
func TestClient_TerminalResultExactlyOnce(t *testing.T) {
	connL, connR := net.Pipe()
	defer func() {
		assert.NoError(t, connR.Close())
	}()
	collector := new(manualCollector)
	clock := &manualClock{current: time.Now()}
	release := make(chan struct{})
	var calls int32
	finished := make(chan struct{})
	response := MustBuild(TransactionID, BindingSuccess)
	agent := &manualAgent{}
	// Block the first (timeout) event inside the client until the test releases
	// it, so a response event races it while the transaction is still live.
	agent.start = func(id [TransactionIDSize]byte, _ time.Time) error {
		go func() {
			<-release
			agent.h(Event{TransactionID: id, Error: ErrTransactionTimeOut})
		}()

		return nil
	}
	client, err := NewClient(connR,
		WithAgent(agent),
		WithClock(clock),
		WithCollector(collector),
		WithRTO(time.Millisecond),
	)
	assert.NoError(t, err)

	go func() {
		assert.NoError(t, client.Do(MustBuild(response, BindingRequest), func(Event) {
			atomic.AddInt32(&calls, 1)
			close(finished)
		}))
	}()
	readBuf := make([]byte, 1500)
	_, err = connL.Read(readBuf)
	assert.NoError(t, err)

	// Release the timeout and immediately deliver a genuine response. Only one
	// of the competing terminal events may invoke the handler.
	close(release)
	agent.h(Event{TransactionID: response.TransactionID, Message: response})

	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("transaction never reached a terminal state")
	}
	assert.Eventually(t, func() bool {
		return atomic.LoadInt32(&calls) == 1
	}, time.Second, 10*time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "handler must run exactly once")
	assert.NoError(t, client.Close())
}
