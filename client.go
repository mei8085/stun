// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v4"
	"github.com/pion/logging"
	"github.com/pion/transport/v5"
	"github.com/pion/transport/v5/stdnet"
)

// ErrUnsupportedURI is an error thrown if the user passes an unsupported STUN or TURN URI.
var ErrUnsupportedURI = fmt.Errorf("invalid schema or transport")

// Dial connects to the address on the named network and then
// initializes Client on that connection, returning error if any.
func Dial(network, address string) (*Client, error) {
	conn, err := net.Dial(network, address) //nolint: noctx
	if err != nil {
		return nil, err
	}

	return NewClient(conn)
}

type dialConfig struct {
	dtlsOptions []dtls.ClientOption
	tlsConfig   *tls.Config
	net         transport.Net
}

// DialOption configures a connection opened by DialURI.
type DialOption func(*dialConfig)

// WithTLSConfig sets the TLS configuration. A nil configuration uses TLS defaults.
// DialURI clones the configuration before setting ServerName to the URI host.
func WithTLSConfig(config *tls.Config) DialOption {
	return func(cfg *dialConfig) {
		cfg.tlsConfig = config
	}
}

// WithDTLSOptions appends DTLS client options.
// DialURI sets the server name to the URI host after applying these options.
func WithDTLSOptions(options ...dtls.ClientOption) DialOption {
	return func(cfg *dialConfig) {
		cfg.dtlsOptions = append(cfg.dtlsOptions, options...)
	}
}

// WithNet sets the network used by DialURI. A nil network uses the standard network.
func WithNet(network transport.Net) DialOption {
	return func(cfg *dialConfig) {
		cfg.net = network
	}
}

// DialURI connect to the STUN/TURN URI and then
// initializes Client on that connection, returning error if any.
func DialURI(uri *URI, options ...DialOption) (*Client, error) { //nolint:cyclop
	cfg := &dialConfig{}
	for _, option := range options {
		if option == nil {
			continue
		}

		option(cfg)
	}

	var conn Connection
	var err error

	nw := cfg.net
	if nw == nil {
		nw, err = stdnet.NewNet()
		if err != nil {
			return nil, fmt.Errorf("failed to create net: %w", err)
		}
	}

	addr := net.JoinHostPort(uri.Host, strconv.Itoa(uri.Port))

	switch {
	case uri.Scheme == SchemeTypeSTUN:
		if conn, err = nw.Dial("udp", addr); err != nil {
			return nil, fmt.Errorf("failed to listen: %w", err)
		}

	case uri.Scheme == SchemeTypeTURN:
		network := "udp" //nolint:goconst
		if uri.Proto == ProtoTypeTCP {
			network = "tcp" //nolint:goconst
		}

		if conn, err = nw.Dial(network, addr); err != nil {
			return nil, fmt.Errorf("failed to dial: %w", err)
		}

	case uri.Scheme == SchemeTypeTURNS && uri.Proto == ProtoTypeUDP:
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDPAddr: %w", err)
		}

		udpConn, err := nw.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial: %w", err)
		}

		dtlsOptions := append([]dtls.ClientOption{}, cfg.dtlsOptions...)
		dtlsOptions = append(dtlsOptions, dtls.WithServerName(uri.Host))
		dtlsConn, err := dtls.Client(udpConn, udpConn.RemoteAddr(), dtlsOptions...)
		if err != nil {
			_ = udpConn.Close()

			return nil, fmt.Errorf("failed to connect to '%s': %w", addr, err)
		}
		conn = dtlsConn

	case (uri.Scheme == SchemeTypeTURNS || uri.Scheme == SchemeTypeSTUNS) && uri.Proto == ProtoTypeTCP:
		tlsCfg := &tls.Config{} //nolint:gosec
		if cfg.tlsConfig != nil {
			tlsCfg = cfg.tlsConfig.Clone()
		}
		tlsCfg.ServerName = uri.Host

		tcpConn, err := nw.Dial("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial: %w", err)
		}

		conn = tls.Client(tcpConn, tlsCfg)

	default:
		return nil, ErrUnsupportedURI
	}

	return NewClient(conn)
}

// ErrNoConnection means that ClientOptions.Connection is nil.
var ErrNoConnection = errors.New("no connection provided")

// ClientOption sets some client option.
type ClientOption func(c *Client)

// WithHandler sets client handler which is called if Agent emits the Event
// with TransactionID that is not currently registered by Client.
// Useful for handling Data indications from TURN server.
func WithHandler(h Handler) ClientOption {
	return func(c *Client) {
		c.handler = h
	}
}

// WithRTO sets client RTO as defined in STUN RFC.
func WithRTO(rto time.Duration) ClientOption {
	return func(c *Client) {
		c.rto = int64(rto)
	}
}

// WithClock sets Clock of client, the source of current time.
// Also clock is passed to default collector if set.
func WithClock(clock Clock) ClientOption {
	return func(c *Client) {
		c.clock = clock
	}
}

// WithTimeoutRate sets RTO timer minimum resolution.
func WithTimeoutRate(d time.Duration) ClientOption {
	return func(c *Client) {
		c.rtoRate = d
	}
}

// WithAgent sets client STUN agent.
//
// Defaults to agent implementation in current package,
// see agent.go.
func WithAgent(a ClientAgent) ClientOption {
	return func(c *Client) {
		c.a = a
	}
}

// WithCollector rests client timeout collector, the implementation
// of ticker which calls function on each tick.
func WithCollector(coll Collector) ClientOption {
	return func(c *Client) {
		c.collector = coll
	}
}

// WithNoConnClose prevents client from closing underlying connection when
// the Close() method is called.
func WithNoConnClose() ClientOption {
	return func(c *Client) {
		c.closeConn = false
	}
}

// WithStrictMode sets strict decode behavior for messages decoded by the client.
func WithStrictMode(strict bool) ClientOption {
	return func(c *Client) {
		c.strict = strict
	}
}

// WithLoggerFactory sets logger used by the client and decoded messages.
func WithLoggerFactory(loggerFactory logging.LoggerFactory) ClientOption {
	return func(c *Client) {
		if loggerFactory == nil {
			c.logger = nil

			return
		}
		c.logger = loggerFactory.NewLogger("stun")
	}
}

// WithNoRetransmit disables retransmissions and sets RTO to
// defaultMaxAttempts * defaultRTO which will be effectively time out
// if not set.
//
// Useful for TCP connections where transport handles RTO.
func WithNoRetransmit(c *Client) {
	c.maxAttempts = 0
	if c.rto == 0 {
		c.rto = defaultMaxAttempts * int64(defaultRTO)
	}
}

const (
	defaultTimeoutRate = time.Millisecond * 5
	defaultRTO         = time.Millisecond * 300
	defaultMaxAttempts = 7
)

// NewClient initializes new Client from provided options,
// starting internal goroutines and using default options fields
// if necessary. Call Close method after using Client to close conn and
// release resources.
//
// The conn will be closed on Close call. Use WithNoConnClose option to
// prevent that.
//
// Note that user should handle the protocol multiplexing, client does not
// provide any API for it, so if you need to read application data, wrap the
// connection with your (de-)multiplexer and pass the wrapper as conn.
func NewClient(conn Connection, options ...ClientOption) (*Client, error) {
	client := &Client{
		close:       make(chan struct{}),
		c:           conn,
		clock:       systemClock(),
		rto:         int64(defaultRTO),
		rtoRate:     defaultTimeoutRate,
		t:           make(map[transactionID]*clientTransaction, 100),
		maxAttempts: defaultMaxAttempts,
		closeConn:   true,
	}
	for _, o := range options {
		o(client)
	}
	if client.c == nil {
		return nil, ErrNoConnection
	}
	if client.a == nil {
		client.a = NewAgent(nil)
	}
	if err := client.a.SetHandler(client.handleAgentCallback); err != nil {
		return nil, err
	}
	if client.collector == nil {
		client.collector = &tickerCollector{
			close: make(chan struct{}),
			clock: client.clock,
		}
	}
	if err := client.collector.Start(client.rtoRate, func(t time.Time) {
		closedOrPanic(client.a.Collect(t))
	}); err != nil {
		return nil, err
	}
	client.wg.Add(1)
	go client.readUntilClosed()
	runtime.SetFinalizer(client, clientFinalizer)

	return client, nil
}

func clientFinalizer(c *Client) {
	if c == nil {
		return
	}
	err := c.Close()
	if errors.Is(err, ErrClientClosed) {
		return
	}
	if err == nil {
		log.Println("client: called finalizer on non-closed client") // nolint

		return
	}
	log.Println("client: called finalizer on non-closed client:", err) // nolint
}

// Connection wraps Reader, Writer and Closer interfaces.
type Connection interface {
	io.Reader
	io.Writer
	io.Closer
}

// ClientAgent is Agent implementation that is used by Client to
// process transactions.
type ClientAgent interface {
	Process(*Message) error
	Close() error
	Start(id [TransactionIDSize]byte, deadline time.Time) error
	Stop(id [TransactionIDSize]byte) error
	Collect(time.Time) error
	SetHandler(h Handler) error
}

// Client simulates "connection" to STUN server.
type Client struct {
	rto         int64 // time.Duration
	a           ClientAgent
	c           Connection
	close       chan struct{}
	rtoRate     time.Duration
	maxAttempts int32
	closed      bool
	closeConn   bool // should call c.Close() while closing
	wg          sync.WaitGroup
	clock       Clock
	handler     Handler
	collector   Collector
	// t holds every transaction that has not reached a terminal state yet.
	t      map[transactionID]*clientTransaction
	logger logging.LeveledLogger
	strict bool

	// mux guards closed and t
	mux sync.RWMutex
}

// clientTransaction represents transaction in progress.
// If transaction is succeed or failed, f will be called
// provided by event.
// Concurrent access is invalid.
type clientTransaction struct {
	id       transactionID
	attempt  int32
	calls    int32
	recycled int32 // atomic guard: the pooled object is returned at most once
	// armed reports whether the agent currently holds a registration for this
	// exact transaction. All reads and writes happen under eventMu.
	armed    bool
	h        Handler
	start    time.Time
	rto      time.Duration
	raw      []byte
	deadline time.Time

	// eventMu serializes every event delivered for this transaction and guards
	// armed/attempt/deadline. The same transaction stays registered across
	// retransmissions, so a timeout and a late or mismatched response can be
	// dispatched concurrently by different goroutines. A transaction that is
	// re-acquired from the pool first takes this lock, so it can never run
	// concurrently with an event goroutine still finishing the previous owner.
	eventMu sync.Mutex
}

// handle invokes the transaction handler at most once. The atomic
// compare-and-swap on calls is the single gate that lets exactly one goroutine
// run the user handler, so concurrent terminal events (for example a response
// racing a timeout or a shutdown) can never deliver a second observable result
// or dereference a handler that was already released.
func (t *clientTransaction) handle(e Event) {
	if atomic.LoadInt32(&t.recycled) != 0 {
		return
	}
	h := t.h
	if h == nil {
		return
	}
	if !atomic.CompareAndSwapInt32(&t.calls, 0, 1) {
		return
	}
	h(e)
}

var clientTransactionPool = &sync.Pool{ //nolint:gochecknoglobals
	New: func() any {
		return &clientTransaction{
			raw: make([]byte, 1500),
		}
	},
}

func acquireClientTransaction() *clientTransaction {
	t := clientTransactionPool.Get().(*clientTransaction) //nolint:forcetypeassert
	// Wait for any event goroutine that still holds this pooled object's lock
	// to finish. Client.Close pools a terminal transaction without taking
	// eventMu (it must not block on a callback stuck in user code), so this
	// lock is the happens-before edge that prevents a new owner from reusing
	// the memory while the previous owner's callback is still running.
	t.eventMu.Lock()
	// Fully reset every observable field before publishing. A pooled object may
	// have been returned by a path that only marked it terminal, so no stale
	// handler, attempt or deadline may survive into the new owner.
	t.recycled = 0
	t.calls = 0
	t.attempt = 0
	t.armed = false
	t.h = nil
	t.start = time.Time{}
	t.rto = 0
	t.deadline = time.Time{}
	t.id = transactionID{}
	t.eventMu.Unlock()

	return t
}

// reset clears the handler reference so a pooled transaction cannot retain a
// callback after it terminates. Other fields are overwritten by Start when the
// object is re-acquired, so they do not need to be cleared here. It must be
// called with eventMu held.
func (t *clientTransaction) reset() {
	t.h = nil
}

// markRecycled atomically marks the transaction terminal and reports whether
// the caller won the right to pool it.
func (t *clientTransaction) markRecycled() bool {
	return atomic.CompareAndSwapInt32(&t.recycled, 0, 1)
}

// recycleLocked returns the transaction to the pool. It must be called with
// eventMu held, which serializes against every other event goroutine and
// against a new Start that re-acquires the object (Start takes eventMu before
// publishing). It is therefore impossible for pooled memory to be reused while
// an event goroutine still touches it.
func (t *clientTransaction) recycleLocked() {
	if !t.markRecycled() {
		return
	}
	t.reset()
	clientTransactionPool.Put(t)
}

// recycle is the non-blocking variant used by Client.Close and by paths that
// released eventMu (after an agent Stop that re-enters the callback). It marks
// the object terminal first so any racing handle() becomes a no-op and the
// object is pooled at most once, then pools it without taking eventMu: Close
// must not wait on that lock because an in-flight retransmit callback can be
// blocked in user-supplied Clock/Write code while holding it. A new Start that
// re-acquires the object takes eventMu before publishing, and the recycled
// flag prevents the still-finishing callback from invoking a handler again.
func (t *clientTransaction) recycle() {
	if !t.markRecycled() {
		return
	}
	clientTransactionPool.Put(t)
}

// arm registers the transaction with the agent for its current deadline and
// flips the armed flag. It is a no-op if the flag is already set. Every agent
// event consumes the registration (the agent deletes it before dispatching),
// so an event that does not terminate the transaction - a retransmission
// timeout or an ignored mismatched packet - must re-arm. It must be called
// with eventMu held.
//
// ErrTransactionExists means a newer transaction already owns the agent
// registration for the ID (transaction-ID reuse); this transaction can no
// longer be re-armed and the caller terminates it instead of blocking forever.
func (c *Client) arm(transaction *clientTransaction) error {
	if transaction.armed {
		return nil
	}
	if err := c.a.Start(transaction.id, transaction.deadline); err != nil {
		return err
	}
	transaction.armed = true

	return nil
}

// disarm mirrors that the agent consumed its registration by dispatching an
// event. It must be called with eventMu held.
func (t *clientTransaction) disarm() {
	t.armed = false
}

// isResponseForTransaction reports whether m is a STUN response (success or
// error class) that can terminate the waiting transaction. Requests and
// indications are never responses, so a forged message of those classes that
// carries a known transaction ID cannot complete or cancel the waiting
// transaction, and neither can any non-STUN payload. The method is not
// required to match exactly: STUN transaction IDs are already unique per
// request and some callers build requests with the zero-value method.
func isResponseForTransaction(m *Message) bool {
	if m == nil {
		return false
	}
	class := m.Type.Class

	return class == ClassSuccessResponse || class == ClassErrorResponse
}

func (t *clientTransaction) nextTimeout(now time.Time) time.Time {
	return now.Add(time.Duration(t.attempt+1) * t.rto)
}

// start registers transaction.
//
// Could return ErrClientClosed, ErrTransactionExists.
func (c *Client) start(t *clientTransaction) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.closed {
		return ErrClientClosed
	}
	_, exists := c.t[t.id]
	if exists {
		return ErrTransactionExists
	}
	c.t[t.id] = t

	return nil
}

// Clock abstracts the source of current time.
type Clock interface {
	Now() time.Time
}

type systemClockService struct{}

func (systemClockService) Now() time.Time { return time.Now() }

func systemClock() systemClockService {
	return systemClockService{}
}

// SetRTO sets current RTO value.
func (c *Client) SetRTO(rto time.Duration) {
	atomic.StoreInt64(&c.rto, int64(rto))
}

// StopErr occurs when Client fails to stop transaction while
// processing error.
//
//nolint:errname
type StopErr struct {
	Err   error // value returned by Stop()
	Cause error // error that caused Stop() call
}

func (e StopErr) Error() string {
	return fmt.Sprintf("error while stopping due to %s: %s", sprintErr(e.Cause), sprintErr(e.Err))
}

// CloseErr indicates client close failure.
//
//nolint:errname
type CloseErr struct {
	AgentErr      error
	ConnectionErr error
}

func sprintErr(err error) string {
	if err == nil {
		return "<nil>" //nolint:goconst
	}

	return err.Error()
}

func (c CloseErr) Error() string {
	return fmt.Sprintf("failed to close: %s (connection), %s (agent)", sprintErr(c.ConnectionErr), sprintErr(c.AgentErr))
}

func (c *Client) readUntilClosed() {
	defer c.wg.Done()
	options := []MessageOption{
		WithStrict(c.strict),
	}
	if c.logger != nil {
		options = append(options, withMessageLogger(c.logger))
	}
	m := NewWithOptions(options...)
	m.Raw = make([]byte, 1024)
	for {
		select {
		case <-c.close:
			return
		default:
		}
		_, err := m.ReadFrom(c.c)
		if err == nil {
			if pErr := c.a.Process(m); errors.Is(pErr, ErrAgentClosed) {
				return
			}
		}
	}
}

func closedOrPanic(err error) {
	if err == nil || errors.Is(err, ErrAgentClosed) {
		return
	}
	panic(err) //nolint
}

type tickerCollector struct {
	close chan struct{}
	wg    sync.WaitGroup
	clock Clock
}

// Collector calls function f with constant rate.
//
// The simple Collector is ticker which calls function on each tick.
type Collector interface {
	Start(rate time.Duration, f func(now time.Time)) error
	Close() error
}

func (a *tickerCollector) Start(rate time.Duration, f func(now time.Time)) error {
	t := time.NewTicker(rate)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for {
			select {
			case <-a.close:
				t.Stop()

				return
			case <-t.C:
				f(a.clock.Now())
			}
		}
	}()

	return nil
}

func (a *tickerCollector) Close() error {
	close(a.close)
	a.wg.Wait()

	return nil
}

// ErrClientClosed indicates that client is closed.
var ErrClientClosed = errors.New("client is closed")

// Close stops internal connection and agent, returning CloseErr on error.
func (c *Client) Close() error {
	if err := c.checkInit(); err != nil {
		return err
	}
	c.mux.Lock()
	if c.closed {
		c.mux.Unlock()

		return ErrClientClosed
	}
	c.closed = true
	// Snapshot and detach every in-flight transaction before tearing down the
	// agent and connection. Each waiter receives a single ErrClientClosed
	// terminal event; events racing the close afterwards find no owner and are
	// ignored, so no terminal state can be observed twice.
	pending := make([]*clientTransaction, 0, len(c.t))
	for _, transaction := range c.t {
		pending = append(pending, transaction)
	}
	c.t = make(map[transactionID]*clientTransaction)
	c.mux.Unlock()
	if closeErr := c.collector.Close(); closeErr != nil {
		return closeErr
	}
	var connErr error
	agentErr := c.a.Close()
	if c.closeConn {
		connErr = c.c.Close()
	}
	close(c.close)
	c.wg.Wait()
	for _, transaction := range pending {
		// Do not block on eventMu here: an in-flight retransmit callback can
		// be stuck inside the user-supplied Clock or a connection Write while
		// waiting on c.mux, which would deadlock shutdown. The atomic calls and
		// recycled guards make a concurrent terminal callback safe: at most one
		// observable result is delivered and the object is pooled once.
		transaction.handle(Event{
			TransactionID: transaction.id,
			Error:         ErrClientClosed,
		})
		transaction.recycle()
	}
	if agentErr == nil && connErr == nil {
		return nil
	}

	return CloseErr{
		AgentErr:      agentErr,
		ConnectionErr: connErr,
	}
}

// Indicate sends indication m to server. Shorthand to Start call
// with zero deadline and callback.
func (c *Client) Indicate(m *Message) error {
	return c.Start(m, nil)
}

// callbackWaitHandler blocks on wait() call until callback is called.
type callbackWaitHandler struct {
	handler   Handler
	callback  func(event Event)
	cond      *sync.Cond
	processed bool
}

func (s *callbackWaitHandler) HandleEvent(e Event) {
	s.cond.L.Lock()
	// A late duplicate terminal event can arrive after wait() has consumed the
	// result and released this handler back to its pool (for example a
	// retransmitted response racing the first one). The original result was
	// already delivered, so the duplicate is safely ignored instead of
	// dereferencing a nil callback and panicking.
	if s.callback == nil {
		s.cond.L.Unlock()

		return
	}
	s.callback(e)
	s.processed = true
	s.cond.Broadcast()
	s.cond.L.Unlock()
}

func (s *callbackWaitHandler) wait() {
	s.cond.L.Lock()
	for !s.processed {
		s.cond.Wait()
	}
	s.processed = false
	s.callback = nil
	s.cond.L.Unlock()
}

func (s *callbackWaitHandler) setCallback(f func(event Event)) {
	if f == nil {
		panic("f is nil") //nolint
	}
	s.cond.L.Lock()
	s.callback = f
	if s.handler == nil {
		s.handler = s.HandleEvent
	}
	s.cond.L.Unlock()
}

var callbackWaitHandlerPool = sync.Pool{ //nolint:gochecknoglobals
	New: func() any {
		return &callbackWaitHandler{
			cond: sync.NewCond(new(sync.Mutex)),
		}
	},
}

// ErrClientNotInitialized means that client connection or agent is nil.
var ErrClientNotInitialized = errors.New("client not initialized")

func (c *Client) checkInit() error {
	if c == nil || c.c == nil || c.a == nil || c.close == nil {
		return ErrClientNotInitialized
	}

	return nil
}

// Do is Start wrapper that waits until callback is called. If no callback
// provided, Indicate is called instead.
//
// Do has cpu overhead due to blocking, see BenchmarkClient_Do.
// Use Start method for less overhead.
func (c *Client) Do(m *Message, f func(Event)) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	if f == nil {
		return c.Indicate(m)
	}
	h := callbackWaitHandlerPool.Get().(*callbackWaitHandler) //nolint:forcetypeassert
	h.setCallback(f)
	defer func() {
		callbackWaitHandlerPool.Put(h)
	}()
	if err := c.Start(m, h.handler); err != nil {
		return err
	}
	h.wait()

	return nil
}

// removeIfOwner unregisters transaction only if it is still the current owner
// of its transaction ID. A stale event must never remove a different
// transaction that reused the ID after the original one was unregistered,
// otherwise a forged or late response could terminate the new transaction.
// It reports whether the transaction was removed.
func (c *Client) removeIfOwner(transaction *clientTransaction) bool {
	c.mux.Lock()
	defer c.mux.Unlock()
	if c.t == nil || c.t[transaction.id] != transaction {
		return false
	}
	delete(c.t, transaction.id)

	return true
}

// finishTransaction unregisters the transaction if it is still the owner and
// delivers exactly one terminal event, returning the pooled object. It is the
// single funnel through which every client transaction reaches a terminal
// state, so callbacks cannot be invoked twice and late events after
// unregistration are safely ignored. It must be called with eventMu held.
func (c *Client) finishTransaction(transaction *clientTransaction, event Event) {
	c.removeIfOwner(transaction)
	transaction.handle(event)
	// recycleLocked flips the recycled flag exactly once and returns the
	// object to the pool while eventMu is held.
	transaction.recycleLocked()
}

type buffer struct {
	buf []byte
}

var bufferPool = &sync.Pool{ //nolint:gochecknoglobals
	New: func() any {
		return &buffer{buf: make([]byte, 2048)}
	},
}

func (c *Client) handleAgentCallback(event Event) { //nolint:cyclop
	c.mux.Lock()
	if c.closed {
		c.mux.Unlock()

		return
	}
	transaction, found := c.t[event.TransactionID]
	c.mux.Unlock()
	if !found {
		// No transaction is waiting on this ID. The event is either a data
		// indication that the client does not manage or a stale/forged
		// response for a transaction that already terminated. Deliver the
		// former to the fallback handler and safely ignore everything else,
		// but never let it start or complete any transaction.
		if c.handler != nil && !errors.Is(event.Error, ErrTransactionStopped) {
			c.handler(event)
		}

		return
	}

	// Serialize all events for this transaction. It stays registered across
	// retransmissions, so a timeout and a late or mismatched response can be
	// dispatched concurrently; only one of them may mutate or terminate it.
	transaction.eventMu.Lock()
	// Re-check ownership under the lock. Pointer identity is exact: a newer
	// transaction that reused the same ID is a different object and is never
	// matched, so a stale or reused-ID event cannot touch it or produce a
	// second observable result for the original one.
	c.mux.RLock()
	owner := c.t[event.TransactionID] == transaction
	c.mux.RUnlock()
	if !owner {
		transaction.eventMu.Unlock()

		return
	}
	// The agent consumed its registration to deliver this event.
	transaction.disarm()

	// A message only takes effect inside a still-waiting transaction whose
	// request type it answers. Forged requests/indications and responses of
	// another method are dropped without terminating the transaction: it is
	// re-armed to keep waiting for a valid response (or time out).
	if event.Error == nil && !isResponseForTransaction(event.Message) {
		armErr := c.arm(transaction)
		if armErr == nil {
			if c.logger != nil {
				c.logger.Debugf("ignoring message of type %s with transaction ID %x: not a response for the waiting transaction", event.Message.Type, transaction.id)
			}
			transaction.eventMu.Unlock()

			return
		}
		// A lost registration (ID reuse) or any other arm failure still has to
		// release the waiter exactly once: finishTransaction unregisters and
		// delivers a single terminal event.
		c.finishTransaction(transaction, Event{
			TransactionID: transaction.id,
			Error:         armErr,
		})
		transaction.eventMu.Unlock()

		return
	}

	if atomic.LoadInt32(&c.maxAttempts) <= transaction.attempt || event.Error == nil {
		// Transaction completed: a success or error response always
		// terminates it, and error events (timeout/stop/close) terminate it
		// once the maximum number of attempts is reached.
		c.finishTransaction(transaction, event)
		transaction.eventMu.Unlock()

		return
	}
	// Doing re-transmission. The client keeps the transaction registered for
	// the whole attempt: the same clientTransaction object retains ownership
	// of its ID, so a late response arriving between attempts still belongs to
	// this transaction and a concurrent re-registration with the same ID keeps
	// failing with ErrTransactionExists.
	transaction.attempt++
	transaction.deadline = transaction.nextTimeout(c.clock.Now())
	// Re-arm the agent for the next attempt before writing the retransmit. The
	// agent registration was consumed by the timeout event.
	if armErr := c.arm(transaction); armErr != nil {
		c.finishTransaction(transaction, Event{
			TransactionID: transaction.id,
			Error:         armErr,
		})
		transaction.eventMu.Unlock()

		return
	}
	buff := bufferPool.Get().(*buffer) //nolint:forcetypeassert
	buff.buf = buff.buf[:copy(buff.buf[:cap(buff.buf)], transaction.raw)]
	defer bufferPool.Put(buff)
	// Writing message to connection again.
	_, writeErr := c.c.Write(buff.buf)
	if writeErr != nil {
		// Detach the client transaction while still holding eventMu. The
		// ErrTransactionStopped event that Stop delivers synchronously
		// re-enters handleAgentCallback, but it finds no owner in c.t
		// (removeIfOwner already deleted the entry) and returns from the
		// not-found branch before touching eventMu, so keeping the lock here
		// cannot self-deadlock. Holding it also makes the terminal delivery and
		// pool return atomic, so the object cannot be recycled and reused by a
		// new Start while this goroutine still references it.
		c.removeIfOwner(transaction)
		if stopErr := c.a.Stop(transaction.id); stopErr != nil {
			// Failed to stop agent transaction. Wrapping the error in StopError.
			writeErr = StopErr{
				Err:   stopErr,
				Cause: writeErr,
			}
		}
		transaction.handle(Event{
			TransactionID: transaction.id,
			Error:         writeErr,
		})
		transaction.recycleLocked()
		transaction.eventMu.Unlock()

		return
	}
	transaction.eventMu.Unlock()
}

// Start starts transaction (if h set) and writes message to server, handler
// is called asynchronously.
func (c *Client) Start(msg *Message, handler Handler) error {
	if err := c.checkInit(); err != nil {
		return err
	}
	c.mux.RLock()
	closed := c.closed
	c.mux.RUnlock()
	if closed {
		return ErrClientClosed
	}
	if handler != nil {
		// Starting transaction only if h is set. Useful for indications.
		t := acquireClientTransaction()
		t.id = msg.TransactionID
		t.start = c.clock.Now()
		t.h = handler
		t.rto = time.Duration(atomic.LoadInt64(&c.rto))
		t.attempt = 0
		t.calls = 0
		t.raw = append(t.raw[:0], msg.Raw...)
		d := t.nextTimeout(t.start)
		t.deadline = d
		if err := c.start(t); err != nil {
			t.recycle()

			return err
		}
		// Hold eventMu while arming so an event the agent may dispatch
		// immediately after Start cannot observe or mutate the armed flag
		// concurrently.
		t.eventMu.Lock()
		armErr := c.arm(t)
		t.eventMu.Unlock()
		if armErr != nil {
			// Release the client registration only while it is still owned by
			// this fresh transaction, and return the pooled object so a failed
			// start cannot leak a waiter or a reusable ID slot.
			c.removeIfOwner(t)
			t.recycle()

			return armErr
		}
	}
	_, err := msg.WriteTo(c.c)
	if err != nil && handler != nil {
		c.mux.RLock()
		transaction := c.t[msg.TransactionID]
		c.mux.RUnlock()
		if transaction != nil {
			// Hold eventMu across the whole terminal sequence so the object
			// cannot be recycled by a concurrent Close and reused by a new
			// Start before this goroutine finishes with it. The Stop call
			// below re-enters handleAgentCallback, but that event finds no
			// owner after removeIfOwner and returns on the not-found branch
			// before touching eventMu, so taking the lock here is safe.
			transaction.eventMu.Lock()
			if c.removeIfOwner(transaction) {
				// Stopping the agent transaction instead of waiting until deadline.
				if stopErr := c.a.Stop(msg.TransactionID); stopErr != nil {
					err = StopErr{
						Err:   stopErr,
						Cause: err,
					}
				}
				transaction.handle(Event{
					TransactionID: msg.TransactionID,
					Error:         err,
				})
				transaction.recycleLocked()
			}
			transaction.eventMu.Unlock()
		}
	}

	return err
}
