package client

import (
	"sync"
	"time"
)

// defaultHandshakeTraceLimit is the number of Raw bytes retained when
// Config.HandshakeTraceLimit is zero.
const defaultHandshakeTraceLimit = 4 << 20

// traceSink accumulates handshake events and dispatches the callback.
type traceSink struct {
	mu        sync.Mutex
	events    []HandshakeEvent
	bytes     int
	limit     int
	logger    func(HandshakeEvent)
	truncated bool
}

// newTraceSink builds a sink from the configuration.
func newTraceSink(config *Config) (sink *traceSink) {
	limit := defaultHandshakeTraceLimit

	if config != nil {
		if config.HandshakeTraceLimit < 0 {
			limit = -1
		} else if config.HandshakeTraceLimit > 0 {
			limit = config.HandshakeTraceLimit
		}
	}

	sink = &traceSink{
		limit:  limit,
		logger: config.HandshakeLogger,
	}

	return sink
}

// emit records an event and calls the logger.
func (t *traceSink) emit(event *HandshakeEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}

	if event.Name == "" {
		event.Name = event.Type.String()
	}

	if t.logger != nil {
		t.logger(*event)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.limit >= 0 && t.bytes+len(event.Raw) > t.limit {
		t.truncated = true

		return
	}

	t.events = append(t.events, *event)
	t.bytes += len(event.Raw)
}

// log returns the accumulated log.
func (t *traceSink) log() (log *HandshakeLog) {
	if t == nil {
		return &HandshakeLog{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	log = &HandshakeLog{
		Events:    make([]HandshakeEvent, len(t.events)),
		Truncated: t.truncated,
	}

	copy(log.Events, t.events)

	return log
}

// trace returns a copy of the accumulated events.
func (t *traceSink) trace() (events []HandshakeEvent) {
	if t == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	events = make([]HandshakeEvent, len(t.events))

	copy(events, t.events)

	return events
}
