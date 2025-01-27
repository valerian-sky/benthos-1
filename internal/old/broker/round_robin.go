package broker

import (
	"sync/atomic"
	"time"

	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/message"
)

//------------------------------------------------------------------------------

// RoundRobin is a broker that implements types.Consumer and sends each message
// out to a single consumer chosen from an array in round-robin fashion.
// Consumers that apply backpressure will block all consumers.
type RoundRobin struct {
	running int32

	stats metrics.Type

	transactions <-chan message.Transaction

	outputTSChans []chan message.Transaction
	outputs       []output.Streamed

	closedChan chan struct{}
	closeChan  chan struct{}
}

// NewRoundRobin creates a new RoundRobin type by providing consumers.
func NewRoundRobin(outputs []output.Streamed, stats metrics.Type) (*RoundRobin, error) {
	o := &RoundRobin{
		running:      1,
		stats:        stats,
		transactions: nil,
		outputs:      outputs,
		closedChan:   make(chan struct{}),
		closeChan:    make(chan struct{}),
	}
	o.outputTSChans = make([]chan message.Transaction, len(o.outputs))
	for i := range o.outputTSChans {
		o.outputTSChans[i] = make(chan message.Transaction)
		if err := o.outputs[i].Consume(o.outputTSChans[i]); err != nil {
			return nil, err
		}
	}
	return o, nil
}

//------------------------------------------------------------------------------

// Consume assigns a new messages channel for the broker to read.
func (o *RoundRobin) Consume(ts <-chan message.Transaction) error {
	if o.transactions != nil {
		return component.ErrAlreadyStarted
	}
	o.transactions = ts

	go o.loop()
	return nil
}

// Connected returns a boolean indicating whether this output is currently
// connected to its target.
func (o *RoundRobin) Connected() bool {
	for _, out := range o.outputs {
		if !out.Connected() {
			return false
		}
	}
	return true
}

// MaxInFlight returns the maximum number of in flight messages permitted by the
// output. This value can be used to determine a sensible value for parent
// outputs, but should not be relied upon as part of dispatcher logic.
func (o *RoundRobin) MaxInFlight() (m int, ok bool) {
	for _, out := range o.outputs {
		if mif, exists := output.GetMaxInFlight(out); exists && mif > m {
			m = mif
			ok = true
		}
	}
	return
}

//------------------------------------------------------------------------------

// loop is an internal loop that brokers incoming messages to many outputs.
func (o *RoundRobin) loop() {
	defer func() {
		for _, c := range o.outputTSChans {
			close(c)
		}
		closeAllOutputs(o.outputs)
		close(o.closedChan)
	}()

	i := 0
	var open bool
	for atomic.LoadInt32(&o.running) == 1 {
		var ts message.Transaction
		select {
		case ts, open = <-o.transactions:
			if !open {
				return
			}
		case <-o.closeChan:
			return
		}
		select {
		case o.outputTSChans[i] <- ts:
		case <-o.closeChan:
			return
		}

		i++
		if i >= len(o.outputTSChans) {
			i = 0
		}
	}
}

// CloseAsync shuts down the RoundRobin broker and stops processing requests.
func (o *RoundRobin) CloseAsync() {
	if atomic.CompareAndSwapInt32(&o.running, 1, 0) {
		close(o.closeChan)
	}
}

// WaitForClose blocks until the RoundRobin broker has closed down.
func (o *RoundRobin) WaitForClose(timeout time.Duration) error {
	select {
	case <-o.closedChan:
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
