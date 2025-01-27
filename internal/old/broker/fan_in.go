package broker

import (
	"time"

	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/input"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/message"
)

//------------------------------------------------------------------------------

// FanIn is a broker that implements types.Producer, takes an array of inputs
// and routes them through a single message channel.
type FanIn struct {
	stats metrics.Type

	transactions chan message.Transaction

	closables       []input.Streamed
	inputClosedChan chan int
	inputMap        map[int]struct{}

	closedChan chan struct{}
}

// NewFanIn creates a new FanIn type by providing inputs.
func NewFanIn(inputs []input.Streamed, stats metrics.Type) (*FanIn, error) {
	i := &FanIn{
		stats: stats,

		transactions: make(chan message.Transaction),

		inputClosedChan: make(chan int),
		inputMap:        make(map[int]struct{}),

		closables:  []input.Streamed{},
		closedChan: make(chan struct{}),
	}

	for n, input := range inputs {
		i.closables = append(i.closables, input)

		// Keep track of # open inputs
		i.inputMap[n] = struct{}{}

		// Launch goroutine that async writes input into single channel
		go func(index int) {
			defer func() {
				// If the input closes we need to signal to the broker
				i.inputClosedChan <- index
			}()
			for {
				in, open := <-inputs[index].TransactionChan()
				if !open {
					return
				}
				i.transactions <- in
			}
		}(n)
	}

	go i.loop()
	return i, nil
}

//------------------------------------------------------------------------------

// TransactionChan returns the channel used for consuming transactions from this
// broker.
func (i *FanIn) TransactionChan() <-chan message.Transaction {
	return i.transactions
}

// Connected returns a boolean indicating whether this output is currently
// connected to its target.
func (i *FanIn) Connected() bool {
	type connector interface {
		Connected() bool
	}
	for _, in := range i.closables {
		if c, ok := in.(connector); ok {
			if !c.Connected() {
				return false
			}
		}
	}
	return true
}

//------------------------------------------------------------------------------

// loop is an internal loop that brokers incoming messages to many outputs.
func (i *FanIn) loop() {
	defer func() {
		close(i.inputClosedChan)
		close(i.transactions)
		close(i.closedChan)
	}()

	for len(i.inputMap) > 0 {
		index := <-i.inputClosedChan
		delete(i.inputMap, index)
	}
}

// CloseAsync shuts down the FanIn broker and stops processing requests.
func (i *FanIn) CloseAsync() {
	for _, closable := range i.closables {
		closable.CloseAsync()
	}
}

// WaitForClose blocks until the FanIn broker has closed down.
func (i *FanIn) WaitForClose(timeout time.Duration) error {
	select {
	case <-i.closedChan:
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
