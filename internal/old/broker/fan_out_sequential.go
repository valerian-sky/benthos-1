package broker

import (
	"context"
	"sync"
	"time"

	"github.com/benthosdev/benthos/v4/internal/component"
	"github.com/benthosdev/benthos/v4/internal/component/metrics"
	"github.com/benthosdev/benthos/v4/internal/component/output"
	"github.com/benthosdev/benthos/v4/internal/log"
	"github.com/benthosdev/benthos/v4/internal/message"
	"github.com/benthosdev/benthos/v4/internal/old/util/throttle"
)

//------------------------------------------------------------------------------

// FanOutSequential is a broker that implements types.Consumer and broadcasts
// each message out to an array of outputs, but does so sequentially, only
// proceeding onto an output when the preceding output has successfully
// reported message receipt.
type FanOutSequential struct {
	logger log.Modular
	stats  metrics.Type

	maxInFlight  int
	transactions <-chan message.Transaction

	outputTSChans []chan message.Transaction
	outputs       []output.Streamed

	ctx        context.Context
	close      func()
	closedChan chan struct{}
}

// NewFanOutSequential creates a new FanOutSequential type by providing outputs.
func NewFanOutSequential(
	outputs []output.Streamed, logger log.Modular, stats metrics.Type,
) (*FanOutSequential, error) {
	ctx, done := context.WithCancel(context.Background())
	o := &FanOutSequential{
		maxInFlight:  1,
		stats:        stats,
		logger:       logger,
		transactions: nil,
		outputs:      outputs,
		closedChan:   make(chan struct{}),
		ctx:          ctx,
		close:        done,
	}

	o.outputTSChans = make([]chan message.Transaction, len(o.outputs))
	for i := range o.outputTSChans {
		o.outputTSChans[i] = make(chan message.Transaction)
		if err := o.outputs[i].Consume(o.outputTSChans[i]); err != nil {
			return nil, err
		}
		if mif, ok := output.GetMaxInFlight(o.outputs[i]); ok && mif > o.maxInFlight {
			o.maxInFlight = mif
		}
	}
	return o, nil
}

// WithMaxInFlight sets the maximum number of in-flight messages this broker
// supports. This must be set before calling Consume.
func (o *FanOutSequential) WithMaxInFlight(i int) *FanOutSequential {
	if i < 1 {
		i = 1
	}
	o.maxInFlight = i
	return o
}

//------------------------------------------------------------------------------

// Consume assigns a new transactions channel for the broker to read.
func (o *FanOutSequential) Consume(transactions <-chan message.Transaction) error {
	if o.transactions != nil {
		return component.ErrAlreadyStarted
	}
	o.transactions = transactions

	go o.loop()
	return nil
}

// Connected returns a boolean indicating whether this output is currently
// connected to its target.
func (o *FanOutSequential) Connected() bool {
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
func (o *FanOutSequential) MaxInFlight() (int, bool) {
	return o.maxInFlight, true
}

//------------------------------------------------------------------------------

// loop is an internal loop that brokers incoming messages to many outputs.
func (o *FanOutSequential) loop() {
	wg := sync.WaitGroup{}

	defer func() {
		wg.Wait()
		for _, c := range o.outputTSChans {
			close(c)
		}
		closeAllOutputs(o.outputs)
		close(o.closedChan)
	}()

	sendLoop := func() {
		defer wg.Done()
		for {
			var ts message.Transaction
			var open bool

			select {
			case ts, open = <-o.transactions:
				if !open {
					return
				}
			case <-o.ctx.Done():
				return
			}

			for i := range o.outputTSChans {
				msgCopy := ts.Payload.Copy()

				throt := throttle.New(throttle.OptCloseChan(o.ctx.Done()))
				resChan := make(chan error)

				// Try until success or shutdown.
			sendLoop:
				for {
					select {
					case o.outputTSChans[i] <- message.NewTransaction(msgCopy, resChan):
					case <-o.ctx.Done():
						return
					}
					select {
					case res := <-resChan:
						if res != nil {
							o.logger.Errorf("Failed to dispatch fan out message to output '%v': %v\n", i, res)
							if !throt.Retry() {
								return
							}
						} else {
							break sendLoop
						}
					case <-o.ctx.Done():
						return
					}
				}
			}

			_ = ts.Ack(o.ctx, nil)
		}
	}

	// Max in flight
	for i := 0; i < o.maxInFlight; i++ {
		wg.Add(1)
		go sendLoop()
	}
}

// CloseAsync shuts down the FanOutSequential broker and stops processing requests.
func (o *FanOutSequential) CloseAsync() {
	o.close()
}

// WaitForClose blocks until the FanOutSequential broker has closed down.
func (o *FanOutSequential) WaitForClose(timeout time.Duration) error {
	select {
	case <-o.closedChan:
	case <-time.After(timeout):
		return component.ErrTimeout
	}
	return nil
}

//------------------------------------------------------------------------------
